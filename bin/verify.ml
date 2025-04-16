(*
module Lwt_scheduler = Dmarc.Sigs.Make (Lwt)

module Flow = struct
  type flow = Lwt_unix.file_descr
  type +'a io = 'a Lwt.t

  let input = Lwt_unix.read
end

include
  Dmarc.Make
    (Lwt_scheduler)
    (struct
      include Lwt

      let iter_p = Lwt_list.iter_p
      let map_p = Lwt_list.map_p
    end)
    (Flow)
    (DNS)

open Rresult
open Lwt.Infix

let ctx sender helo ip =
  Uspf.empty |> fun ctx ->
  Option.fold ~none:ctx
    ~some:(fun helo -> Uspf.with_sender (`HELO helo) ctx)
    helo
  |> fun ctx ->
  Option.fold ~none:ctx
    ~some:(fun sender -> Uspf.with_sender (`MAILFROM sender) ctx)
    sender
  |> fun ctx -> Option.fold ~none:ctx ~some:(fun ip -> Uspf.with_ip ip ctx) ip

let pp_spf_result ppf = function
  | Ok (_ctx, `Pass _) -> Fmt.(styled `Green string) ppf "pass"
  | Ok (_ctx, v) -> Fmt.(styled `Red Uspf.pp_res) ppf v
  | Error (_, _msg) -> Fmt.(styled `Red string) ppf "internal error"

let pp_dkim_result ppf = function
  | Ok (`Valid dkim) ->
      Fmt.(styled `Green Domain_name.pp) ppf (Dkim.domain dkim)
  | Ok (`Invalid dkim) ->
      Fmt.(styled `Red Domain_name.pp) ppf (Dkim.domain dkim)
  | Error (`DKIM_record_unreachable dkim) ->
      Fmt.pf ppf "%a:unreachable"
        Fmt.(styled `Red Domain_name.pp)
        (Dkim.domain dkim)
  | Error (`Invalid_DKIM_record (dkim, _)) ->
      Fmt.pf ppf "%a:invalid-record"
        Fmt.(styled `Red Domain_name.pp)
        (Dkim.domain dkim)

let run nameservers sender helo ip =
  let ctx = ctx sender helo ip in
  let he = Happy_eyeballs_lwt.create () in
  let dns =
    DNS.create
      ~nameservers:(`Tcp, (nameservers :> DNS.Transport.io_addr list))
      he in
  verify ~newline:LF ~ctx
    ~epoch:(fun () -> Int64.of_float (Unix.gettimeofday ()))
    dns Lwt_unix.stdin
  >>= function
  | Ok (`Pass (_aligned, _spf, v)) ->
      Fmt.pr "%a: %a\n%!" Domain_name.pp v Fmt.(styled `Green string) "pass" ;
      Lwt.return (`Ok 0)
  | Ok (`Fail (spf_aligned, spf, dkims)) ->
      Fmt.epr "%a: (SPF aligned: %b, SPF: %a, DKIM: %a)\n%!"
        Fmt.(styled `Red string)
        "error" spf_aligned pp_spf_result spf
        Fmt.(Dump.list pp_dkim_result)
        dkims ;
      Lwt.return (`Ok 1)
  | Error err ->
      Fmt.epr "%a: %a.\n%!" Fmt.(styled `Red string) "error" Dmarc.pp_error err ;
      Lwt.return (`Error (false, Fmt.str "%a." Dmarc.pp_error err))

let run _ nameservers sender helo ip =
  Lwt_main.run (run nameservers sender helo ip)
*)

let reporter ppf =
  let report src level ~over k msgf =
    let k _ = over () ; k () in
    let with_metadata header _tags k ppf fmt =
      Format.kfprintf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let () = Fmt_tty.setup_std_outputs ~style_renderer:`Ansi_tty ~utf_8:true ()
let () = Logs.set_reporter (reporter Fmt.stdout)
(* let () = Logs.set_level ~all:true (Some Logs.Debug) *)

let run _quiet newline input =
  let ic, ic_close =
    match input with
    | None -> (stdin, ignore)
    | Some fpath ->
        let ic = open_in (Fpath.to_string fpath) in
        let ic_close () = close_in ic in
        (ic, ic_close) in
  let dns = Dns_client_unix.create () in
  Fun.protect ~finally:ic_close @@ fun () ->
  let decoder = Dmarc.Verify.decoder () in
  let buf = Bytes.create 0x7ff in
  let rec go decoder =
    match Dmarc.Verify.decode decoder with
    | #Dmarc.Verify.error as err ->
        Fmt.invalid_arg "%a." Dmarc.Verify.pp_error err
    | `Await decoder when newline = `CRLF ->
        let len = Stdlib.input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let decoder = Dmarc.Verify.src decoder str 0 (String.length str) in
        go decoder
    | `Info value ->
        let receiver = `Domain [ "omelet" ] in
        let fn, value = Dmarc.to_field ~receiver value in
        Fmt.pr "%a: %s%!" Mrmime.Field_name.pp fn
          (Unstrctrd.to_utf_8_string value)
    | `Await decoder ->
        let len = Stdlib.input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let str = String.split_on_char '\n' str in
        let str = String.concat "\r\n" str in
        let decoder = Dmarc.Verify.src decoder str 0 (String.length str) in
        go decoder
    | `Query (decoder, domain_name, Dns.Rr_map.K record) ->
        Logs.debug (fun m ->
            m "ask %a:%a" Dns.Rr_map.ppk (Dns.Rr_map.K record) Domain_name.pp
              domain_name) ;
        let response =
          Dns_client_unix.get_resource_record dns record domain_name in
        let decoder = Dmarc.Verify.response decoder record response in
        go decoder in
  go decoder

let () = run true `CRLF None

(*
open Cmdliner

let common_options = "COMMON OPTIONS"

let verbosity =
  let env = Cmd.Env.info "DMARC_LOGS" in
  Logs_cli.level ~docs:common_options ~env ()

let renderer =
  let env = Cmd.Env.info "DMARC_FMT" in
  Fmt_cli.style_renderer ~docs:common_options ~env ()

let reporter ppf =
  let report src level ~over k msgf =
    let k _ =
      over () ;
      k () in
    let with_metadata header _tags k ppf fmt =
      Fmt.kpf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let setup_logs style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer () ;
  Logs.set_level level ;
  Logs.set_reporter (reporter Fmt.stderr) ;
  Option.is_none level

let setup_logs = Term.(const setup_logs $ renderer $ verbosity)

let inet_addr_of_string str =
  match Unix.inet_addr_of_string str with v -> Some v | exception _ -> None

let pp_nameserver ppf = function
  | `Plaintext (inet_addr, 53) -> Fmt.pf ppf "%a" Ipaddr.pp inet_addr
  | `Plaintext (inet_addr, port) -> Fmt.pf ppf "%a:%d" Ipaddr.pp inet_addr port

let nameserver =
  let parser str =
    match String.split_on_char ':' str with
    | [ addr; port ] -> (
        match (Ipaddr.of_string str, int_of_string port) with
        | Ok addr, port -> Ok (`Plaintext (addr, port))
        | Error _, port -> R.error_msgf "Invalid IP address: %s:%d" addr port
        | exception _ -> R.error_msgf "Invalid nameserver: %S" str)
    | [] -> (
        match Ipaddr.of_string str with
        | Ok addr -> Ok (`Plaintext (addr, 53))
        | Error _ -> R.error_msgf "Invalid IP address: %S" str)
    | _ -> R.error_msgf "Invalid nameserver: %S" str in
  Arg.conv (parser, pp_nameserver)

let google = `Plaintext (Ipaddr.of_string_exn "8.8.8.8", 53)

let nameservers =
  let doc = "DNS nameservers." in
  Arg.(value & opt_all nameserver [ google ] & info [ "n"; "nameserver" ] ~doc)

let sender =
  let parser str =
    match R.(Emile.of_string str >>= Colombe_emile.to_path) with
    | Ok v -> Ok v
    | Error _ -> R.error_msgf "Invalid sender: %S" str in
  let pp = Colombe.Path.pp in
  Arg.conv (parser, pp)

let sender =
  let doc = "The sender of the given email." in
  Arg.(value & opt (some sender) None & info [ "s"; "sender" ] ~doc)

let domain_name = Arg.conv (Domain_name.of_string, Domain_name.pp)

let helo =
  let doc = "HELO/EHLO name used by the SMTP client." in
  Arg.(value & opt (some domain_name) None & info [ "helo" ] ~doc)

let ip =
  let doc = "The IP address of the client." in
  let ipaddr = Arg.conv (Ipaddr.of_string, Ipaddr.pp) in
  Arg.(value & opt (some ipaddr) None & info [ "ip" ] ~doc)

let cmd =
  let info = Cmd.info "verify" in
  Cmd.v info
    Term.(ret (const run $ setup_logs $ nameservers $ sender $ helo $ ip))

let () = exit (Cmd.eval' cmd)
*)
