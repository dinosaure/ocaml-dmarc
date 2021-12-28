module Lwt_scheduler = Dmarc.Sigs.Make (Lwt)

module Flow = struct
  type flow = Lwt_unix.file_descr
  type +'a io = 'a Lwt.t

  let input = Lwt_unix.read
end

module DNS = struct
  include Dns_client_lwt

  type +'a io = 'a Lwt.t

  type error =
    [ `Msg of string
    | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
    | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]

  let getrrecord dns k domain_name = get_resource_record dns k domain_name
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

let run sender helo ip =
  let ctx = ctx sender helo ip in
  let dns = DNS.create () in
  verify ~newline:LF ~ctx
    ~epoch:(fun () -> Int64.of_float (Unix.gettimeofday ()))
    dns Lwt_unix.stdin
  >>= function
  | Ok `Pass ->
      Fmt.pr "DMARC: OK!\n%!" ;
      assert false
  | Ok (`Fail (spf, dkims)) ->
      Fmt.epr "DMARC: ERR (SPF: %b, DKIM: %b)!\n%!" (R.is_ok spf)
        (List.for_all (function Ok (`Valid _) -> true | _ -> false) dkims) ;
      assert false
  | Error err ->
      Fmt.epr "%a.\n%!" Dmarc.pp_error err ;
      assert false

let run _ sender helo ip = Lwt_main.run (run sender helo ip)

open Cmdliner

let common_options = "COMMON OPTIONS"

let verbosity =
  let env = Arg.env_var "BLAZE_LOGS" in
  Logs_cli.level ~docs:common_options ~env ()

let renderer =
  let env = Arg.env_var "BLAZE_FMT" in
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
  (Term.(ret (const run $ setup_logs $ sender $ helo $ ip)), Term.info "verify")

let () = Term.(exit_status @@ eval cmd)
