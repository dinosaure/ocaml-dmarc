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
