let get_result t ~name =
  let fn { Dmarc.Authentication_results.meth; value; _ } =
    if String.equal name meth then Some value else None in
  List.find_map fn t.Dmarc.Authentication_results.results

let is_authentication_results =
  Mrmime.Field_name.equal Dmarc.field_authentication_results

let p =
  let open Mrmime in
  let unstructured = Field.(Witness Unstructured) in
  let open Field_name in
  Map.empty
  |> Map.add date unstructured
  |> Map.add from unstructured
  |> Map.add sender unstructured
  |> Map.add reply_to unstructured
  |> Map.add (v "To") unstructured
  |> Map.add cc unstructured
  |> Map.add bcc unstructured
  |> Map.add subject unstructured
  |> Map.add message_id unstructured
  |> Map.add comments unstructured
  |> Map.add content_type unstructured
  |> Map.add content_encoding unstructured

let to_unstrctrd unstructured =
  let fold acc = function #Unstrctrd.elt as elt -> elt :: acc | _ -> acc in
  let unstrctrd = List.fold_left fold [] unstructured in
  Result.get_ok (Unstrctrd.of_list (List.rev unstrctrd))

let get_unstrctrd : type a. a Mrmime.Field.t -> a -> Mrmime.Unstructured.t =
  function
  | Unstructured -> Fun.id
  | _ -> fun _ -> assert false

let collect filename expects =
  let ic = open_in filename in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
  let open Mrmime in
  let decoder = Hd.decoder p in
  let buf = Bytes.create 0x7ff in
  let rec go results =
    match Hd.decode decoder with
    | `Field field ->
        let (Field.Field (fn, w, v)) = Location.prj field in
        if is_authentication_results fn
        then
          let v = get_unstrctrd w v in
          let v = to_unstrctrd v in
          match Dmarc.Authentication_results.of_unstrctrd v with
          | Ok t -> go (t :: results)
          | Error _ -> go results
        else go results
    | `Malformed _ -> failwith "Invalid email"
    | `End _ -> List.rev results
    | `Await ->
        let len = Stdlib.input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        Hd.src decoder str 0 len ; go results in
  let results = go [] in
  let fn (serv, name, value) =
    let fn { Dmarc.Authentication_results.servid; _ } = servid = serv in
    let result = List.filter fn results in
    let result = List.find_map (get_result ~name) result in
    match result with
    | Some value' -> Alcotest.(check string) name value value'
    | None -> Alcotest.failf "%s:%s not found" name value in
  List.iter fn expects

let make filename expects =
  Alcotest.test_case filename `Quick @@ fun () -> collect filename expects

let v ~serv k v = (serv, k, v)

[@@@ocamlformat "disable"]

let tests =
  [
    "raw/001.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/002.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/003.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/004.mail",
    [ v ~serv:"mx.google.com" "dkim" "pass"
    ; v ~serv:"mx.google.com" "spf" "pass"
    ; v ~serv:"mx.google.com" "dmarc" "pass" ]
  ; "raw/005.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/006.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/007.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dkim" "pass"
    ]
  ; "raw/008.mail",
    [ v ~serv:"smtp.subspace.kernel.org" "arc" "pass"
    ; v ~serv:"smtp.subspace.kernel.org" "dmarc" "fail"
    ; v ~serv:"smtp.subspace.kernel.org" "spf" "fail"
    ; v ~serv:"webhostingserver.nl" "iprev" "pass"
    ; v ~serv:"webhostingserver.nl" "auth" "pass"
    ; v ~serv:"webhostingserver.nl" "spf" "softfail"
    ; v ~serv:"webhostingserver.nl" "dmarc" "skipped"
    ; v ~serv:"webhostingserver.nl" "arc" "none"
    ]

  ]
[@@@ocamlformat "enable"]

let tests = List.map (fun (filename, expects) -> make filename expects) tests
let () = Alcotest.run "authentication-results" [ ("parser", tests) ]
