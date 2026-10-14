open Lookup.Syntax

let src = Logs.Src.create "dmarc.report"

module Log = (val Logs.src_log src : Logs.LOG)

(* NOTE(dinosaure): The "destination host" of a reporting URI. For a "mailto:"
   URI, it is the domain of the email address. *)
let host uri =
  let str =
    match Option.map String.lowercase_ascii (Uri.scheme uri) with
    | Some "mailto" -> (
        let path = Uri.path uri in
        match String.rindex_opt path '@' with
        | Some idx ->
            Some (String.sub path (idx + 1) (String.length path - idx - 1))
        | None -> None)
    | _ -> Uri.host uri in
  Option.bind str (fun str -> Result.to_option (Domain_name.of_string str))

let tag = function
  | `Rua -> fun r -> r.Record.rua
  | `Ruf -> fun r -> r.Record.ruf

(* NOTE(dinosaure): The external reporting arrangement is authorized if at
   least one TXT record at <domain>._report._dmarc.<host> starts with
   "v=DMARC1". Such a record can override the destination (with the same
   destination host). *)
let authorization ~domain kind host =
  let name =
    let ( let* ) = Result.bind in
    let* name = Domain_name.prepend_label host "_dmarc" in
    let* name = Domain_name.prepend_label name "_report" in
    Domain_name.append domain name in
  match name with
  | Error _ ->
      (* NOTE(dinosaure): If the length of the constructed name exceed DNS
         limits, a positive determination of the external reporting
         relationship cannot be made. *)
      Lookup.return (Ok `Unauthorized)
  | Ok name -> (
      let+ answer = Lookup.ask name `Txt in
      match answer with
      | `Txt txts -> begin
          let records =
            List.filter_map
              (fun txt -> Result.to_option (Record.of_string txt))
              txts in
          match records with
          | [] -> Ok `Unauthorized
          | records ->
          match List.find_opt (fun r -> tag kind r <> []) records with
          | Some record -> Ok (`Override (tag kind record))
          | None -> Ok `Authorized
        end
      | `No_domain | `No_data | `Exists -> Ok `Unauthorized
      | `Error _ -> Error `Temperror)

let same_host a b =
  match (host a, host b) with
  | Some a, Some b -> Domain_name.equal a b
  | _ -> false

let destinations ~domain kind record =
  let domain = Domain_name.raw domain in
  let* org = Tree_walk.organizational_domain domain in
  match org with
  | Error _ as err -> Lookup.return err
  | Ok org ->
      let rec go acc = function
        | [] -> Lookup.return (Ok (List.rev acc))
        | uri :: uris ->
            begin match host uri with
            | None -> go acc uris
            | Some host -> (
                let* org' = Tree_walk.organizational_domain host in
                match org' with
                | Error _ as err -> Lookup.return err
                | Ok org' when Domain_name.equal org org' ->
                    go (uri :: acc) uris
                | Ok _ -> (
                    let* authorization = authorization ~domain kind host in
                    match authorization with
                    | Error _ as err -> Lookup.return err
                    | Ok `Unauthorized ->
                        Log.debug (fun m ->
                            m "%a is not authorized to receive reports for %a"
                              Domain_name.pp host Domain_name.pp domain) ;
                        go acc uris
                    | Ok `Authorized -> go (uri :: acc) uris
                    | Ok (`Override uris') ->
                        (* The overriding URI MUST use the same destination
                           host. Otherwise, we MUST NOT generate a report to
                           either the original or the override URI. *)
                        if List.for_all (same_host uri) uris'
                        then go (List.rev_append uris' acc) uris
                        else go acc uris))
            end in
      go [] (tag kind record)
