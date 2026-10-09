(* DNS Tree Walk, see RFC 9989, Section 4.10. *)

open Lookup.Syntax

let src = Logs.Src.create "dmarc.tree-walk"

module Log = (val Logs.src_log src : Logs.LOG)

let count = Domain_name.count_labels
let drop domain_name amount = Domain_name.drop_label_exn ~amount domain_name

(* The DNS names which must be queried (from the longest to the shortest) to
   walk the tree from [domain_name]. A domain with more than eight labels does
   not result in more than eight queries (steps 3 and 4). *)
let targets domain_name =
  let n = count domain_name in
  if n = 0
  then []
  else if n = 1
  then [ domain_name ]
  else
    let next = if n < 8 then drop domain_name 1 else drop domain_name (n - 7) in
    let rec go acc domain_name =
      let acc = domain_name :: acc in
      if count domain_name <= 1
      then List.rev acc
      else go acc (drop domain_name 1) in
    domain_name :: go [] next

type lookup = [ `Record of Record.t | `Nothing | `Temperror ]

(* Records that do not start with a "v" tag that identifies the current
   version of DMARC are discarded. If multiple DMARC Policy Records are
   returned for a single target, they are all discarded (steps 2 and 6). *)
let record_at domain_name : lookup Lookup.t =
  match Domain_name.prepend_label domain_name "_dmarc" with
  | Error _ -> Lookup.return `Nothing
  | Ok dn -> begin
      let+ answer = Lookup.ask dn `Txt in
      match answer with
      | `Txt txts ->
          begin match List.filter Record.is_dmarc txts with
          | [ txt ] -> (
              match Record.of_string txt with
              | Ok record -> `Record record
              | Error _ -> `Nothing)
          | [] -> `Nothing
          | _ ->
              Log.warn (fun m ->
                  m "Multiple DMARC records for %a, ignore them" Domain_name.pp
                    domain_name) ;
              `Nothing
          end
      | `No_domain | `No_data | `Exists -> `Nothing
      | `Error msg ->
          Log.warn (fun m ->
              m "Impossible to get the DMARC record of %a: %s" Domain_name.pp
                domain_name msg) ;
          `Temperror
    end

(* The DMARC Policy Records found by a DNS Tree Walk from [domain_name], from
   the longest to the shortest domain. The walk stops as soon as a record
   contains "psd=y" or "psd=n". *)
let walk domain_name =
  let rec go acc = function
    | [] -> Lookup.return (Ok (List.rev acc))
    | target :: targets -> (
        let* lookup = record_at target in
        match lookup with
        | `Temperror -> Lookup.return (Error `Temperror)
        | `Nothing -> go acc targets
        | `Record ({ Record.psd = `Yes | `No; _ } as record) ->
            Lookup.return (Ok (List.rev ((target, record) :: acc)))
        | `Record record -> go ((target, record) :: acc) targets) in
  go [] (targets domain_name)

(* See RFC 9989, Section 4.10.2. *)
let select ~start records =
  let rec go = function
    | [] -> None
    | (domain_name, { Record.psd = `No; _ }) :: _ -> Some domain_name
    | (domain_name, { Record.psd = `Yes; _ }) :: _
      when not (Domain_name.equal domain_name start) ->
        (* The Organizational Domain is the domain one label below this one. *)
        Some (drop start (count start - count domain_name - 1))
    | _ :: rest -> go rest in
  match go records with
  | Some domain_name -> domain_name
  | None ->
  match List.rev records with
  | (domain_name, _) :: _ -> domain_name
  | [] -> start

let organizational_domain domain_name =
  let domain_name = Domain_name.raw domain_name in
  let+ records = walk domain_name in
  Result.map (select ~start:domain_name) records

type policy = {
    record : Record.t
  ; domain : [ `raw ] Domain_name.t
  ; author : bool
}

(* DMARC Policy Discovery, see RFC 9989, Section 4.10.1. The record to be
   applied is found at the Author Domain, the Organizational Domain of the
   Author Domain or the PSD of the Author Domain. *)
let discover author =
  let author = Domain_name.raw author in
  let* lookup = record_at author in
  match lookup with
  | `Temperror -> Lookup.return (Error `Temperror)
  | `Record record ->
      Lookup.return (Ok (Some { record; domain = author; author = true }))
  | `Nothing -> begin
      let+ records = walk author in
      match records with
      | Error _ as err -> err
      | Ok [] -> Ok None
      | Ok records -> begin
          let org = select ~start:author records in
          let is_org (domain_name, _) = Domain_name.equal domain_name org in
          let is_psd (_, { Record.psd; _ }) = psd = `Yes in
          let found =
            match List.find_opt is_org records with
            | Some _ as found -> found
            | None -> List.find_opt is_psd records in
          match found with
          | Some (domain, record) ->
              Ok (Some { record; domain; author = false })
          | None -> Ok None
        end
    end

let common_suffix a b =
  let a = List.rev_map String.lowercase_ascii (Domain_name.to_strings a) in
  let b = List.rev_map String.lowercase_ascii (Domain_name.to_strings b) in
  let rec go n = function
    | x :: r, y :: r' when String.equal x y -> go (succ n) (r, r')
    | _ -> n in
  go 0 (a, b)

(* Identifier Alignment, see RFC 9989, Sections 3.2.10 and 4.10.2. *)
let aligned ~mode author identifier =
  let author = Domain_name.raw author
  and identifier = Domain_name.raw identifier in
  if Domain_name.equal author identifier
  then Lookup.return (Ok true)
  else
    match mode with
    | `Strict -> Lookup.return (Ok false)
    | `Relaxed when common_suffix author identifier = 0 ->
        (* NOTE(dinosaure): an Organizational Domain is a suffix of its domain,
           two domains without common suffix can not have the same
           Organizational Domain. *)
        Lookup.return (Ok false)
    | `Relaxed -> begin
        let* a = organizational_domain author in
        let+ b = organizational_domain identifier in
        match (a, b) with
        | Ok a, Ok b -> Ok (Domain_name.equal a b)
        | Error _, _ | _, Error _ -> Error `Temperror
      end
