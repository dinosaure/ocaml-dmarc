[@@@warning "-30"]

let reword_error f = function Ok v -> Ok v | Error err -> Error (f err)
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( % ) f g = fun x -> f (g x)
let invalid_argf fmt = Fmt.kstr invalid_arg fmt
let src = Logs.Src.create "dmarc"

module Log = (val Logs.src_log src : Logs.LOG)

type policy = Value.policy
type mode = Value.mode
type psd = Value.psd
type fo = Value.fo

let pp_policy = Value.pp_policy

module Record = struct
  include Record

  let of_string str =
    match of_string str with
    | Ok _ as value -> value
    | Error `Not_a_DMARC_record -> error_msgf "Invalid DMARC record: %S" str
end

module Lookup = Lookup

let organizational_domain = Tree_walk.organizational_domain

module Report = struct
  let destinations = Report.destinations
end

type field =
  | From of Mrmime.Field_name.t * Unstrctrd.t * Emile.mailbox list
  | DKIM of Mrmime.Field_name.t * Unstrctrd.t * Dkim.signed Dkim.t
  | SPF of Mrmime.Field_name.t * Unstrctrd.t * Uspf.Extract.field
  | Field of Mrmime.Field_name.t * Unstrctrd.t

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

let parse_from_field_value unstrctrd =
  let str = Unstrctrd.(to_utf_8_string (fold_fws unstrctrd)) in
  match Angstrom.parse_string ~consume:Prefix Emile.Parser.mailbox_list str with
  | Ok _ as v -> v
  | Error _ -> Error (`Invalid_From_field unstrctrd)

(* See RFC 9989, Section 5.3.1. If zero or more than one domain is extracted
   from the RFC5322.From header field, then DMARC validation is not possible. *)
let extract_from fields =
  let fn = function From (_, _, mailboxes) -> Some mailboxes | _ -> None in
  match List.filter_map fn fields with
  | [] -> Error `Missing_From_field
  | _ :: _ :: _ -> Error `Multiple_From_fields
  | [ mailboxes ] -> (
      let fn { Emile.domain = domain, _; _ } = domain in
      match List.map fn mailboxes with
      | [] -> Error `Missing_From_field
      | domain :: domains ->
          if List.for_all (Emile.equal_domain domain) domains
          then Ok domain
          else Error `Multiple_author_domains)

let emile_domain_to_domain_name = function
  | ( `Addr (Emile.IPv4 _)
    | `Addr (Emile.IPv6 _)
    | `Addr (Emile.Ext _)
    | `Literal _ ) as domain ->
      Error (`Invalid_domain domain)
  | `Domain lst as domain ->
      reword_error
        (fun _ -> `Invalid_domain domain)
        (Domain_name.of_strings lst)

module SPF = struct
  type 'a t =
    | S_query :
        'x Domain_name.t * 'a Uspf.record * ('a Uspf.response -> 'b Uspf.t)
        -> 'b t
    | S_done : 'a -> 'a t
    | S_result : Uspf.Result.t -> 'a t

  type computation =
    | SPF_query :
        'x Domain_name.t * 'a Uspf.record * ('a Uspf.response -> 'b Uspf.t)
        -> computation
    | SPF_result : Uspf.Result.t -> computation

  let eval : type a. a Uspf.t -> computation =
    let rec go : type a. a Uspf.t -> a t = function
      | Request (dn, r, fn) -> S_query (dn, r, fn)
      | Return v -> S_done v
      | Map (x, fn) -> (
          match go x with
          | S_done x -> S_done (fn x)
          | S_result _ as result -> result
          | S_query (dn, r, fn') ->
              let fn resp = Uspf.Map (fn' resp, fn) in
              S_query (dn, r, fn)
          | exception Uspf.Result result -> S_result result)
      | Tries lst ->
          let rec iter = function
            | [] -> Uspf.Return ()
            | fn :: fns ->
            match go (fn ()) with
            | S_done () -> iter fns
            | S_query (dn, r, fn') ->
                let fn resp = iter ((fun () -> fn' resp) :: fns) in
                Uspf.Request (dn, r, fn)
            | S_result result -> Uspf.terminate result in
          go (iter lst)
      | Choose_on c ->
      match go (c.fn ()) with
      | S_done _ as value -> value
      | S_query _ as query -> query
      | S_result _ as result -> result
      | exception Uspf.Result result ->
          let none _ = Uspf.terminate result in
          let some = Fun.id in
          let fn =
            match result with
            | `None -> Option.fold ~none ~some c.none
            | `Neutral -> Option.fold ~none ~some c.neutral
            | `Fail -> Option.fold ~none ~some c.fail
            | `Softfail -> Option.fold ~none ~some c.softfail
            | `Temperror -> Option.fold ~none ~some c.temperror
            | `Permerror -> Option.fold ~none ~some c.permerror
            | `Pass m -> (
                fun () -> match c.pass with Some fn -> fn m | None -> none ())
          in
          let m = fn () in
          go m in
    fun m ->
      match go m with
      | S_done _ -> SPF_result `None
      | S_query (dn, r, fn) -> SPF_query (dn, r, fn)
      | S_result result -> SPF_result result
      | exception Uspf.Result result -> SPF_result result
end

module Refl = struct
  type ('a, 'b) t = Refl : ('a, 'a) t

  let equal : type a b. a Uspf.record -> b Uspf.record -> (a, b) t option =
   fun a b ->
    match (a, b) with
    | Soa, Soa -> Some Refl
    | Ns, Ns -> Some Refl
    | Mx, Mx -> Some Refl
    | Cname, Cname -> Some Refl
    | A, A -> Some Refl
    | Aaaa, Aaaa -> Some Refl
    | Ptr, Ptr -> Some Refl
    | Srv, Srv -> Some Refl
    | Dnskey, Dnskey -> Some Refl
    | Caa, Caa -> Some Refl
    | Tlsa, Tlsa -> Some Refl
    | Sshfp, Sshfp -> Some Refl
    | Txt, Txt -> Some Refl
    | Ds, Ds -> Some Refl
    | Rrsig, Rrsig -> Some Refl
    | Nsec, Nsec -> Some Refl
    | Nsec3, Nsec3 -> Some Refl
    | Loc, Loc -> Some Refl
    | Null, Null -> Some Refl
    | Unknown _, Unknown _ -> Some Refl
    | _ -> None
end

module DKIM = struct
  type t =
    | Pass of { dkim : Dkim.signed Dkim.t; domain_key : Dkim.domain_key }
    | Fail of { dkim : Dkim.signed Dkim.t; domain_key : Dkim.domain_key }
    | Temperror of { dkim : Dkim.signed Dkim.t }
    | Permerror of {
          dkim : Dkim.signed Dkim.t
        ; field_name : Mrmime.Field_name.t
        ; value : Unstrctrd.t
        ; error : error
      }
    | Neutral of { field_name : Mrmime.Field_name.t; value : Unstrctrd.t }

  and signature = {
      dkim : Dkim.signed Dkim.t
    ; domain_key : Dkim.domain_key
    ; fields : bool
    ; body : string
  }

  and error = [ `Invalid_domain_key | `Domain_key_unavailable ]

  let from_signature { dkim; domain_key; fields; body = bh } =
    let pass =
      let _, Dkim.Hash_value (k, bh') =
        (Dkim.signature_and_hash dkim :> string * Dkim.hash_value) in
      let bh' = Digestif.to_raw_string k bh' in
      fields && Eqaf.equal bh bh' in
    if pass then Pass { dkim; domain_key } else Fail { dkim; domain_key }
end

module Verify = struct
  type error =
    [ `Invalid_email
    | `Unexpected_response of Dns.Rr_map.k
    | `Invalid_domain of Emile.domain
    | `Missing_From_field
    | `Multiple_From_fields
    | `Multiple_author_domains
    | `Missing_SPF_context ]

  let pp_error ppf = function
    | `Invalid_email -> Fmt.string ppf "Invalid email"
    | `Unexpected_response _ -> Fmt.string ppf "Unexpected DNS response"
    | `Invalid_domain _ -> Fmt.string ppf "Invalid domain"
    | `Missing_From_field -> Fmt.string ppf "Missing From field"
    | `Multiple_From_fields -> Fmt.string ppf "Multiple From fields"
    | `Multiple_author_domains -> Fmt.string ppf "Multiple author domains"
    | `Missing_SPF_context -> Fmt.string ppf "Missing SPF context"

  type result = [ `Pass | `Fail | `None | `Temperror | `Permerror ]

  let pp_result ppf = function
    | `Pass -> Fmt.string ppf "pass"
    | `Fail -> Fmt.string ppf "fail"
    | `None -> Fmt.string ppf "none"
    | `Temperror -> Fmt.string ppf "temperror"
    | `Permerror -> Fmt.string ppf "permerror"

  type policy = {
      record : Record.t
    ; domain : [ `raw ] Domain_name.t
    ; assessment : Value.policy
    ; applied : Value.policy
  }

  type info = {
      domain : [ `raw ] Domain_name.t
    ; spf : Uspf.Result.t
    ; ctx : Uspf.ctx
    ; dkims : DKIM.t list
    ; policy : policy option
    ; result : result
  }

  type decoder = {
      input : bytes
    ; input_pos : int
    ; input_len : int
    ; state : state
    ; ctx : Uspf.ctx option
  }

  and raw = {
      spf : SPF.computation
    ; ctx : Uspf.ctx
    ; response : response option
    ; prelude : string
    ; domain : [ `raw ] Domain_name.t
    ; others : (Mrmime.Field_name.t * Unstrctrd.t) list
    ; dkims : (Mrmime.Field_name.t * Unstrctrd.t * Dkim.signed Dkim.t) list
  }

  and partial = {
      domain : [ `raw ] Domain_name.t
    ; spf : Uspf.Result.t
    ; ctx : Uspf.ctx
  }

  and inputs = {
      domain : [ `raw ] Domain_name.t
    ; spf : Uspf.Result.t
    ; ctx : Uspf.ctx
    ; dkims : DKIM.t list
  }

  and state =
    | Extraction of Mrmime.Hd.decoder * field list
    | Queries of raw * dkim list * DKIM.t list
    | Body of
        Dkim.Body.decoder
        * [ `CRLF | `Spaces of string ] list
        * ctx list
        * DKIM.t list
        * partial
    | Evaluation of inputs * Lookup.cache * response option

  and decode =
    [ `Await of decoder
    | `Query of decoder * [ `raw ] Domain_name.t * Dns.Rr_map.k
    | `Info of info
    | error ]

  and ctx =
    | Ctx : {
          bh : string
        ; b : (Dkim.signed, 'k) Dkim.Digest.value
        ; dk : Dkim.domain_key
      }
        -> ctx

  and dkim = {
      field_name : Mrmime.Field_name.t
    ; value : Unstrctrd.t
    ; dkim : Dkim.signed Dkim.t
    ; domain_key : Dkim.domain_key
  }

  and response = Response : 'a Uspf.record * 'a Uspf.response -> response

  let decoder ?ctx () =
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Extraction (dec, []) in
    { input; input_pos; input_len; state; ctx }

  let end_of_input decoder =
    { decoder with input = Bytes.empty; input_pos = 0; input_len = min_int }

  let src decoder src idx len =
    if idx < 0 || len < 0 || idx + len > String.length src
    then invalid_argf "Dmarc.Verify.src: source out of bounds" ;
    let input = Bytes.unsafe_of_string src in
    let input_pos = idx in
    let input_len = idx + len - 1 in
    let decoder = { decoder with input; input_pos; input_len } in
    match decoder.state with
    | Extraction (v, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Body (v, _, _, _, _) ->
        Dkim.Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Queries _ | Evaluation _ ->
        if len == 0 then end_of_input decoder else decoder

  let response : type a.
      decoder -> a Dns.Rr_map.key -> a Uspf.response -> decoder =
   fun decoder record response ->
    match decoder.state with
    | Queries (raw, dkims, preempted) ->
        let raw = { raw with response = Some (Response (record, response)) } in
        let state = Queries (raw, dkims, preempted) in
        { decoder with state }
    | Evaluation (inputs, cache, _) ->
        let state =
          Evaluation (inputs, cache, Some (Response (record, response))) in
        { decoder with state }
    | _ -> invalid_arg "Dmarc.Verify.response"

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let signatures ctxs =
    let fn (Ctx { bh; b = (dkim, _) as value; dk }) =
      let b, bh = Dkim.Digest.verify ~fields:bh ~domain_key:dk value in
      DKIM.from_signature { DKIM.dkim; domain_key = dk; fields = bh; body = b }
    in
    List.map fn ctxs

  (* DMARC evaluation, see RFC 9989, Section 5.3. *)

  open Lookup.Syntax

  (* The Authenticated Identifiers of the message (Section 4.3): the SPF Domain
     (if SPF passes) and the DKIM Signing Domains of valid signatures. *)
  let identifiers (inputs : inputs) (record : Record.t) =
    let spf =
      match (inputs.spf, Uspf.domain inputs.ctx) with
      | `Pass _, Some domain -> [ (record.aspf, Domain_name.raw domain) ]
      | _ -> [] in
    let fn = function
      | DKIM.Pass { dkim; _ } -> Some (record.adkim, Dkim.domain dkim)
      | _ -> None in
    let dkims = List.filter_map fn inputs.dkims in
    (* NOTE(dinosaure): we check first identifiers which do not require any
       DNS queries. *)
    let cost (mode, domain) =
      if Domain_name.equal domain inputs.domain
      then 0
      else match mode with `Strict -> 1 | `Relaxed -> 2 in
    let compare a b = Int.compare (cost a) (cost b) in
    List.stable_sort compare (spf @ dkims)

  let rec any_aligned author = function
    | [] -> Lookup.return (Ok false)
    | (mode, identifier) :: rest -> (
        let* aligned = Tree_walk.aligned ~mode author identifier in
        match aligned with
        | Ok true -> Lookup.return (Ok true)
        | Ok false -> any_aligned author rest
        | Error _ as err -> (
            let+ aligned = any_aligned author rest in
            match aligned with Ok true -> Ok true | _ -> err))

  (* The Domain Owner Assessment Policy (Section 4.10.1): "p" if the record is
     the one of the Author Domain, otherwise "sp" (if the Author Domain exists)
     or "np" (if the Author Domain does not exist). In the absence of
     applicable "sp" or "np", "p" is used. *)
  let assessment ?(existence = false) (inputs : inputs)
      (policy : Tree_walk.policy) =
    let record = policy.record in
    let p = Record.policy record in
    let sp = Option.value ~default:p record.sp in
    match (policy.author, record.np) with
    | true, _ -> Lookup.return p
    | false, None -> Lookup.return sp
    | false, Some _ when not existence -> Lookup.return sp
    | false, Some np -> (
        let+ answer = Lookup.ask inputs.domain `Exists in
        match answer with `No_domain -> np | _ -> sp)

  (* The "t" tag (test mode) requests to apply a policy one level below the
     specified one. *)
  let applied (record : Record.t) policy =
    match (record.t, policy) with
    | false, policy -> policy
    | true, `Reject -> `Quarantine
    | true, (`Quarantine | `None) -> `None

  let evaluate (inputs : inputs) =
    let policy ?existence (p : Tree_walk.policy) =
      let+ assessment = assessment ?existence inputs p in
      let applied = applied p.record assessment in
      Some { record = p.record; domain = p.domain; assessment; applied } in
    let* discovered = Tree_walk.discover inputs.domain in
    match discovered with
    | Error `Temperror -> Lookup.return (None, `Temperror)
    | Ok None -> Lookup.return (None, `None)
    | Ok (Some p) when not p.record.usable ->
        let+ policy = policy p in
        (policy, `Permerror)
    | Ok (Some p) -> (
        let identifiers = identifiers inputs p.record in
        let* aligned = any_aligned inputs.domain identifiers in
        match aligned with
        | Ok true ->
            let+ policy = policy p in
            (policy, `Pass)
        | Ok false ->
            let+ policy = policy ~existence:true p in
            (policy, `Fail)
        | Error `Temperror ->
            let+ policy = policy p in
            (policy, `Temperror))

  let answer_of_response :
      Lookup.kind -> response -> (Lookup.answer, _) Stdlib.result =
   fun kind (Response (record, response)) ->
    match (kind, record, response) with
    | `Txt, Dns.Rr_map.Txt, Ok (_ttl, txts) ->
        Ok (`Txt (Dns.Rr_map.Txt_set.elements txts))
    | `Exists, _, Ok _ -> Ok `Exists
    | _, _, Error (`No_domain _) -> Ok `No_domain
    | _, _, Error (`No_data _) -> Ok `No_data
    | _, _, Error (`Msg msg) -> Ok (`Error msg)
    | `Txt, record, Ok _ -> Error (`Unexpected_response (Dns.Rr_map.K record))

  let rec evaluation t (inputs : inputs) cache response =
    match (Lookup.step cache (evaluate inputs), response) with
    | `Done (policy, result), _ ->
        let ({ domain; spf; ctx; dkims } : inputs) = inputs in
        `Info ({ domain; spf; ctx; dkims; policy; result } : info)
    | `Need (domain_name, kind), None ->
        let state = Evaluation (inputs, cache, None) in
        let record =
          match kind with
          | `Txt -> Dns.Rr_map.K Dns.Rr_map.Txt
          | `Exists -> Dns.Rr_map.K Dns.Rr_map.A in
        `Query ({ t with state }, domain_name, record)
    | `Need (domain_name, kind), Some response ->
    match answer_of_response kind response with
    | Ok answer ->
        let cache = Lookup.add cache domain_name kind answer in
        evaluation t inputs cache None
    | Error err -> err

  let rec extract t decoder fields =
    let open Mrmime in
    let rec go fields =
      match Hd.decode decoder with
      | `Field field -> (
          let (Field.Field (fn, w, v)) = Location.prj field in
          let is_from = Field_name.equal fn Field_name.from in
          let is_dkim_signature =
            Field_name.equal fn Dkim.field_dkim_signature in
          let is_received_spf = Field_name.equal fn Uspf.field_received_spf in
          match (is_from, is_dkim_signature, is_received_spf, w) with
          | true, false, false, Field.Unstructured -> (
              let v = to_unstrctrd v in
              match parse_from_field_value v with
              | Ok ms -> go (From (fn, v, ms) :: fields)
              | Error _ -> go (Field (fn, v) :: fields))
          | false, true, false, Field.Unstructured -> (
              let v = Dkim.trim (to_unstrctrd v) in
              match Dkim.of_unstrctrd v with
              | Ok dkim ->
                  Log.debug (fun m -> m "New DKIM field") ;
                  go (DKIM (fn, v, dkim) :: fields)
              | Error (`Msg msg) ->
                  Log.warn (fun m ->
                      m "Bad DKIM field: %s (%S)" msg
                        (Unstrctrd.to_utf_8_string v)) ;
                  go (Field (fn, v) :: fields))
          | false, false, true, Field.Unstructured -> (
              let v = to_unstrctrd v in
              match Uspf.Extract.of_unstrctrd v with
              | Ok spf -> go (SPF (fn, v, spf) :: fields)
              | Error _ -> go (Field (fn, v) :: fields))
          | _, _, _, Field.Unstructured ->
              let v = to_unstrctrd v in
              go (Field (fn, v) :: fields)
          | _ -> assert false)
      | `Malformed _ -> `Invalid_email
      | `End prelude -> (
          let from =
            let ( let* ) = Result.bind in
            let* domain = extract_from fields in
            emile_domain_to_domain_name domain in
          let ctx =
            let fn = function
              | SPF (_, _, { Uspf.Extract.ctx; _ }) -> Some ctx
              | _ -> None in
            let ctxs = List.filter_map fn fields in
            let fn = function
              | None -> Fun.const None
              | Some ctx0 -> Uspf.merge ctx0 in
            let ctx =
              match ctxs with
              | [] -> None
              | ctx :: ctxs -> List.fold_left fn (Some ctx) ctxs in
            match (ctx, t.ctx) with
            | Some ctx, None -> Ok ctx
            | _, Some ctx -> Ok ctx
            | _ -> Error `Missing_SPF_context in
          match (from, ctx) with
          | Error err, _ | _, Error err -> err
          | Ok domain, Ok ctx ->
              let spf = SPF.eval (Uspf.get_and_check ctx) in
              let fn = function
                | From (fn, v, _) -> Either.Left (fn, v)
                | SPF (fn, v, _) -> Either.Left (fn, v)
                | Field (fn, v) -> Either.Left (fn, v)
                | DKIM (fn, v, dkim) -> Either.Right (fn, v, dkim) in
              let others, dkims = List.partition_map fn fields in
              let raw =
                { spf; ctx; response = None; prelude; domain; others; dkims }
              in
              let state = Queries (raw, [], []) in
              decode { t with state })
      | `Await ->
          let state = Extraction (decoder, fields) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t in
    go fields

  and queries t raw dkims preempted =
    match (raw.spf, raw.response) with
    | SPF.SPF_query (dn, r, _), None ->
        Log.debug (fun m -> m "SPF DNS query") ;
        let t = { t with state = Queries (raw, dkims, preempted) } in
        `Query (t, Domain_name.raw dn, Dns.Rr_map.K r)
    | SPF.SPF_query (_dn, r, fn), Some (Response (r', v)) -> (
        Log.debug (fun m -> m "SPF DNS query with response") ;
        match Refl.equal r r' with
        | Some Refl.Refl ->
            let spf =
              try SPF.eval (fn v)
              with Uspf.Result result -> SPF.SPF_result result in
            let raw = { raw with spf } in
            let raw = { raw with response = None } in
            queries t raw dkims preempted
        | None -> `Unexpected_response (Dns.Rr_map.K r))
    | SPF.SPF_result spf, None -> (
        match raw.dkims with
        | [] ->
            let prelude = Bytes.unsafe_of_string raw.prelude in
            let fn { field_name; value; dkim; domain_key } =
              let v = (field_name, value, dkim, domain_key) in
              let bh, Dkim.Digest.Value b =
                Dkim.Digest.digest_fields raw.others v in
              Ctx { bh; b; dk = domain_key } in
            let ctxs = List.map fn dkims in
            let decoder = Dkim.Body.decoder () in
            let partial : partial =
              { domain = raw.domain; spf; ctx = raw.ctx } in
            if Bytes.length prelude > 0
            then Dkim.Body.src decoder prelude 0 (Bytes.length prelude) ;
            let state = Body (decoder, [], ctxs, preempted, partial) in
            decode { t with state }
        | (field_name, value, dkim) :: rest ->
        match Dkim.Verify.domain_key dkim with
        | Ok dn ->
            let t = { t with state = Queries (raw, dkims, preempted) } in
            `Query (t, dn, Dns.Rr_map.(K Txt))
        | Error _ ->
            let error =
              DKIM.Permerror
                { dkim; field_name; value; error = `Invalid_domain_key } in
            let preempted = error :: preempted in
            let raw = { raw with dkims = rest } in
            queries t raw dkims preempted)
    | SPF.SPF_result _, Some resp ->
    match (raw.dkims, resp) with
    | ( (field_name, value, dkim) :: rest
      , Response (Dns.Rr_map.Txt, Ok (_ttl, txts)) ) -> (
        let txts = Dns.Rr_map.Txt_set.elements txts in
        let txts = List.map (String.concat "" % String.split_on_char ' ') txts in
        let txts = String.concat "" txts in
        match Dkim.domain_key_of_string txts with
        | Ok dk ->
            let dkim = { field_name; value; dkim; domain_key = dk } in
            let dkims = dkim :: dkims in
            let raw = { raw with dkims = rest } in
            let raw = { raw with response = None } in
            queries t raw dkims preempted
        | Error _ ->
            let error =
              DKIM.Permerror
                { dkim; field_name; value; error = `Invalid_domain_key } in
            let preempted = error :: preempted in
            let raw = { raw with dkims = rest } in
            let raw = { raw with response = None } in
            queries t raw dkims preempted)
    | (field_name, value, dkim) :: rest, Response (_, Error err) ->
        let error =
          match err with
          | `No_data _ | `No_domain _ ->
              DKIM.Permerror
                { dkim; field_name; value; error = `Domain_key_unavailable }
          | _ -> DKIM.Temperror { dkim } in
        let preempted = error :: preempted in
        let raw = { raw with dkims = rest } in
        let raw = { raw with response = None } in
        queries t raw dkims preempted
    | (_fn, _unstrctrd, _dkim) :: _, Response (r, Ok _) ->
        `Unexpected_response (Dns.Rr_map.K r)
    | [], _ -> failwith "Unexpected empty DKIM list"

  and digest t decoder stack ctxs preempted (partial : partial) =
    let rec go stack results =
      match Dkim.Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) results
      | `Data x ->
          let fn (Ctx { bh; b; dk }) =
            Ctx { bh; b = Dkim.Digest.digest_wsp (List.rev stack) b; dk } in
          let results = List.map fn results in
          let fn (Ctx { bh; b; dk }) =
            Ctx { bh; b = Dkim.Digest.digest_str x b; dk } in
          let results = List.map fn results in
          go [] results
      | `Await ->
          let state = Body (decoder, stack, results, preempted, partial) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End ->
          let fn (Ctx { bh; b; dk }) =
            Ctx { bh; b = Dkim.Digest.digest_wsp [ `CRLF ] b; dk } in
          let results = List.map fn results in
          let dkims = signatures results in
          let dkims = List.rev_append preempted dkims in
          let ({ domain; spf; ctx } : partial) = partial in
          let inputs : inputs = { domain; spf; ctx; dkims } in
          let state = Evaluation (inputs, Lookup.empty, None) in
          evaluation { t with state } inputs Lookup.empty None in
    go stack ctxs

  and decode t =
    match t.state with
    | Extraction (decoder, fields) -> extract t decoder fields
    | Queries (raw, dkims, preempted) -> queries t raw dkims preempted
    | Body (decoder, stack, ctxs, preempted, partial) ->
        digest t decoder stack ctxs preempted partial
    | Evaluation (inputs, cache, response) -> evaluation t inputs cache response
end

module Encoder = struct
  open Prettym

  let spf ?receiver ppf (info : Verify.info) =
    let domain ppf domain_name =
      eval ppf [ char $ '@'; !!string ] (Domain_name.to_string domain_name)
    in
    let smtp ppf ctx =
      match (Uspf.origin ctx, Uspf.domain ctx) with
      | Some `HELO, Some v ->
          eval ppf
            [ fws; string $ "smtp.helo"; cut; char $ '='; cut; !!string ]
            (Domain_name.to_string v)
      | Some `MAILFROM, Some v ->
          eval ppf
            [ fws; string $ "smtp.mailfrom"; cut; char $ '='; cut; !!domain ]
            v
      | _ -> ppf in
    eval ppf
      [
        tbox 1; string $ "spf"; cut; char $ '='; cut; !!Uspf.Encoder.result
      ; spaces 1; !!(Uspf.Encoder.comment ~ctx:info.ctx ?receiver); !!smtp
      ; char $ ';'; close; new_line
      ]
      info.spf info.spf info.ctx

  let dkim ppf value =
    let domain ppf domain_name =
      eval ppf [ char $ '@'; !!string ] (Domain_name.to_string domain_name)
    in
    let domain ppf domain_name =
      eval ppf
        [ string $ "header.i"; cut; char $ '='; cut; !!domain ]
        domain_name in
    let selector ppf selector =
      eval ppf
        [ string $ "header.s"; cut; char $ '='; cut; !!string ]
        (Domain_name.to_string selector) in
    let b ppf (dkim : Dkim.signed Dkim.t) =
      let b, _ = (Dkim.signature_and_hash dkim :> string * Dkim.hash_value) in
      let b = Base64.encode_exn b in
      let max = Int.min 8 (String.length b) in
      let b = String.sub b 0 max in
      eval ppf [ string $ "header.b"; cut; char $ '='; cut; !!string ] b in
    let result ppf = function
      | DKIM.Pass _ -> string ppf "pass"
      | DKIM.Fail _ -> string ppf "fail"
      | DKIM.Temperror _ -> string ppf "temperror"
      | DKIM.Permerror _ -> string ppf "permerror"
      | _ -> assert false in
    match value with
    | DKIM.Pass { dkim; _ }
    | DKIM.Fail { dkim; _ }
    | DKIM.Temperror { dkim; _ }
    | DKIM.Permerror { dkim; _ } ->
        eval ppf
          [
            string $ "dkim"; cut; char $ '='; cut; !!result; spaces 1; !!domain
          ; spaces 1; !!selector; spaces 1; !!b; char $ ';'; new_line
          ]
          value (Dkim.domain dkim) (Dkim.selector dkim) dkim
    | Neutral _ ->
        eval ppf
          [
            string $ "dkim"; cut; char $ '='; cut; !!result; char $ ';'
          ; new_line
          ]
          value

  let policy ppf = function
    | `None -> string ppf "NONE"
    | `Quarantine -> string ppf "QUARANTINE"
    | `Reject -> string ppf "REJECT"

  let dmarc_comment ppf = function
    | None -> ppf
    | Some { Verify.record; _ } ->
        let p = Record.policy record in
        let sp = Option.value ~default:p record.Record.sp in
        let np ppf = function
          | None -> ppf
          | Some np ->
              eval ppf
                [ spaces 1; string $ "np"; cut; char $ '='; cut; !!policy ]
                np in
        let t ppf = function
          | false -> ppf
          | true -> eval ppf [ spaces 1; string $ "t=y" ] in
        eval ppf
          [
            spaces 1; char $ '('; string $ "p"; cut; char $ '='; cut; !!policy
          ; spaces 1; string $ "sp"; cut; char $ '='; cut; !!policy; !!np; !!t
          ; char $ ')'
          ]
          p sp record.Record.np record.Record.t

  let dmarc ppf (info : Verify.info) =
    let result ppf v = string ppf (Fmt.str "%a" Verify.pp_result v) in
    let from ppf domain_name =
      eval ppf
        [ string $ "header.from"; cut; char $ '='; cut; !!string ]
        (Domain_name.to_string domain_name) in
    eval ppf
      [
        string $ "dmarc"; cut; char $ '='; cut; !!result; !!dmarc_comment
      ; spaces 1; !!from
      ]
      info.result info.policy info.domain

  let domain_name ppf = function
    | `Addr (Emile.IPv4 v) -> eval ppf [ !!string ] (Ipaddr.V4.to_string v)
    | `Addr (Emile.IPv6 v) -> eval ppf [ !!string ] (Ipaddr.V6.to_string v)
    | `Addr (Emile.Ext (k, v)) ->
        eval ppf [ char $ '['; !!string; char $ ':'; !!string; char $ ']' ] k v
    | `Domain vs ->
        let sep = ((fun ppf () -> string ppf "."), ()) in
        eval ppf [ !!(list ~sep string) ] vs
    | `Literal v -> eval ppf [ char $ '['; !!string; char $ ']' ] v

  let value ~receiver ppf (info : Verify.info) =
    let sep = ((fun ppf () -> eval ppf [ cut ]), ()) in
    eval ppf
      [
        !!domain_name; char $ ';'; fws; !!(spf ~receiver); fws
      ; !!(list ~sep dkim); !!dmarc
      ]
      receiver info info.dkims info

  let field ~receiver ppf info =
    eval ppf [ tbox 1; !!(value ~receiver); close; new_line ] info
end

let field_authentication_results = Mrmime.Field_name.v "Authentication-Results"

let to_field ~receiver info =
  let v = Prettym.to_string (Encoder.field ~receiver) info in
  let _, v = Result.get_ok (Unstrctrd.of_string v) in
  (field_authentication_results, v)

module Authentication_results = struct
  type property = {
      ty : string
    ; property : string
    ; value :
        [ `Value of string | `Mailbox of string list option * Emile.domain ]
  }

  type result = {
      meth : string
    ; version : int option
    ; value : string
    ; reason : string option
    ; properties : property list
  }

  type t = { servid : string; version : int option; results : result list }

  module Decoder = struct
    open Angstrom

    let is_white = function ' ' | '\t' -> true | _ -> false
    let is_digit = function '0' .. '9' -> true | _ -> false

    let ldh_str =
      take_while1 (function
        | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' -> true
        | _ -> false)
      >>= fun ldh ->
      if ldh.[String.length ldh - 1] = '-'
      then fail "invalid ldh-str"
      else return ldh

    let keyword = ldh_str

    (* From Mr. MIME *)

    (* NOTE(dinosaure): about tspecials, I see some emails which includes the "/" character
       into values. *)

    let is_tspecials = function
      | '(' | ')' | '<' | '>' | '@' | ',' | ';' | ':' | '\\' | '"' (* | '/' *)
      | '[' | ']' | '?' | '=' ->
          true
      | _ -> false

    let is_ctl = function '\000' .. '\031' | '\127' -> true | _ -> false
    let is_space = ( = ) ' '
    let is_ascii = function '\000' .. '\127' -> true | _ -> false

    let is_token c =
      is_ascii c
      && (not (is_tspecials c))
      && (not (is_ctl c))
      && not (is_space c)

    let token = take_while1 is_token
    let _3 x y z = (x, y, z)
    let _4 a b c d = (a, b, c, d)
    let ( .![]<- ) = Bytes.set
    let utf_8_tail = satisfy @@ function '\x80' .. '\xbf' -> true | _ -> false

    let utf_8_0 =
      satisfy (function '\xc2' .. '\xdf' -> true | _ -> false) >>= fun b0 ->
      utf_8_tail >>= fun b1 ->
      let res = Bytes.create 2 in
      res.![0] <- b0 ;
      res.![1] <- b1 ;
      return (Bytes.unsafe_to_string res)

    let utf_8_1 =
      lift3 _3 (char '\xe0')
        (satisfy @@ function '\xa0' .. '\xbf' -> true | _ -> false)
        utf_8_tail
      <|> lift3 _3
            (satisfy @@ function '\xe1' .. '\xec' -> true | _ -> false)
            utf_8_tail utf_8_tail
      <|> lift3 _3 (char '\xed')
            (satisfy @@ function '\x80' .. '\x9f' -> true | _ -> false)
            utf_8_tail
      <|> lift3 _3
            (satisfy @@ function '\xee' .. '\xef' -> true | _ -> false)
            utf_8_tail utf_8_tail

    let utf_8_1 =
      utf_8_1 >>= fun (b0, b1, b2) ->
      let res = Bytes.create 3 in
      res.![0] <- b0 ;
      res.![1] <- b1 ;
      res.![2] <- b2 ;
      return (Bytes.unsafe_to_string res)

    let utf_8_2 =
      lift4 _4 (char '\xf0')
        (satisfy @@ function '\x90' .. '\xbf' -> true | _ -> false)
        utf_8_tail utf_8_tail
      <|> lift4 _4
            (satisfy @@ function '\xf1' .. '\xf3' -> true | _ -> false)
            utf_8_tail utf_8_tail utf_8_tail
      <|> lift4 _4 (char '\xf4')
            (satisfy @@ function '\x80' .. '\x8f' -> true | _ -> false)
            utf_8_tail utf_8_tail

    let utf_8_2 =
      utf_8_2 >>= fun (b0, b1, b2, b3) ->
      let res = Bytes.create 4 in
      res.![0] <- b0 ;
      res.![1] <- b1 ;
      res.![2] <- b2 ;
      res.![3] <- b3 ;
      return (Bytes.unsafe_to_string res)

    let utf_8_and is =
      satisfy is >>| String.make 1 <|> utf_8_0 <|> utf_8_1 <|> utf_8_2

    let of_escaped_character = function
      | '\x61' -> '\x07' (* "\a" *)
      | '\x62' -> '\x08' (* "\b" *)
      | '\x74' -> '\x09' (* "\t" *)
      | '\x6E' -> '\x0A' (* "\n" *)
      | '\x76' -> '\x0B' (* "\v" *)
      | '\x66' -> '\x0C' (* "\f" *)
      | '\x72' -> '\x0D' (* "\r" *)
      | c -> c

    let quoted_pair =
      char '\\' *> any_char >>| of_escaped_character >>| String.make 1

    let is_obs_no_ws_ctl = function
      | '\001' .. '\008' | '\011' | '\012' | '\014' .. '\031' | '\127' -> true
      | _ -> false

    let is_qtext = function
      | '\033' | '\035' .. '\091' | '\093' .. '\126' -> true
      | c -> is_obs_no_ws_ctl c

    let is_wsp = function ' ' | '\t' -> true | _ -> false

    let quoted_string =
      char '"'
      *> many
           (quoted_pair
           <|> utf_8_and is_qtext
           <|> (satisfy is_wsp >>| String.make 1))
      <* char '"'
      >>| String.concat ""

    let value =
      quoted_string >>| (fun v -> `String v) <|> (token >>| fun v -> `Token v)

    (* End of Mr. MIME's value decoder *)

    let ignore_spaces = skip_while is_white

    let no_result =
      ignore_spaces *> char ';' *> ignore_spaces *> string "none"
      >>| fun _none -> `None

    let authres_version = take_while1 is_digit
    let authserv_id = value >>| function `String str | `Token str -> str

    let meth =
      keyword >>= fun m ->
      let version = ignore_spaces *> char '/' *> take_while1 is_digit in
      option None (version >>| Option.some) >>| fun version ->
      (m, Option.map int_of_string version)

    let result = keyword

    let methodspec =
      ignore_spaces *> meth >>= fun m ->
      ignore_spaces *> char '=' *> ignore_spaces *> result >>| fun r -> (m, r)

    let reasonspec =
      string "reason" *> ignore_spaces *> char '=' *> ignore_spaces *> value

    let ptype = keyword
    let property = (* string "mailfrom" <|> string "rcptto" <|> *) keyword

    (* From Emile *)

    let uchar_is_ascii x = Uchar.to_int x >= 0 && Uchar.to_int x <= 0x7f

    let with_uutf is =
      let decoder = Uutf.decoder ~encoding:`UTF_8 `Manual in
      let buf = Buffer.create 0x100 in
      let rec go byte_count =
        match Uutf.decode decoder with
        | `Await -> `Continue
        | `Malformed _ -> `Error "Invalid UTF-8 character"
        | `Uchar uchar when uchar_is_ascii uchar ->
            if is (Uchar.to_char uchar)
            then (
              Uutf.Buffer.add_utf_8 buf uchar ;
              go byte_count)
            else `End (Uutf.decoder_byte_count decoder - byte_count - 1)
        | `Uchar uchar ->
            Uutf.Buffer.add_utf_8 buf uchar ;
            go byte_count
        | `End -> `End (Uutf.decoder_byte_count decoder - byte_count) in
      let scan buf ~off ~len =
        let src = Bigstringaf.substring buf ~off ~len in
        Uutf.Manual.src decoder (Bytes.unsafe_of_string src) 0 len ;
        go (Uutf.decoder_byte_count decoder) in
      fix @@ fun m ->
      available >>= fun len ->
      Unsafe.peek len scan >>= function
      | `Error err -> fail err
      | `Continue -> advance len >>= fun () -> m
      | `End len -> advance len >>= fun () -> return (Buffer.contents buf)

    let with_uutf1 is =
      available >>= fun n ->
      if n > 0
      then
        with_uutf is >>= fun s ->
        if String.length s > 0 then return s else fail "with_uutf1"
      else fail "with_uutf1"

    let local_part =
      (* NOTE(dinosaure): it's like [Emile.Parser.local_part] but without [CFWS]. *)
      let atom = Emile.Parser.(with_uutf1 is_atext) in
      let word = atom <|> Emile.Parser.quoted_string in
      let obs_local_part = sep_by1 (char '.') word in
      let dot_atom = sep_by1 (char '.') atom in
      let quoted_string = Emile.Parser.quoted_string >>| fun str -> [ str ] in
      obs_local_part <|> dot_atom <|> quoted_string >>= fun lst ->
      let len = List.fold_left (fun a x -> a + String.length x) 0 lst in
      if len > 0 then return lst else fail "local-part empty"

    (* End of Emile's local-part decoder *)

    let mailbox =
      let local_part =
        option None (local_part >>| Option.some)
        <* option () (char '@' >>| fun _ -> ()) in
      let domain_name = Dkim.Decoder.domain_name >>| fun v -> `Domain v in
      option None local_part >>= fun local_part ->
      domain_name >>| fun domain_name -> `Mailbox (local_part, domain_name)

    (* NOTE(dinosaure): this is an extension of [mailbox] which allows a mailbox
       to be surrounded by '<' & '>'. It allows multiple domains but... we don't
       care. We found such email address into some Authentication-Results values. *)
    let mailbox =
      let extension =
        Emile.Parser.angle_addr
        >>| fun { Emile.local; domain = domain, _; _ } ->
        let fn = function `Atom str | `String str -> str in
        let local = List.map fn local in
        `Mailbox (Some local, domain) in
      mailbox <|> extension

    let pvalue =
      let value = value >>| function `String v | `Token v -> `Value v in
      ignore_spaces *> (mailbox <|> value) <* ignore_spaces

    let propspec =
      ptype >>= fun ty ->
      (* NOTE(dinosaure): the RFC says that the property is required but some mails don't have it.
         We must accept nullable properties... *)
      option "" (ignore_spaces *> char '.' *> ignore_spaces *> property)
      >>= fun property ->
      ignore_spaces *> char '=' >>= fun _ ->
      pvalue >>| fun value -> { ty; property; value }

    let resinfo =
      ignore_spaces *> char ';' *> methodspec
      >>= fun ((meth, version), value) ->
      option None (ignore_spaces *> reasonspec >>| Option.some)
      >>= fun reason ->
      let reason =
        match reason with
        | Some (`String str | `Token str) -> Some str
        | None -> None in
      option [] (ignore_spaces *> many1 propspec) >>= fun properties ->
      return { meth; version; value; reason; properties }

    (* NOTE(dinosaure): some emails don't put the verification method and write
       only some properties... So we handle this case but we ignore it. *)
    let invalid_resinfo =
      ignore_spaces *> char ';' *> ignore_spaces *> many1 propspec >>= fun _ ->
      return None

    let resinfo = resinfo >>| Option.some
    let resinfo = resinfo <|> invalid_resinfo >>| fun info -> `Info info

    let end_of_phrase =
      ignore_spaces *> char ';' *> ignore_spaces *> end_of_input >>| fun () ->
      `End_of_phrase

    let end_of_input = ignore_spaces *> end_of_input >>| fun () -> `End_of_input

    (* NOTE(dinosaure): this is needed because some emails want to terminate an
       Authentication-Results with [;]. *)
    let resinfos =
      fix @@ fun m ->
      resinfo <|> end_of_phrase <|> end_of_input >>= function
      | `Info (Some x) -> m >>| fun r -> x :: r
      | `Info None -> m
      | `End_of_phrase -> return []
      | `End_of_input -> return []

    let resinfos =
      resinfo >>= function
      | `Info (Some x) -> resinfos >>| fun r -> x :: r
      | `Info None -> resinfos

    let authres_payload =
      ignore_spaces *> authserv_id >>= fun servid ->
      option None (ignore_spaces *> authres_version >>| Option.some)
      >>= fun version ->
      no_result <|> (resinfos >>| fun lst -> `Results lst) >>= fun results ->
      ignore_spaces
      *>
      let version = Option.map int_of_string version in
      let results =
        match results with `None -> [] | `Results results -> results in
      return { servid; version; results }
  end

  module Encoder = struct
    open Prettym

    let version ppf = function
      | None -> ppf
      | Some v -> eval ppf [ char $ '/'; !!string ] (string_of_int v)

    let reason ppf = function
      | None -> ppf
      | Some reason ->
          eval ppf
            [ spaces 1; string $ "reason"; cut; char $ '='; cut; !!string ]
            reason

    let value ppf = function
      | `Value str -> string ppf str
      | `Mailbox _ -> assert false (* TODO(dinosaure): flemme *)

    let property ppf t =
      match t.property with
      | "" -> eval ppf [ !!string; cut; char $ '='; cut; !!value ] t.ty t.value
      | property ->
          eval ppf
            [ !!string; char $ '.'; !!string; cut; char $ '='; cut; !!value ]
            t.ty property t.value

    let result ppf t =
      let sep = ((fun ppf () -> eval ppf [ spaces 1 ]), ()) in
      eval ppf
        [
          char $ ';'; cut; !!string; !!version; cut; char $ '='; cut; !!string
        ; !!reason; spaces 1; !!(list ~sep property)
        ]
        t.meth t.version t.value t.reason t.properties

    let encoder ppf t =
      let sep = ((fun ppf () -> eval ppf [ cut ]), ()) in
      eval ppf
        [
          tbox 1; !!string; !!version; char $ ';'; !!(list ~sep result); close
        ; new_line
        ]
        t.servid t.version t.results
  end

  let of_unstrctrd unstrctrd =
    let ( let* ) = Result.bind in
    let v = Unstrctrd.fold_fws unstrctrd in
    let* v = Unstrctrd.without_comments v in
    let str = Unstrctrd.to_utf_8_string v in
    match Angstrom.parse_string ~consume:All Decoder.authres_payload str with
    | Ok _ as results -> results
    | Error _ ->
        Log.debug (fun m -> m "Invalid Authentication-Results value:") ;
        Log.debug (fun m -> m "%s" str) ;
        error_msgf "Invalid Authentication-Results value"

  let to_unstrctrd t =
    let str = Prettym.to_string ~new_line:"\r\n" Encoder.encoder t in
    let v = Unstrctrd.of_string str in
    let _, value = Result.get_ok v in
    value

  let of_verification ~receiver (info : Verify.info) =
    let servid =
      match receiver with
      | `Addr (Emile.IPv4 v) -> Ipaddr.V4.to_string v
      | `Addr (Emile.IPv6 v) -> Ipaddr.V6.to_string v
      | `Addr (Emile.Ext (k, v)) -> Fmt.str "[%s:%s]" k v
      | `Domain vs -> String.concat "." vs
      | `Literal v -> Fmt.str "[%s]" v in
    let spf =
      let value = Prettym.to_string Uspf.Encoder.result info.spf in
      let properties =
        match (Uspf.origin info.ctx, Uspf.domain info.ctx) with
        | Some `HELO, Some v ->
            let value = `Value (Domain_name.to_string v) in
            [ { ty = "smtp"; property = "helo"; value } ]
        | Some `MAILFROM, Some v ->
            let value = `Value (Domain_name.to_string v) in
            [ { ty = "smtp"; property = "mailfrom"; value } ]
        | _ -> [] in
      { meth = "spf"; version = None; value; reason = None; properties } in
    let dkims =
      let fn dkim =
        let value =
          match dkim with
          | DKIM.Pass _ -> "pass"
          | Fail _ -> "fail"
          | Temperror _ -> "temperror"
          | Permerror _ -> "permerror"
          | Neutral _ -> "neutral" in
        let properties =
          match dkim with
          | Neutral _ -> []
          | Pass { dkim; _ }
          | Fail { dkim; _ }
          | Temperror { dkim; _ }
          | Permerror { dkim; _ } ->
              let selector = Dkim.selector dkim in
              let selector = Domain_name.to_string selector in
              let selector =
                { ty = "header"; property = "s"; value = `Value selector } in
              let domain = Dkim.domain dkim in
              let domain = `Domain (Domain_name.to_strings domain) in
              let domain =
                {
                  ty = "header"
                ; property = "i"
                ; value = `Mailbox (None, domain)
                } in
              let b, _ =
                (Dkim.signature_and_hash dkim :> string * Dkim.hash_value) in
              let b = Base64.encode_exn b in
              let b = String.sub b 0 (Int.min 8 (String.length b)) in
              let b = { ty = "header"; property = "b"; value = `Value b } in
              [ selector; domain; b ] in
        { meth = "dkim"; version = None; reason = None; value; properties }
      in
      List.map fn info.dkims in
    let dmarc =
      let value = Fmt.str "%a" Verify.pp_result info.result in
      let properties =
        let value = `Value (Domain_name.to_string info.domain) in
        [ { ty = "header"; property = "from"; value } ] in
      { meth = "dmarc"; version = None; reason = None; value; properties } in
    let results = [ spf ] in
    let results = List.rev_append results dkims in
    let results = List.rev_append results [ dmarc ] in
    { servid; version = None; results }
end
