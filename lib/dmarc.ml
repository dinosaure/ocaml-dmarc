[@@@warning "-30"]

let reword_error f = function Ok v -> Ok v | Error err -> Error (f err)
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( % ) f g = fun x -> f (g x)
let invalid_argf fmt = Fmt.kstr invalid_arg fmt
let src = Logs.Src.create "dmarc"

module Log = (val Logs.src_log src : Logs.LOG)

type t = {
    dkim_alignment : Value.mode
  ; spf_alignment : Value.mode
  ; failure_reporting : [ `_0 | `_1 | `D | `S ]
  ; policy : Value.policy * Value.policy
  ; percentage : Value.percent
  ; interval : Value.interval
  ; formats : string * string list
  ; feedbacks : Value.uri list
  ; failures : Value.uri list
}

let pp_fo ppf = function
  | `_0 -> Fmt.string ppf "0"
  | `_1 -> Fmt.string ppf "1"
  | `D -> Fmt.string ppf "d"
  | `S -> Fmt.string ppf "s"

let pp ppf dmarc =
  Fmt.pf ppf
    "{ @[<hov>adkim= %a;@ aspf= %a;@ fo= %a;@ p= %a;@ sp= %a;@ pct= %a%%;@ ri= \
     %a;@ rfmt= @[<hov>%a@];@ rua= @[<hov>%a@];@ ruf= @[<hov>%a@];@] }"
    Value.pp_mode dmarc.dkim_alignment Value.pp_mode dmarc.spf_alignment pp_fo
    dmarc.failure_reporting Value.pp_policy (fst dmarc.policy) Value.pp_policy
    (snd dmarc.policy) Value.pp_percent dmarc.percentage Value.pp_interval
    dmarc.interval
    Fmt.(Dump.list string)
    (fst dmarc.formats :: snd dmarc.formats)
    Fmt.(Dump.list Value.pp_uri)
    dmarc.feedbacks
    Fmt.(Dump.list Value.pp_uri)
    dmarc.failures

let of_map map =
  let dkim_alignment =
    Option.value ~default:Value.Relaxed Value.(find K.adkim map) in
  let spf_alignment =
    Option.value ~default:Value.Relaxed Value.(find K.aspf map) in
  let failure_reporting = Option.value ~default:`_0 Value.(find K.fo map) in
  let percentage = Option.value ~default:100 Value.(find K.pct map) in
  let interval = Option.value ~default:86400 Value.(find K.ri map) in
  let formats =
    match Value.(find K.rf map) with None -> ("afrf", []) | Some v -> v in
  let feedbacks = Option.value ~default:[] Value.(find K.rua map) in
  let failures = Option.value ~default:[] Value.(find K.ruf map) in
  match (Value.(find K.p map), Value.(find K.sp map)) with
  | Some (("quarantine" | "reject" | "none") as v), None ->
      let v = Value.policy_of_string v in
      Ok
        {
          dkim_alignment
        ; spf_alignment
        ; failure_reporting
        ; policy = (v, v)
        ; percentage
        ; interval
        ; formats
        ; feedbacks
        ; failures
        }
  | ( Some (("quarantine" | "reject" | "none") as v)
    , Some (("quarantine" | "reject" | "none") as v') ) ->
      let v = Value.policy_of_string v in
      let v' = Value.policy_of_string v' in
      Ok
        {
          dkim_alignment
        ; spf_alignment
        ; failure_reporting
        ; policy = (v, v')
        ; percentage
        ; interval
        ; formats
        ; feedbacks
        ; failures
        }
  | None, _ -> Error `Missing_DMARC_policy
  | Some v, _ ->
  match feedbacks with
  | _ :: _ ->
      (* XXX(dinosaure): According to RFC 7489,
       * If a retrieved policy record does not contain a valid "p" tag, or contains an "sp" tag
       * that is not valid, then:
       *
       * 1. if a "rua" tag is present and contains at least one syntactically valid reporting URI,
       *    the Mail Receiver SHOULD act as if a record containing a valid "v" tag and "p=none" was
       *    retrieved, and continue processing; *)
      Ok
        {
          dkim_alignment
        ; spf_alignment
        ; failure_reporting
        ; policy = (Value.None, Value.None)
        ; percentage
        ; interval
        ; formats
        ; feedbacks
        ; failures
        }
      (* 2. otherwise, the Mail Receiver applies no DMARC processing to this message. *)
  | [] -> Error (`Invalid_DMARC_policy v)

module Decoder = struct
  let ( or ) a b x = a x || b x
  let is_alpha = function 'a' .. 'z' | 'A' .. 'Z' -> true | _ -> false
  let is_digit = function '0' .. '9' -> true | _ -> false
  let is_wsp = function ' ' | '\t' -> true | _ -> false
  let is_dash = ( = ) '-'

  open Angstrom

  (* XXX(dinosaure): According to RFC 5321, Keyword = Ldh-str. *)
  let ldh_str =
    take_while1 (is_alpha or is_digit or is_dash) >>= fun res ->
    if String.get res (String.length res - 1) <> '-'
    then return res
    else fail "Invalid ldh-str token"

  let keyword = ldh_str

  let dmarc_uri =
    take_while1 @@ function ',' | ';' | ' ' | '\t' -> false | _ -> true

  let weight =
    let ( * ) = Int64.mul in
    take_while1 is_digit >>| Int64.of_string >>= fun n ->
    peek_char >>= function
    | Some 'k' -> advance 1 >>= fun () -> return (n * 1000L)
    | Some 'm' -> advance 1 >>= fun () -> return (n * 1000L * 1000L)
    | Some 'g' -> advance 1 >>= fun () -> return (n * 1000L * 1000L * 1000L)
    | Some 't' ->
        advance 1 >>= fun () -> return (n * 1000L * 1000L * 1000L * 1000L)
    | _ -> return n

  let dmarc_uri =
    dmarc_uri >>| Uri.of_string >>= fun uri ->
    peek_char >>= function
    | Some '!' -> advance 1 *> weight >>= fun weight -> return (uri, Some weight)
    | _ -> return (uri, None)

  let binding ~key parser =
    string key *> skip_while is_wsp *> char '=' *> skip_while is_wsp *> parser

  let dmarc_rfmt =
    let parser =
      keyword >>= fun x ->
      many (skip_while is_wsp *> char ':' *> keyword) >>= fun r ->
      return (x :: r) in
    binding ~key:"rf" parser

  let dmarc_version = binding ~key:"v" (string "DMARC1")
  let dmarc_sep = skip_while is_wsp *> char ';' *> skip_while is_wsp

  let dmarc_request =
    binding ~key:"p"
      (choice [ string "none"; string "quarantine"; string "reject" ])

  let dmarc_srequest =
    binding ~key:"sp"
      (choice [ string "none"; string "quarantine"; string "reject" ])

  let dmarc_auri =
    binding ~key:"rua"
      ( dmarc_uri >>= fun x ->
        many (skip_while is_wsp *> char ',' *> skip_while is_wsp *> dmarc_uri)
        >>= fun r -> return (x :: r) )

  let dmarc_furi =
    binding ~key:"ruf"
      ( dmarc_uri >>= fun x ->
        many (skip_while is_wsp *> char ',' *> skip_while is_wsp *> dmarc_uri)
        >>= fun r -> return (x :: r) )

  let dmarc_adkim = binding ~key:"adkim" (choice [ string "r"; string "s" ])
  let dmarc_aspf = binding ~key:"aspf" (choice [ string "r"; string "s" ])

  let dmarc_ainterval =
    binding ~key:"ri" (take_while1 is_digit >>| int_of_string)

  let dmarc_fo =
    binding ~key:"fo"
      (choice [ string "0"; string "1"; string "d"; string "s" ])

  let dmarc_percent = binding ~key:"pct" (take_while1 is_digit >>| int_of_string)

  let dmarc_value =
    dmarc_request
    >>| (fun v -> `P v)
    <|> (dmarc_srequest >>| fun v -> `SP v)
    <|> (dmarc_auri >>| fun v -> `RUA v)
    <|> (dmarc_furi >>| fun v -> `RUF v)
    <|> (dmarc_adkim >>| fun v -> `ADKIM v)
    <|> (dmarc_aspf >>| fun v -> `ASPF v)
    <|> (dmarc_ainterval >>| fun v -> `RI v)
    <|> (dmarc_fo >>| fun v -> `FO v)
    <|> (dmarc_rfmt >>| fun v -> `RF v)
    <|> (dmarc_percent >>| fun v -> `PCT v)

  let dmarc_record =
    dmarc_version >>= fun version ->
    many (dmarc_sep *> dmarc_value) >>= fun values ->
    option () dmarc_sep *> return (`V version :: values)

  let parse_record str =
    match Angstrom.parse_string ~consume:Prefix dmarc_record str with
    | Ok v -> Ok (Value.values_to_map v)
    | Error _ -> Error (`Invalid_DMARC str)
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

let extract_from fields =
  let exception Multiple_from in
  let res = ref None in
  match
    List.iter
      (fun field ->
        match (field, !res) with
        | From (_, _, [ mailbox ]), None -> res := Some mailbox
        | From _, _ ->
            raise Multiple_from
            (* XXX(dinosaure): According RFC 7489, Section 6.6.1,
             * - Messages with multiples RFC5322.From fields are typically rejected
             * - Messages bearing a single RFC5322.From field containing multiple
             *   addresses are typically rejected *)
        | _ -> ())
      fields ;
    !res
  with
  | Some mailbox -> Ok mailbox
  | None ->
      Error `Missing_From_field
      (* - Messages that have no RFC5322.From field at all are typically rejected. *)
  | exception Multiple_from -> Error `Multiple_mailboxes

(* TODO(dinosaure): RFC7489 talks about "syntactically valid __multi-valued__ RFC5322.From" field
 * as a valid case to initiate DMARC verification. But I don't know the meaning of such case! *)

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

(* XXX(dinosaure): See RFC 7489, 3.2. *)
let rec organization_domain ~domain =
  let open Organization_domains in
  find ~domain organization_domains

and find ~domain = function
  | [] -> None
  | x :: r ->
  match Domain_name.is_subdomain ~subdomain:domain ~domain:x with
  | false -> find ~domain r
  | true -> (
      let x_labels = Domain_name.count_labels x in
      let domain_labels = Domain_name.count_labels domain in
      let amount = domain_labels - x_labels - 1 in
      if amount < 0
      then find ~domain r
      else
        match Domain_name.drop_label ~amount domain with
        | Ok v -> Some v
        | Error _ -> find ~domain r)

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

  let aligned ~dmarc ~domain ctx =
    let spf_alignment = dmarc.spf_alignment in
    match (spf_alignment, domain, Uspf.domain ctx) with
    | Value.Strict, d, Some d' -> Domain_name.equal d d'
    | Value.Relaxed, d, Some d' -> (
        let d = organization_domain ~domain:d in
        let d' = organization_domain ~domain:d' in
        match (d, d') with
        | Some a, Some b -> Domain_name.equal a b
        | _ -> false)
    | _, _, None -> false

  let pass : Uspf.Result.t -> bool = function `Pass _ -> true | _ -> false
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
      let _, Dkim.Hash_value (k, bh') = Dkim.signature_and_hash dkim in
      let bh' = Digestif.to_raw_string k bh' in
      fields && Eqaf.equal bh bh' in
    if pass then Pass { dkim; domain_key } else Fail { dkim; domain_key }

  let aligned ~dmarc ~domain = function
    | Pass { dkim; _ } -> (
        let dkim_alignment = dmarc.dkim_alignment in
        match (dkim_alignment, domain, Dkim.domain dkim) with
        | Value.Strict, d, d' -> Domain_name.equal d d'
        | Value.Relaxed, d, d' -> (
            let d = organization_domain ~domain:d in
            let d' = organization_domain ~domain:d' in
            match (d, d') with
            | Some a, Some b -> Domain_name.equal a b
            | _ -> false))
    | _ -> false
end

module Verify = struct
  type error =
    [ `Invalid_DMARC of string
    | `Invalid_DMARC_policy of string
    | `Missing_DMARC_policy
    | `Invalid_email
    | `DMARC_unreachable
    | `Unexpected_response of Dns.Rr_map.k
    | `Invalid_domain of Emile.domain
    | `Missing_From_field
    | `Missing_SPF_context
    | `Multiple_mailboxes ]

  let pp_error ppf = function
    | `Invalid_DMARC _ -> Fmt.string ppf "Invalid DMARC"
    | `Invalid_DMARC_policy _ -> Fmt.string ppf "Invalid DMARC policy"
    | `Missing_DMARC_policy -> Fmt.string ppf "Missing DMARC policy"
    | `Invalid_email -> Fmt.string ppf "Invalid email"
    | `DMARC_unreachable -> Fmt.string ppf "DMARC unreachable"
    | `Unexpected_response _ -> Fmt.string ppf "Unexpected DNS response"
    | `Invalid_domain _ -> Fmt.string ppf "Invalid domain"
    | `Missing_From_field -> Fmt.string ppf "Missing From field"
    | `Missing_SPF_context -> Fmt.string ppf "Missing SPF context"
    | `Multiple_mailboxes -> Fmt.string ppf "Multiple mailboxes"

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
    ; dmarc : dmarc
    ; fields : field list
    ; others : (Mrmime.Field_name.t * Unstrctrd.t) list
    ; dkims : (Mrmime.Field_name.t * Unstrctrd.t * Dkim.signed Dkim.t) list
  }

  and info = {
      spf : Uspf.Result.t
    ; ctx : Uspf.ctx
    ; dmarc : t
    ; domain : [ `raw ] Domain_name.t
  }

  and state =
    | Extraction of Mrmime.Hd.decoder * field list
    | Queries of raw * dkim list * DKIM.t list
    | Body of Dkim.Body.decoder * ctx list * DKIM.t list * info

  and decode =
    [ `Await of decoder
    | `Query of decoder * [ `raw ] Domain_name.t * Dns.Rr_map.k
    | `Info of info * DKIM.t list * [ `Pass | `Fail ]
    | error ]

  and ctx = Ctx : string * 'k Dkim.Digest.value -> ctx

  and dkim = {
      field_name : Mrmime.Field_name.t
    ; value : Unstrctrd.t
    ; dkim : Dkim.signed Dkim.t
    ; domain_key : Dkim.domain_key
  }

  and response = Response : 'a Uspf.record * 'a Uspf.response -> response
  and dmarc = Ask_dmarc | Ask_organization | DMARC of t

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
    | Body (v, _, _, _) ->
        Dkim.Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Queries _ -> if len == 0 then end_of_input decoder else decoder

  let response : type a.
      decoder -> a Dns.Rr_map.key -> a Uspf.response -> decoder =
   fun decoder record response ->
    match decoder.state with
    | Queries (raw, dkims, preempted) ->
        let raw = { raw with response = Some (Response (record, response)) } in
        let state = Queries (raw, dkims, preempted) in
        { decoder with state }
    | _ -> invalid_arg "Dmarc.Verify.response"

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let signatures ctxs =
    let fn (Ctx (fields, ((dkim, dk, _) as value))) =
      let body, fields = Dkim.Digest.verify ~fields value in
      DKIM.from_signature { DKIM.dkim; domain_key = dk; fields; body } in
    List.map fn ctxs

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
            let* { Emile.domain = domain, _; _ } = extract_from fields in
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
              let raw =
                {
                  spf
                ; ctx
                ; response = None
                ; prelude
                ; domain
                ; dmarc = Ask_dmarc
                ; fields
                ; others = []
                ; dkims = []
                } in
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
    match (raw.dmarc, raw.spf, raw.response) with
    | Ask_dmarc, _, None ->
        let dn = Domain_name.prepend_label_exn raw.domain "_dmarc" in
        let t = { t with state = Queries (raw, dkims, preempted) } in
        `Query (t, dn, Dns.Rr_map.(K Txt))
    | Ask_organization, _, None -> (
        match organization_domain ~domain:raw.domain with
        | None -> `DMARC_unreachable
        | Some dn ->
            let dn = Domain_name.prepend_label_exn dn "_dmarc" in
            let t = { t with state = Queries (raw, dkims, preempted) } in
            `Query (t, dn, Dns.Rr_map.(K Txt)))
    | ((Ask_dmarc | Ask_organization) as s), _, Some (Response (r', v)) -> (
        match (s, r', v) with
        | Ask_dmarc, Dns.Rr_map.Txt, Error _ ->
            let raw = { raw with response = None } in
            let raw = { raw with dmarc = Ask_organization } in
            queries t raw dkims preempted
        | _, Dns.Rr_map.Txt, Ok (_ttl, txts) -> (
            let str = String.concat "" (Dns.Rr_map.Txt_set.elements txts) in
            match Result.bind (Decoder.parse_record str) of_map with
            | Ok dmarc ->
                let fn = function
                  | From (fn, v, _) -> Either.Left (fn, v)
                  | SPF (fn, v, _) -> Either.Left (fn, v)
                  | Field (fn, v) -> Either.Left (fn, v)
                  | DKIM (fn, v, dkim) -> Either.Right (fn, v, dkim) in
                let fields = raw.fields in
                let others, dkims' = List.partition_map fn fields in
                let raw = { raw with fields = []; others; dkims = dkims' } in
                let raw = { raw with response = None } in
                let raw = { raw with dmarc = DMARC dmarc } in
                queries t raw dkims preempted
            | Error err -> err)
        | _ -> `Unexpected_response (Dns.Rr_map.K r'))
    | DMARC dmarc, SPF.SPF_result spf, None -> (
        match raw.dkims with
        | [] ->
            let prelude = Bytes.unsafe_of_string raw.prelude in
            let fn { field_name; value; dkim; domain_key } =
              let v = (field_name, value, dkim, domain_key) in
              let fields, Dkim.Digest.Value value =
                Dkim.Digest.digest_fields raw.others v in
              Ctx (fields, value) in
            let ctxs = List.map fn dkims in
            let decoder = Dkim.Body.decoder () in
            let info = { spf; ctx = raw.ctx; dmarc; domain = raw.domain } in
            if Bytes.length prelude > 0
            then Dkim.Body.src decoder prelude 0 (Bytes.length prelude) ;
            let state = Body (decoder, ctxs, preempted, info) in
            decode { t with state }
        | (field_name, value, dkim) :: rest ->
        (* TODO(dinosaure): expire? *)
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
    | _, SPF.SPF_result _, Some resp -> (
        match (raw.dkims, resp) with
        | ( (field_name, value, dkim) :: rest
          , Response (Dns.Rr_map.Txt, Ok (_ttl, txts)) ) -> (
            let txts = Dns.Rr_map.Txt_set.elements txts in
            let txts =
              List.map (String.concat "" % String.split_on_char ' ') txts in
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
                    { dkim; field_name; value; error = `Invalid_domain_key }
                in
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
        | [], _ -> failwith "Unexpected empty DKIM list")
    | _, SPF.SPF_query (dn, r, _), None ->
        Log.debug (fun m -> m "SPF DNS query") ;
        let t = { t with state = Queries (raw, dkims, preempted) } in
        `Query (t, Domain_name.raw dn, Dns.Rr_map.K r)
    | _, SPF.SPF_query (_dn, r, fn), Some (Response (r', v)) -> (
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

  and digest t decoder ctxs preempted info =
    let rec go stack results =
      match Dkim.Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) results
      | `Data x ->
          let fn (Ctx (fields, value)) =
            Ctx (fields, Dkim.Digest.digest_wsp (List.rev stack) value) in
          let results = List.map fn results in
          let fn (Ctx (fields, value)) =
            Ctx (fields, Dkim.Digest.digest_str x value) in
          let results = List.map fn results in
          go [] results
      | `Await ->
          let fn (Ctx (fields, value)) =
            Ctx (fields, Dkim.Digest.digest_wsp stack value) in
          let results = List.map fn results in
          let state = Body (decoder, results, preempted, info) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End ->
          let dkims = signatures ctxs in
          let dkims = List.rev_append preempted dkims in
          let check = DKIM.aligned ~dmarc:info.dmarc ~domain:info.domain in
          let dmarc =
            if
              SPF.aligned ~dmarc:info.dmarc ~domain:info.domain info.ctx
              && SPF.pass info.spf
              || List.exists check dkims
            then `Pass
            else `Fail in
          `Info (info, dkims, dmarc) in
    go [] ctxs

  and decode t =
    match t.state with
    | Extraction (decoder, fields) -> extract t decoder fields
    | Queries (raw, dkims, preempted) -> queries t raw dkims preempted
    | Body (decoder, ctxs, preempted, info) ->
        digest t decoder ctxs preempted info
end

module Encoder = struct
  open Prettym

  let spf ?receiver ppf info =
    let domain ppf domain_name =
      eval ppf [ char $ '@'; !!string ] (Domain_name.to_string domain_name)
    in
    let smtp ppf ctx =
      match (Uspf.origin ctx, Uspf.domain ctx) with
      | Some `HELO, Some v ->
          eval ppf
            [ fws; string $ "smtp.helo"; cut; char $ '='; cut; !!domain ]
            v
      | Some `MAILFROM, Some v ->
          eval ppf
            [ fws; string $ "smtp.mailfrom"; cut; char $ '='; cut; !!domain ]
            v
      | _ -> ppf in
    eval ppf
      [
        tbox 1; string $ "spf"; cut; char $ '='; cut; !!Uspf.Encoder.result
      ; spaces 1; !!(Uspf.Encoder.comment ~ctx:info.Verify.ctx ?receiver)
      ; !!smtp; char $ ';'; close; new_line
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
    let b ppf dkim =
      let b, _ = Dkim.signature_and_hash dkim in
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

  let dmarc_comment ppf dmarc =
    let policy ppf = function
      | Value.None -> string ppf "NONE"
      | Value.Quarantine -> string ppf "QUARANTINE"
      | Value.Reject -> string ppf "REJECT" in
    let p ppf (value, _) =
      eval ppf [ string $ "p"; cut; char $ '='; cut; !!policy ] value in
    let sp ppf (_, value) =
      eval ppf [ string $ "sp"; cut; char $ '='; cut; !!policy ] value in
    eval ppf
      [ spaces 1; char $ '('; !!p; spaces 1; !!sp; char $ ')' ]
      dmarc.policy dmarc.policy

  let dmarc ppf (info, value) =
    let result ppf = function
      | `Pass -> string ppf "pass"
      | `Fail -> string ppf "fail" in
    let from ppf domain_name =
      eval ppf
        [ string $ "header.from"; cut; char $ '='; cut; !!string ]
        (Domain_name.to_string domain_name) in
    eval ppf
      [
        string $ "dmarc"; cut; char $ '='; cut; !!result; !!dmarc_comment
      ; spaces 1; !!from; 
      ]
      value info.Verify.dmarc info.Verify.domain

  let domain_name ppf = function
    | `Addr (Emile.IPv4 v) -> eval ppf [ !!string ] (Ipaddr.V4.to_string v)
    | `Addr (Emile.IPv6 v) -> eval ppf [ !!string ] (Ipaddr.V6.to_string v)
    | `Addr (Emile.Ext (k, v)) ->
        eval ppf [ char $ '['; !!string; char $ ':'; !!string; char $ ']' ] k v
    | `Domain vs ->
        let sep = ((fun ppf () -> string ppf "."), ()) in
        eval ppf [ !!(list ~sep string) ] vs
    | `Literal v -> eval ppf [ char $ '['; !!string; char $ ']' ] v

  let field ~receiver ppf (info, dkims, value) =
    let sep = ((fun ppf () -> eval ppf [ cut ]), ()) in
    eval ppf
      [
        tbox 1; !!domain_name; char $ ';'; new_line; !!(spf ~receiver)
      ; !!(list ~sep dkim); !!dmarc; close; new_line
      ]
      receiver info dkims (info, value)
end

let field_authentication_results = Mrmime.Field_name.v "Authentication-Results"

let to_field ~receiver result =
  let v = Prettym.to_string (Encoder.field ~receiver) result in
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

    let is_tspecials = function
      | '(' | ')' | '<' | '>' | '@' | ',' | ';' | ':' | '\\' | '"' | '/' | '['
      | ']' | '?' | '=' ->
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
    let property = string "mailfrom" <|> string "rcptto" <|> keyword

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

    let pvalue =
      let value = value >>| function `String v | `Token v -> `Value v in
      ignore_spaces *> (mailbox <|> value) <* ignore_spaces

    let propspec =
      ptype >>= fun ty ->
      ignore_spaces *> char '.' *> ignore_spaces *> property >>= fun property ->
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

    let authres_payload =
      ignore_spaces *> authserv_id >>= fun servid ->
      option None (ignore_spaces *> authres_version >>| Option.some)
      >>= fun version ->
      no_result <|> (many1 resinfo >>| fun lst -> `Results lst)
      >>= fun results ->
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
      eval ppf
        [ !!string; char $ '.'; !!string; cut; char $ '='; cut; !!value ]
        t.ty t.property t.value

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
    let* v =
      match Angstrom.parse_string ~consume:All Decoder.authres_payload str with
      | Ok _ as results -> results
      | Error _ -> error_msgf "Invalid Authentication-Results value" in
    Ok v

  let to_unstrctrd t =
    let str = Prettym.to_string ~new_line:"\r\n" Encoder.encoder t in
    let v = Unstrctrd.of_string str in
    let _, value = Result.get_ok v in
    value
end
