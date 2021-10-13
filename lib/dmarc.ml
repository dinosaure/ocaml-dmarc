module Sigs = Sigs
open Rresult
open Sigs

let src = Logs.Src.create "dmarc"

module Log = (val Logs.src_log src : Logs.LOG)

type dmarc = {
  dkim_alignment : Value.mode;
  spf_alignment : Value.mode;
  failure_reporting : [ `_0 | `_1 | `D | `S ];
  policy : Value.policy * Value.policy;
  percentage : Value.percent;
  interval : Value.interval;
  formats : string * string list;
  feedbacks : Value.uri list;
  failures : Value.uri list;
}

let pp_fo ppf = function
  | `_0 -> Fmt.string ppf "0"
  | `_1 -> Fmt.string ppf "1"
  | `D -> Fmt.string ppf "d"
  | `S -> Fmt.string ppf "s"

let pp_dmarc ppf dmarc =
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

let dmarc_of_map map =
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
      R.ok
        {
          dkim_alignment;
          spf_alignment;
          failure_reporting;
          policy = (v, v);
          percentage;
          interval;
          formats;
          feedbacks;
          failures;
        }
  | ( Some (("quarantine" | "reject" | "none") as v),
      Some (("quarantine" | "reject" | "none") as v') ) ->
      let v = Value.policy_of_string v in
      let v' = Value.policy_of_string v' in
      R.ok
        {
          dkim_alignment;
          spf_alignment;
          failure_reporting;
          policy = (v, v');
          percentage;
          interval;
          formats;
          feedbacks;
          failures;
        }
  | None, _ -> R.error `Missing_DMARC_policy
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
      R.ok
        {
          dkim_alignment;
          spf_alignment;
          failure_reporting;
          policy = (Value.None, Value.None);
          percentage;
          interval;
          formats;
          feedbacks;
          failures;
        }
      (* 2. otherwise, the Mail Receiver applies no DMARC processing to this message. *)
  | [] -> R.error (`Invalid_DMARC_policy v)

type spf_result = (Spf.ctx * Spf.res, Spf.ctx * string) result

type dkim_result =
  ( [ `Invalid of Dkim.signed Dkim.dkim | `Valid of Dkim.signed Dkim.dkim ],
    [ `DKIM_record_unreachable of Dkim.signed Dkim.dkim
    | `Invalid_DKIM_record of Dkim.signed Dkim.dkim * Dkim.map ] )
  result

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

type newline = LF | CRLF

let sub_string_and_replace_newline chunk len =
  let count = ref 0 in
  String.iter
    (function '\n' -> incr count | _ -> ())
    (Bytes.sub_string chunk 0 len) ;
  let plus = !count in
  let pos = ref 0 in
  let res = Bytes.create (len + plus) in
  for i = 0 to len - 1 do
    match Bytes.unsafe_get chunk i with
    | '\n' ->
        Bytes.unsafe_set res !pos '\r' ;
        Bytes.unsafe_set res (!pos + 1) '\n' ;
        pos := !pos + 2
    | chr ->
        Bytes.unsafe_set res !pos chr ;
        incr pos
  done ;
  Bytes.unsafe_to_string res

let sanitize_input newline chunk len =
  match newline with
  | CRLF -> Bytes.sub_string chunk 0 len
  | LF -> sub_string_and_replace_newline chunk len

type elt =
  | From of Mrmime.Field_name.t * Unstrctrd.t * Emile.mailbox list
  | DKIM of Mrmime.Field_name.t * Unstrctrd.t * Dkim.signed Dkim.dkim
  | SPF of Mrmime.Field_name.t * Unstrctrd.t * Spf.spf
  | Field of Mrmime.Field_name.t * Unstrctrd.t

let pp_elt ppf = function
  | From (field_name, _, lst) ->
      Fmt.pf ppf "%a:@ %a" Mrmime.Field_name.pp field_name
        Fmt.(list ~sep:(any "@ ") Emile.pp_mailbox)
        lst
  | DKIM (field_name, _, dkim) ->
      Fmt.pf ppf "%a:@ @[<hov>%a@]" Mrmime.Field_name.pp field_name Dkim.pp_dkim
        dkim
  | SPF (field_name, _, spf) ->
      Fmt.pf ppf "%a:@ @[<hov>%a@]" Mrmime.Field_name.pp field_name Spf.pp_spf
        spf
  | Field (field_name, v) ->
      Fmt.pf ppf "%a:@ %S" Mrmime.Field_name.pp field_name
        (Unstrctrd.to_utf_8_string v)

let elt_to_field = function
  | From (field_name, v, _) -> (field_name, v)
  | DKIM (field_name, v, _) -> (field_name, v)
  | SPF (field_name, v, _) -> (field_name, v)
  | Field (field_name, v) -> (field_name, v)

type info = {
  prelude : string;
  fields : elt list;
  from : Emile.mailbox;
  domain : [ `raw ] Domain_name.t;
}

let pp_info ppf info =
  Fmt.pf ppf
    "{ @[<hov>prelude= %S;@ fields= @[<hov>%a@];@ from= @[<hov>%a@];@ domain= \
     @[<hov>%a@];@] }"
    info.prelude
    Fmt.(Dump.list pp_elt)
    info.fields Emile.pp_mailbox info.from Domain_name.pp info.domain

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
  R.get_ok (Unstrctrd.of_list (List.rev unstrctrd))

let parse_from_field_value unstrctrd =
  let str = Unstrctrd.(to_utf_8_string (fold_fws unstrctrd)) in
  match Angstrom.parse_string ~consume:Prefix Emile.Parser.mailbox_list str with
  | Ok _ as v -> v
  | Error _ -> R.error (`Invalid_From_field unstrctrd)

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
  | Some mailbox -> R.ok mailbox
  | None ->
      R.error `Missing_From_field
      (* - Messages that have no RFC5322.From field at all are typically rejected. *)
  | exception Multiple_from -> R.error `Multiple_mailboxes

(* TODO(dinosaure): RFC7489 talks about "syntactically valid __multi-valued__ RFC5322.From" field
 * as a valid case to initiate DMARC verification. But I don't know the meaning of such case! *)

let emile_domain_to_domain_name = function
  | ( `Addr (Emile.IPv4 _)
    | `Addr (Emile.IPv6 _)
    | `Addr (Emile.Ext _)
    | `Literal _ ) as domain ->
      R.error (`Invalid_domain domain)
  | `Domain lst as domain ->
      R.reword_error
        (fun _ -> `Invalid_domain domain)
        (Domain_name.of_strings lst)

let domain_aligned ~relaxed dmarc v =
  match relaxed with
  | true -> Domain_name.is_subdomain ~subdomain:v ~domain:dmarc.domain
  | false -> Domain_name.equal v dmarc.domain

let _domain_aligned ~relaxed dmarc v =
  match domain_aligned ~relaxed dmarc v with
  | true -> Ok ()
  | false -> Error (`Domain_unaligned (v, dmarc.domain))

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

let _filter_dkim_from_domain ?(alignment = Value.Relaxed) ~from fields =
  let f acc = function
    | DKIM (field_name, v, dkim) as field -> (
        let d = Dkim.domain dkim in
        (* XXX(dinosaure): According to RFC 7489, 3.1.1:

           In relaxed mode, the organizational Domains of both the [DKIM]-
           authenticated signing domain (taken from the value of the "d=" tag in
           the signature) and that of the RFC5322.From domain must be equal if
           the identifiers are to be considered aligned. In strict mode, only
           an exact match between both of the Fully Qualified Domain Names
           (FQDNs) is considered to produce Identifier Alignment. *)
        match alignment with
        | Value.Relaxed -> (
            match
              (organization_domain ~domain:d, organization_domain ~domain:from)
            with
            | Some a, Some b ->
                if Domain_name.equal a b
                then field :: acc
                else Field (field_name, v) :: acc
            | _ -> Field (field_name, v) :: acc)
        | Value.Strict ->
            let fqdn_a = d and fqdn_b = from in
            if Domain_name.equal fqdn_a fqdn_b
            then field :: acc
            else Field (field_name, v) :: acc)
    | field -> field :: acc in
  List.fold_left f [] fields |> List.rev

let ctx_of_spf_result = function Ok (ctx, _) -> ctx | Error (ctx, _) -> ctx

let valid dkim = Ok (`Valid dkim)

let invalid dkim = Ok (`Invalid dkim)

let dkim_record_unreachable dkim = Error (`DKIM_record_unreachable dkim)

let invalid_dkim_record ~record dkim =
  Error (`Invalid_DKIM_record (dkim, record))

let identifier_alignment_checks info ~dmarc ~spf ~dkims =
  let spf_aligned =
    match
      (dmarc.spf_alignment, info.domain, Spf.domain (ctx_of_spf_result spf))
    with
    | Value.Strict, domain, Some domain' -> Domain_name.equal domain domain'
    | Value.Relaxed, domain, Some domain' -> (
        Fmt.epr "Organizational domain of RFC5322.From: %a.\n%!"
          Fmt.(Dump.option Domain_name.pp)
          (organization_domain ~domain) ;
        Fmt.epr "Organizational domain of SPF: %a.\n%!"
          Fmt.(Dump.option Domain_name.pp)
          (organization_domain ~domain:domain') ;
        match
          (organization_domain ~domain, organization_domain ~domain:domain')
        with
        | Some a, Some b -> Domain_name.equal a b
        | _ -> false)
    | _, _, None -> false in
  let dkims_aligned =
    let f acc dkim_result =
      let dkim, ctor =
        match dkim_result with
        | Ok (`Valid dkim) -> (dkim, valid)
        | Ok (`Invalid dkim) -> (dkim, invalid)
        | Error (`DKIM_record_unreachable dkim) ->
            (dkim, dkim_record_unreachable)
        | Error (`Invalid_DKIM_record (dkim, record)) ->
            (dkim, invalid_dkim_record ~record) in
      match (dmarc.dkim_alignment, info.domain, Dkim.domain dkim) with
      | Value.Strict, domain, domain' when Domain_name.equal domain domain' ->
          ctor dkim :: acc
      | Value.Relaxed, domain, domain' -> (
          match
            (organization_domain ~domain, organization_domain ~domain:domain')
          with
          | Some a, Some b when Domain_name.equal a b -> ctor dkim :: acc
          | _ -> acc (* XXX(dinosaure): not sure! *))
      | Value.Strict, _, _ -> acc in
    List.fold_left f [] dkims in
  let is_valid = function Ok (`Valid _) -> true | _ -> false in
  match (spf_aligned, spf, List.for_all is_valid dkims_aligned) with
  | true, Ok (_, (`Neutral | `None | `Pass _)), true -> `Pass
  | false, _, true -> `Pass
  | _ -> `Fail (spf, dkims_aligned)

type error =
  [ `DMARC_unreachable
  | `Invalid_DMARC of string
  | `Invalid_DMARC_policy of string
  | `SPF_error_with of Spf.ctx * string
  | `Invalid_domain of Emile.domain
  | `Invalid_email
  | `Missing_From_field
  | `Multiple_mailboxes
  | `Missing_DMARC_policy
  | `Domain_unaligned of [ `raw ] Domain_name.t * [ `raw ] Domain_name.t ]

let pp_error ppf = function
  | `DMARC_unreachable -> Fmt.string ppf "DMARC unreachable"
  | `Invalid_DMARC record -> Fmt.pf ppf "Invalid DMARC record %S" record
  | `Invalid_DMARC_policy policy -> Fmt.pf ppf "Invalid DMARC policy %S" policy
  | `SPF_error_with (_ctx, err) -> Fmt.pf ppf "SPF error: %s" err
  | `Invalid_domain domain ->
      Fmt.pf ppf "Invalid domain: %a" Emile.pp_domain domain
  | `Invalid_email -> Fmt.pf ppf "Invalid email"
  | `Missing_From_field -> Fmt.pf ppf "Missing From field"
  | `Multiple_mailboxes -> Fmt.pf ppf "Multiple senders"
  | `Missing_DMARC_policy -> Fmt.string ppf "Missing DMARC policy"
  | `Domain_unaligned (a, b) ->
      Fmt.pf ppf "Domain %a unaligned with %a" Domain_name.pp a Domain_name.pp b

type dmarc_result = [ `Pass | `Fail of spf_result * dkim_result list ]

module Make
    (Scheduler : X with type +'a s = 'a Lwt.t)
    (* TODO *)
    (IO : IO with type +'a t = 'a Scheduler.s)
    (Flow : FLOW with type +'a io = 'a IO.t)
    (DNS : DNS with type +'a io = 'a IO.t) =
struct
  module DKIM_scheduler = Dkim.Sigs.Make (IO)
  module SPF_scheduler = Spf.Sigs.Make (IO)
  open IO

  let dkim_scheduler =
    let open DKIM_scheduler in
    {
      Dkim.Sigs.bind = (fun x f -> inj (IO.bind (prj x) (fun x -> prj (f x))));
      Dkim.Sigs.return = (fun x -> inj (IO.return x));
    }

  let spf_scheduler =
    let open SPF_scheduler in
    {
      Spf.Sigs.bind = (fun x f -> inj (IO.bind (prj x) (fun x -> prj (f x))));
      Spf.Sigs.return = (fun x -> inj (IO.return x));
    }

  let ( >>= ) = IO.bind

  let ( >>| ) x f = x >>= fun x -> return (f x)

  let ( >>? ) x f =
    x >>= function Ok x -> f x | Error err -> return (Error err)

  (* XXX(dinosaure): Step 1 of RFC 7489, Section 6.6.2. *)
  let extract_info :
      ?newline:newline -> Flow.flow -> (info, [> error ]) result IO.t =
   fun ?(newline = LF) flow ->
    let open Mrmime in
    let chunk = 0x1000 in
    let raw = Bytes.create chunk in
    let decoder = Hd.decoder p in
    let rec go acc =
      match Hd.decode decoder with
      | `Field field -> (
          let (Field.Field (field_name, w, v)) = Location.prj field in
          match
            ( Field_name.equal field_name Field_name.from,
              Field_name.equal field_name Dkim.field_dkim_signature,
              Field_name.equal field_name Spf.field_received_spf,
              w )
          with
          | true, false, false, Field.Unstructured -> (
              let v = to_unstrctrd v in
              match parse_from_field_value v with
              | Ok mailboxes -> go (From (field_name, v, mailboxes) :: acc)
              | Error _ -> go (Field (field_name, v) :: acc))
          | false, true, false, Field.Unstructured -> (
              let v = to_unstrctrd v in
              match
                R.(Dkim.parse_dkim_field_value v >>= Dkim.post_process_dkim)
              with
              | Ok dkim -> go (DKIM (field_name, v, dkim) :: acc)
              | Error _ -> go (Field (field_name, v) :: acc))
          | false, false, true, Field.Unstructured -> (
              let v = to_unstrctrd v in
              match Spf.parse_received_spf_field_value v with
              | Ok spf -> go (SPF (field_name, v, spf) :: acc)
              | Error _ -> go (Field (field_name, v) :: acc))
          | _, _, _, Field.Unstructured ->
              let v = to_unstrctrd v in
              go (Field (field_name, v) :: acc)
          | _ -> assert false)
      | `Malformed _err -> return (R.error `Invalid_email)
      | `End rest -> return (Ok (rest, List.rev acc))
      | `Await ->
          Flow.input flow raw 0 (Bytes.length raw) >>= fun len ->
          let raw = sanitize_input newline raw len in
          Hd.src decoder raw 0 (String.length raw) ;
          go acc in
    go [] >>? fun (prelude, fields) ->
    return (extract_from fields) >>? fun from ->
    (* TODO(dinosaure): at this point, the domain name can be encoded with UTF-8,
     * we must converte to an A-label. *)
    let { Emile.domain = domain, _; _ } = from in
    return (emile_domain_to_domain_name domain) >>? fun domain ->
    return (R.ok { prelude; from; domain; fields })

  let crlf digest n =
    let rec go = function
      | 0 -> ()
      | n ->
          digest (Some "\r\n") ;
          go (pred n) in
    if n < 0 then Fmt.invalid_arg "Expect at least 0 <crlf>" else go n

  let extract_body :
      ?newline:newline ->
      (unit -> string option IO.t) ->
      prelude:string ->
      simple:(string option -> unit) ->
      relaxed:(string option -> unit) ->
      [ `Consume of unit IO.t ] =
   fun ?(newline = LF) stream ~prelude ~simple ~relaxed ->
    let decoder = Dkim.Body.decoder () in
    let chunk = 0x1000 in
    let raw = Bytes.create (max chunk (String.length prelude)) in

    Bytes.blit_string prelude 0 raw 0 (String.length prelude) ;

    let digest_stack ?(relaxed = false) f l =
      let rec go = function
        | [] -> ()
        | [ `Spaces x ] -> f (Some (if relaxed then " " else x))
        | `CRLF :: r ->
            f (Some "\r\n") ;
            go r
        | `Spaces x :: r ->
            if not relaxed then f (Some x) ;
            go r in
      go (List.rev l) in
    let rec go stack =
      match Dkim.Body.decode decoder with
      | `Await -> (
          stream () >>= function
          | None ->
              Dkim.Body.src decoder Bytes.empty 0 0 ;
              go stack
          | Some str ->
              let raw =
                sanitize_input newline
                  (Bytes.unsafe_of_string str)
                  (String.length str) in
              Dkim.Body.src decoder (Bytes.of_string raw) 0 (String.length raw) ;
              go stack)
      | `End ->
          crlf relaxed 1 ;
          crlf simple 1 ;
          relaxed None ;
          simple None ;
          return ()
      | `Spaces _ as x -> go (x :: stack)
      | `CRLF -> go (`CRLF :: stack)
      | `Data x ->
          digest_stack ~relaxed:true relaxed stack ;
          relaxed (Some x) ;
          digest_stack simple stack ;
          simple (Some x) ;
          go [] in
    Dkim.Body.src decoder raw 0 (String.length prelude) ;
    `Consume (go [])

  module DKIM_DNS = struct
    type backend = DKIM_scheduler.t

    type t = DNS.t

    let gettxtrrecord dns domain_name =
      DNS.getrrecord dns Dns.Rr_map.Txt domain_name >>= function
      | Ok (_ttl, vs) -> return (Ok (Dns.Rr_map.Txt_set.elements vs))
      | Error (`Msg _ as msg) -> return (Error msg)
      | Error (`No_data (domain_name, _soa)) ->
          return (R.error_msgf "No data for %a" Domain_name.pp domain_name)
      | Error (`No_domain (domain_name, _soa)) ->
          return (R.error_msgf "%a not found" Domain_name.pp domain_name)

    let gettxtrrecord dns domain_name =
      DKIM_scheduler.inj (gettxtrrecord dns domain_name)
  end

  module SPF_DNS = struct
    type backend = SPF_scheduler.t

    type t = DNS.t

    type error = DNS.error

    let getrrecord dns record domain_name =
      SPF_scheduler.inj (DNS.getrrecord dns record domain_name)
  end

  (* XXX(dinosaure): Step 2 of RFC7489, Section 6.6.2. *)
  let extract_dmarc ~domain dns =
    let dmarc_domain = Domain_name.prepend_label_exn domain "_dmarc" in
    DNS.getrrecord dns Dns.Rr_map.Txt dmarc_domain >>= function
    | Ok (_ttl, vs) ->
        (* TODO(dinosaure): discard any TXT which does not start with v=DMARC1. *)
        let str = String.concat "" (Dns.Rr_map.Txt_set.elements vs) in
        return R.(Decoder.parse_record str >>= dmarc_of_map)
    | Error _ ->
    match organization_domain ~domain with
    | None -> return (Error `DMARC_unreachable)
    | Some organization_domain -> (
        let dmarc_domain =
          Domain_name.prepend_label_exn organization_domain "_dmarc" in
        DNS.getrrecord dns Dns.Rr_map.Txt dmarc_domain >>= function
        | Ok (_ttl, vs) ->
            let str = String.concat "" (Dns.Rr_map.Txt_set.elements vs) in
            return R.(Decoder.parse_record str >>= dmarc_of_map)
        | Error _ -> return (Error `DMARC_unreachable))
  (* TODO(dinosaure): check Section 6.6.3 to see how to get the DMARC policy.
   * The DMARC policy can comes from the organizational domain instead of the
   * domain given by RFC5322.From. *)

  let verify_spf ~ctx dns =
    Spf.get ~ctx spf_scheduler dns (module SPF_DNS) |> SPF_scheduler.prj
    >>= function
    | Error (`Msg err) -> return (Error (ctx, err))
    | Ok record ->
        Spf.check ~ctx spf_scheduler dns (module SPF_DNS) record
        |> SPF_scheduler.prj
        >>| fun res -> R.ok (ctx, res)

  let verify ?newline ~ctx ~epoch dns flow =
    extract_info ?newline flow >>? fun info ->
    let q = Queue.create () in
    let fields = List.map elt_to_field info.fields in
    let f (dkim_field_name, dkim_field_value, dkim, simple, relaxed) =
      let open DKIM_scheduler in
      Dkim.extract_server dns dkim_scheduler (module DKIM_DNS) dkim
      |> prj
      >>| R.reword_error (fun _ -> `DKIM_record_unreachable dkim)
      >>? fun n ->
      Dkim.post_process_server n
      |> return
      >>| R.reword_error (fun _ -> `Invalid_DKIM_record (dkim, n))
      >>? fun server ->
      Dkim.verify dkim_scheduler ~epoch fields
        (dkim_field_name, dkim_field_value)
        ~simple:(fun () -> inj (Lwt_stream.get simple))
        ~relaxed:(fun () -> inj (Lwt_stream.get relaxed))
        dkim server
      |> prj
      >>= function
      | true -> return (Ok (`Valid dkim))
      | false -> return (Ok (`Invalid dkim)) in
    let s_emitter x = Queue.push (`S x) q in
    let r_emitter x = Queue.push (`R x) q in
    let make_streams acc = function
      | DKIM (dkim_field_name, dkim_field_value, dkim) ->
          let s, s_pusher = Lwt_stream.create_bounded 10 in
          let r, r_pusher = Lwt_stream.create_bounded 10 in
          ((dkim_field_name, dkim_field_value, dkim, s, r), (s_pusher, r_pusher))
          :: acc
      | _ -> acc in
    let dkim_fields_with_streams = List.fold_left make_streams [] info.fields in
    let dkim_fields_with_streams = List.rev dkim_fields_with_streams in
    let dkim_fields, pushers = List.split dkim_fields_with_streams in
    let s_pushers, r_pushers = List.split pushers in
    let i_emmitter, i_pusher = Lwt_stream.create_bounded 10 in
    let rec consume tmp =
      match Queue.pop q with
      | `Await -> (
          Flow.input flow tmp 0 (Bytes.length tmp) >>= function
          | 0 ->
              i_pusher#close ;
              consume tmp
          | len ->
              i_pusher#push (Bytes.sub_string tmp 0 len) >>= fun () ->
              consume tmp)
      | `S (Some str) ->
          IO.iter_p (fun v -> v#push str) s_pushers >>= fun () -> consume tmp
      | `R (Some str) ->
          IO.iter_p (fun v -> v#push str) r_pushers >>= fun () -> consume tmp
      | `S None ->
          List.iter (fun v -> v#close) s_pushers ;
          if List.for_all (fun v -> v#closed) r_pushers
          then return ()
          else consume tmp
      | `R None ->
          List.iter (fun v -> v#close) r_pushers ;
          if List.for_all (fun v -> v#closed) s_pushers
          then return ()
          else consume tmp
      | exception Queue.Empty -> IO.pause () >>= fun () -> consume tmp in
    let (`Consume th) =
      extract_body ?newline ~prelude:info.prelude
        (fun () ->
          Queue.push `Await q ;
          Lwt_stream.get i_emmitter)
        ~simple:s_emitter ~relaxed:r_emitter in
    let ( >|= ) x f = x >>= fun x -> return (f x) in
    IO.all (* XXX(dinosaure): or [lift4]? *)
      [
        (IO.join [ th; consume (Bytes.create 0x1000) ] >|= fun () -> `Unit);
        (extract_dmarc ~domain:info.domain dns >|= fun v -> `DMARC v);
        (verify_spf ~ctx dns >|= fun v -> `SPF v);
        (IO.map_p f dkim_fields >|= fun v -> `DKIM v);
      ]
    >>= function
    | [ `Unit; `DMARC (Ok dmarc); `SPF spf; `DKIM dkims ] ->
        Log.debug (fun m ->
            m "Got SPF result: %a."
              Fmt.(result ~ok:(using snd Spf.pp_res) ~error:(using snd string))
              spf) ;
        let result = identifier_alignment_checks info ~dmarc ~spf ~dkims in
        return (Ok result)
    | [ `Unit; `DMARC (Error err); _; _ ] -> return (Error err)
    | _ -> assert false
end
