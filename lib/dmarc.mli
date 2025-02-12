(*
module Sigs = Sigs

type newline = LF | CRLF
type info

val pp_info : info Fmt.t

type dmarc

val pp_dmarc : dmarc Fmt.t

type spf_result = (Uspf.ctx * Uspf.res, Uspf.ctx * string) result

val pp_spf_result : spf_result Fmt.t

type dkim_result =
  ( [ `Invalid of Dkim.signed Dkim.dkim | `Valid of Dkim.signed Dkim.dkim ],
    [ `DKIM_record_unreachable of Dkim.signed Dkim.dkim
    | `Invalid_DKIM_record of Dkim.signed Dkim.dkim * Dkim.map ] )
  result

val organization_domain :
  domain:[ `raw ] Domain_name.t -> [ `raw ] Domain_name.t option

type error =
  [ `DMARC_unreachable
  | `Invalid_DMARC of string
  | `Invalid_DMARC_policy of string
  | `SPF_error_with of Uspf.ctx * string
  | `Invalid_domain of Emile.domain
  | `Invalid_email
  | `Missing_From_field
  | `Multiple_mailboxes
  | `Missing_DMARC_policy
  | `Domain_unaligned of [ `raw ] Domain_name.t * [ `raw ] Domain_name.t ]

val pp_error : error Fmt.t

type dmarc_result =
  [ `Pass of bool * Uspf.res * [ `raw ] Domain_name.t
  | `Fail of bool * spf_result * dkim_result list ]
*)

type t

module DKIM : sig
  type t =
    | Pass of { dkim : Dkim.signed Dkim.t; domain_key : Dkim.domain_key }
    | Fail of { dkim : Dkim.signed Dkim.t; domain_key : Dkim.domain_key }
    | Temperror of { dkim : Dkim.signed Dkim.t }
    | Permerror of {
        dkim : Dkim.signed Dkim.t;
        field_name : Mrmime.Field_name.t;
        value : Unstrctrd.t;
        error : error;
      }
    | Neutral of { field_name : Mrmime.Field_name.t; value : Unstrctrd.t }
    | Policy of { reason : string }

  and error = [ `Invalid_domain_key | `Domain_key_unavailable ]
end

module Verify : sig
  type decoder

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

  val pp_error : error Fmt.t

  type info = {
    spf : Uspf.Result.t option;
    ctx : Uspf.ctx;
    dmarc : t;
    domain : [ `raw ] Domain_name.t;
  }

  type decode =
    [ `Await of decoder
    | `Query of decoder * [ `raw ] Domain_name.t * Dns.Rr_map.k
    | `Info of info * DKIM.t list * [ `Pass | `Fail ]
    | error ]

  val decoder : ?ctx:Uspf.ctx -> unit -> decoder
  val decode : decoder -> decode
  val src : decoder -> string -> int -> int -> decoder
  val response : decoder -> 'a Dns.Rr_map.key -> 'a Uspf.response -> decoder
end
