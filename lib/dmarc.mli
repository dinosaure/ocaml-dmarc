type t

val pp : t Fmt.t

module DKIM : sig
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
      spf : Uspf.Result.t
    ; ctx : Uspf.ctx
    ; dmarc : t
    ; domain : [ `raw ] Domain_name.t
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

val to_field :
     receiver:Emile.domain
  -> Verify.info * DKIM.t list * [ `Pass | `Fail ]
  -> Mrmime.Field_name.t * Unstrctrd.t
