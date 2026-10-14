(** Domain-based Message Authentication, Reporting, and Conformance (DMARC). *)

type policy = [ `None | `Quarantine | `Reject ]
(** Domain Owner Assessment Policy (RFC 9989, Section 3.2.8). *)

type mode = [ `Relaxed | `Strict ]
(** Identifier Alignment mode (RFC 9989, Section 3.2.10). *)

type psd = [ `Yes | `No | `Unknown ]
type fo = [ `_0 | `_1 | `D | `S ]

val pp_policy : policy Fmt.t

(** {1 DMARC Policy Record} *)

module Record : sig
  type t = {
      p : policy option  (** The ["p"] tag, [None] is treated as ["p=none"]. *)
    ; sp : policy option
    ; np : policy option
    ; adkim : mode
    ; aspf : mode
    ; fo : fo list
    ; psd : psd
    ; t : bool  (** The ["t"] tag (test mode). *)
    ; rua : Uri.t list
    ; ruf : Uri.t list
    ; usable : bool
          (** [false] if the record contains an invalid ["p"], ["sp"] or ["np"]
              tag without a valid ["rua"] tag: in that case, no DMARC processing
              applies (RFC 9989, Section 4.10.1). *)
  }

  val of_string : string -> (t, [> `Msg of string ]) result
  (** [of_string str] parses a DMARC Policy Record (RFC 9989, Section 4.8). The
      record must start with ["v=DMARC1"]. Unknown tags and syntax errors in tag
      values are ignored in favor of default values. The removed tags ["pct"],
      ["rf"] and ["ri"] are ignored. *)

  val is_dmarc : string -> bool
  (** [is_dmarc str] is [true] if [str] starts with a valid ["v=DMARC1"] tag. *)

  val policy : t -> policy
  (** [policy t] is the ["p"] tag of [t] (["none"] if absent). *)

  val pp : t Fmt.t
end

module Lookup : sig
  type kind = [ `Txt | `Exists ]
  (** [`Txt] asks the TXT records of a domain. [`Exists] asks whether a domain
      exists (an [A] query can be used: only a [NXDOMAIN] answer matters). *)

  type answer =
    [ `Txt of string list
      (** Each element is one TXT record (with its character-strings already
          concatenated). *)
    | `Exists
    | `No_domain  (** NXDOMAIN *)
    | `No_data
    | `Error of string  (** A transient error. *) ]

  type 'a t
  type cache

  val empty : cache
  val add : cache -> [ `raw ] Domain_name.t -> kind -> answer -> cache

  val step :
    cache -> 'a t -> [ `Need of [ `raw ] Domain_name.t * kind | `Done of 'a ]

  val run : lookup:([ `raw ] Domain_name.t -> kind -> answer) -> 'a t -> 'a
end

val organizational_domain :
  _ Domain_name.t -> ([ `raw ] Domain_name.t, [> `Temperror ]) result Lookup.t
(** [organizational_domain domain] is the Organizational Domain of [domain]
    determined by a DNS Tree Walk (RFC 9989, Sections 4.10 and 4.10.2). *)

module Report : sig
  val destinations :
       domain:_ Domain_name.t
    -> [ `Rua | `Ruf ]
    -> Record.t
    -> (Uri.t list, [> `Temperror ]) result Lookup.t
  (** [destinations ~domain kind record] are the URIs of the ["rua"] (aggregate
      reports) or ["ruf"] (failure reports) tag of [record] (discovered at
      [domain]) to which reports can be sent. External destinations are verified
      (and possibly overridden) according to RFC 9990, Section 4 and RFC 9991,
      Section 5. *)
end

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
    [ `Invalid_email
    | `Unexpected_response of Dns.Rr_map.k
    | `Invalid_domain of Emile.domain
    | `Missing_From_field
    | `Multiple_From_fields
    | `Multiple_author_domains
    | `Missing_SPF_context ]
  (** Errors which make the DMARC validation impossible. *)

  val pp_error : error Fmt.t

  type result = [ `Pass | `Fail | `None | `Temperror | `Permerror ]
  (** The DMARC result:
      - [`None]: no DMARC Policy Record exists for the Author Domain.
      - [`Pass]: an Authenticated Identifier is aligned with the Author Domain.
      - [`Fail]: no Authenticated Identifier is aligned with the Author Domain.
      - [`Temperror]: a DNS query failed (transient error).
      - [`Permerror]: the DMARC Policy Record is unusable. *)

  val pp_result : result Fmt.t

  type policy = {
      record : Record.t
    ; domain : [ `raw ] Domain_name.t  (** The DMARC Policy Domain. *)
    ; assessment : [ `None | `Quarantine | `Reject ]
          (** The Domain Owner Assessment Policy applicable to the Author Domain
              (["p"], ["sp"] or ["np"]). *)
    ; applied : [ `None | `Quarantine | `Reject ]
          (** [assessment] after the effect of ["t=y"] (one level below). *)
  }

  type info = {
      domain : [ `raw ] Domain_name.t  (** The Author Domain. *)
    ; spf : Uspf.Result.t
    ; ctx : Uspf.ctx
    ; dkims : DKIM.t list
    ; policy : policy option
    ; result : result
  }

  type decode =
    [ `Await of decoder
    | `Query of decoder * [ `raw ] Domain_name.t * Dns.Rr_map.k
    | `Info of info
    | error ]

  val decoder : ?ctx:Uspf.ctx -> unit -> decoder
  val decode : decoder -> decode
  val src : decoder -> string -> int -> int -> decoder
  val response : decoder -> 'a Dns.Rr_map.key -> 'a Uspf.response -> decoder
end

(** {1 Authentication-Results} *)

module Encoder : sig
  val value : receiver:Emile.domain -> Verify.info Prettym.t
  val field : receiver:Emile.domain -> Verify.info Prettym.t
end

val to_field :
  receiver:Emile.domain -> Verify.info -> Mrmime.Field_name.t * Unstrctrd.t

val field_authentication_results : Mrmime.Field_name.t

module Authentication_results : sig
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

  module Decoder : sig
    val authres_payload : t Angstrom.t
  end

  val of_unstrctrd : Unstrctrd.t -> (t, [> `Msg of string ]) Stdlib.result
  val to_unstrctrd : t -> Unstrctrd.t
  val of_verification : receiver:Emile.domain -> Verify.info -> t
end
