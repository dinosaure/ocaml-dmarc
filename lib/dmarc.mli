module Sigs = Sigs
open Sigs

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
  [ `Pass of [ `raw ] Domain_name.t
  | `Fail of bool * spf_result * dkim_result list ]

module Make
    (Scheduler : X with type +'a s = 'a Lwt.t)
    (IO : IO with type +'a t = 'a Scheduler.s)
    (Flow : FLOW with type +'a io = 'a IO.t)
    (DNS : DNS with type +'a io = 'a IO.t) : sig
  val verify :
    ?newline:newline ->
    ctx:Uspf.ctx ->
    epoch:(unit -> int64) ->
    DNS.t ->
    Flow.flow ->
    (dmarc_result, [> error ]) result IO.t
end
