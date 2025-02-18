open Dmarc.Sigs

module Make (DNS : DNS with type +'a io = 'a Lwt.t) : sig
  val verify :
       ?newline:Dmarc.newline
    -> ctx:Uspf.ctx
    -> epoch:(unit -> int64)
    -> DNS.t
    -> (unit -> (string * int * int) option Lwt.t)
    -> (Dmarc.dmarc_result, [> Dmarc.error ]) result Lwt.t
end
