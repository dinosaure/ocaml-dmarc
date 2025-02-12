module Lwt_scheduler = Dmarc.Sigs.Make (struct
  type +'a t = 'a Lwt.t
end)

module Lwt_io = struct
  type +'a t = 'a Lwt.t

  let return = Lwt.return
  let bind = Lwt.bind
  let both = Lwt.both
  let join = Lwt.join
  let pause = Lwt.pause
  let iter_p = Lwt_list.iter_p
  let map_p = Lwt_list.map_p
  let all = Lwt.all
end

open Dmarc.Sigs

module Make (DNS : DNS with type +'a io = 'a Lwt.t) = struct
  module Flow = struct
    type flow = {
        consumer : unit -> (string * int * int) option Lwt.t
      ; queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
    }

    type +'a io = 'a Lwt.t

    open Lwt.Infix

    let rec input t buffer off len =
      match Ke.Rke.N.peek t.queue with
      | x :: _ ->
          let len' = min len (Bigstringaf.length x) in
          Bigstringaf.blit_to_bytes x ~src_off:0 buffer ~dst_off:off ~len:len' ;
          Ke.Rke.N.shift_exn t.queue len' ;
          Lwt.return len'
      | [] -> (
          t.consumer () >>= function
          | None -> Lwt.return 0
          | Some (str, off', len') ->
              let blit src src_off dst dst_off len =
                Bigstringaf.blit_from_string src ~src_off dst ~dst_off ~len
              in
              Ke.Rke.N.push t.queue ~blit ~length:String.length ~off:off'
                ~len:len' str ;
              input t buffer off len)

    let make consumer =
      { consumer; queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char }
  end

  include Dmarc.Make (Lwt_scheduler) (Lwt_io) (Flow) (DNS)

  let verify ?newline ~ctx ~epoch dns consumer =
    let flow = Flow.make consumer in
    verify ?newline ~ctx ~epoch dns flow
end
