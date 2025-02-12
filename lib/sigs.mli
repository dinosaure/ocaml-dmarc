module type FUNCTOR = sig
  type +'a t
end

type (+'a, 't) io

type 't state = {
    bind : 'a 'b. ('a, 't) io -> ('a -> ('b, 't) io) -> ('b, 't) io
  ; return : 'a. 'a -> ('a, 't) io
}

module type X = sig
  type +'a s
  type t

  external inj : 'a s -> ('a, t) io = "%identity"
  external prj : ('a, t) io -> 'a s = "%identity"
end

module Make (T : FUNCTOR) : X with type +'a s = 'a T.t

module type FLOW = sig
  type flow
  type +'a io

  val input : flow -> bytes -> int -> int -> int io
end

module type DNS = sig
  type t
  type +'a io

  type error =
    [ `Msg of string
    | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
    | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]

  val getrrecord :
    t -> 'v Dns.Rr_map.rr -> 'a Domain_name.t -> ('v, [> error ]) result io
end

module type IO = sig
  type +'a t

  val return : 'a -> 'a t
  val bind : 'a t -> ('a -> 'b t) -> 'b t
  val both : 'a t -> 'b t -> ('a * 'b) t
  val join : unit t list -> unit t
  val pause : unit -> unit t
  val iter_p : ('a -> unit t) -> 'a list -> unit t
  val map_p : ('a -> 'b t) -> 'a list -> 'b list t
  val all : 'a t list -> 'a list t
end
