(* NOTE(dinosaure): a simple continuation monad for DNS lookups. *)

type kind = [ `Txt | `Exists ]

type answer =
  [ `Txt of string list | `Exists | `No_domain | `No_data | `Error of string ]

module Key = struct
  type t = [ `raw ] Domain_name.t * kind

  let compare (a, ka) (b, kb) =
    match Domain_name.compare a b with 0 -> Stdlib.compare ka kb | n -> n
end

module Cache = Map.Make (Key)

type cache = answer Cache.t
type 'a step = [ `Need of [ `raw ] Domain_name.t * kind | `Done of 'a ]
type 'a t = cache -> 'a step

let empty = Cache.empty

let add cache domain_name kind answer =
  Cache.add (domain_name, kind) answer cache

let return x : 'a t = fun _ -> `Done x

let bind (m : 'a t) (fn : 'a -> 'b t) : 'b t =
 fun cache ->
  match m cache with `Need _ as need -> need | `Done x -> fn x cache

let map fn m = bind m (fun x -> return (fn x))

let ask domain_name kind : answer t =
 fun cache ->
  match Cache.find_opt (domain_name, kind) cache with
  | Some answer -> `Done answer
  | None -> `Need (domain_name, kind)

let step cache (m : 'a t) = m cache

let run ~lookup m =
  let rec go cache =
    match m cache with
    | `Done v -> v
    | `Need (domain_name, kind) ->
        go (add cache domain_name kind (lookup domain_name kind)) in
  go empty

module Syntax = struct
  let ( let* ) = bind
  let ( let+ ) m f = map f m
end
