type policy = None | Quarantine | Reject

type mode = Relaxed | Strict

type interval = int

type percent = int

type keyword = string

type uri = Uri.t * int64 option

let pp_policy ppf = function
  | None -> Fmt.string ppf "none"
  | Quarantine -> Fmt.string ppf "quarantine"
  | Reject -> Fmt.string ppf "reject"

let policy_of_string = function
  | "quarantine" -> Quarantine
  | "reject" -> Reject
  | "none" -> None
  | str -> Fmt.failwith "Invalid policy: %S" str

let pp_mode ppf = function
  | Relaxed -> Fmt.string ppf "relaxed"
  | Strict -> Fmt.string ppf "strict"

let mode_of_string = function
  | "r" -> Relaxed
  | "s" -> Strict
  | str -> Fmt.failwith "Invalid mode: %S" str

let pp_interval = Fmt.int

let pp_percent = Fmt.int

let pp_keyword = Fmt.string

let pp_uri ppf (uri, (weight : int64 option)) =
  match weight with
  | None -> Fmt.pf ppf "%s" (Uri.to_string uri)
  | Some weight -> Fmt.pf ppf "%s!%Ld" (Uri.to_string uri) weight

type 'a tag = { name : string; pp : 'a Fmt.t }

module Info = struct
  type 'a t = 'a tag = { name : string; pp : 'a Fmt.t }
end

include Hmap.Make (Info)

module K = struct
  let p : string key =
    Key.create { name = "Requested Mail Receiver policy"; pp = Fmt.string }

  let sp : string key =
    Key.create
      {
        name = "Requested Mail Receiver policy for sub-domains";
        pp = Fmt.string;
      }

  let adkim : mode key =
    Key.create { name = "DKIM Identifier alignment"; pp = pp_mode }

  let aspf : mode key =
    Key.create { name = "SPF Identifier alignment"; pp = pp_mode }

  let fo : [ `_0 | `_1 | `D | `S ] key =
    let pp ppf = function
      | `_0 -> Fmt.string ppf "0"
      | `_1 -> Fmt.string ppf "1"
      | `D -> Fmt.string ppf "d"
      | `S -> Fmt.string ppf "s" in
    Key.create { name = "Failure reporting"; pp }

  let rf : (string * string list) key =
    let pp ppf (x, r) = Fmt.(Dump.list string) ppf (x :: r) in
    Key.create
      { name = "Format to be used for message-specific failure reports"; pp }

  let pct : percent key = Key.create { name = "Percentage"; pp = Fmt.int }

  let ri : interval key =
    Key.create
      { name = "Interval requested between aggregate reports"; pp = Fmt.int }

  let rua : uri list key =
    Key.create
      {
        name = "Addresses to which aggregate feedback is to be sent";
        pp = Fmt.(Dump.list pp_uri);
      }

  let ruf : uri list key =
    Key.create
      {
        name =
          "Addresses to which message-specific failure information is be \
           reported";
        pp = Fmt.(Dump.list pp_uri);
      }
end

let failure_reporting_of_string = function
  | "0" -> `_0
  | "1" -> `_1
  | "d" -> `D
  | "s" -> `S
  | str -> Fmt.failwith "Invalid failure reporting: %S" str

let values_to_map lst =
  let f acc = function
    | `P v -> add K.p v acc
    | `SP v -> add K.sp v acc
    | `RUA vs -> add K.rua vs acc
    | `RUF vs -> add K.ruf vs acc
    | `ADKIM v -> add K.adkim (mode_of_string v) acc
    | `ASPF v -> add K.aspf (mode_of_string v) acc
    | `RI v -> add K.ri v acc
    | `FO v -> add K.fo (failure_reporting_of_string v) acc
    | `RF (x :: r) -> add K.rf (x, r) acc
    | `RF [] -> acc
    | `PCT v -> add K.pct v acc
    | `V _ -> acc in
  List.fold_left f empty lst
