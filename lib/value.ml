type policy = [ `None | `Quarantine | `Reject ]
type mode = [ `Relaxed | `Strict ]
type psd = [ `Yes | `No | `Unknown ]
type fo = [ `_0 | `_1 | `D | `S ]

let pp_policy ppf = function
  | `None -> Fmt.string ppf "none"
  | `Quarantine -> Fmt.string ppf "quarantine"
  | `Reject -> Fmt.string ppf "reject"

let pp_mode ppf = function
  | `Relaxed -> Fmt.string ppf "r"
  | `Strict -> Fmt.string ppf "s"

let pp_psd ppf = function
  | `Yes -> Fmt.string ppf "y"
  | `No -> Fmt.string ppf "n"
  | `Unknown -> Fmt.string ppf "u"

let pp_fo ppf = function
  | `_0 -> Fmt.string ppf "0"
  | `_1 -> Fmt.string ppf "1"
  | `D -> Fmt.string ppf "d"
  | `S -> Fmt.string ppf "s"

(* NOTE(dinosaure): According to RFC 5234, literal strings of ABNF are
   case-insensitive (except the "v" value which is explicitly marked as
   case-sensitive with [%s]). *)

let policy_of_string str =
  match String.lowercase_ascii str with
  | "none" -> Some `None
  | "quarantine" -> Some `Quarantine
  | "reject" -> Some `Reject
  | _ -> None

let mode_of_string str =
  match String.lowercase_ascii str with
  | "r" -> Some `Relaxed
  | "s" -> Some `Strict
  | _ -> None

let psd_of_string str =
  match String.lowercase_ascii str with
  | "y" -> Some `Yes
  | "n" -> Some `No
  | "u" -> Some `Unknown
  | _ -> None

let yorn_of_string str =
  match String.lowercase_ascii str with
  | "y" -> Some true
  | "n" -> Some false
  | _ -> None

let fo_of_string str =
  match String.lowercase_ascii str with
  | "0" -> Some `_0
  | "1" -> Some `_1
  | "d" -> Some `D
  | "s" -> Some `S
  | _ -> None
