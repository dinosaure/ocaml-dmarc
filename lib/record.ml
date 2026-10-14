(* DMARC Policy Record, see RFC 9989, Sections 4.7 and 4.8. *)

type t = {
    p : Value.policy option
  ; sp : Value.policy option
  ; np : Value.policy option
  ; adkim : Value.mode
  ; aspf : Value.mode
  ; fo : Value.fo list
  ; psd : Value.psd
  ; t : bool
  ; rua : Uri.t list
  ; ruf : Uri.t list
  ; usable : bool
}

let pp ppf t =
  let pp_opt name pp ppf = function
    | None -> ()
    | Some v -> Fmt.pf ppf "@ %s=%a;" name pp v in
  let pp_uris name ppf = function
    | [] -> ()
    | uris ->
        Fmt.pf ppf "@ %s=%a;" name
          Fmt.(list ~sep:(any ",") (using Uri.to_string string))
          uris in
  Fmt.pf ppf
    "@[<hov>v=DMARC1;%a%a%a@ adkim=%a;@ aspf=%a;@ fo=%a;@ psd=%a;@ t=%s;%a%a@]"
    (pp_opt "p" Value.pp_policy)
    t.p
    (pp_opt "sp" Value.pp_policy)
    t.sp
    (pp_opt "np" Value.pp_policy)
    t.np Value.pp_mode t.adkim Value.pp_mode t.aspf
    Fmt.(list ~sep:(any ":") Value.pp_fo)
    t.fo Value.pp_psd t.psd
    (if t.t then "y" else "n")
    (pp_uris "rua") t.rua (pp_uris "ruf") t.ruf

let is_wsp = function ' ' | '\t' -> true | _ -> false

let trim str =
  let len = String.length str in
  let i = ref 0 and j = ref (len - 1) in
  while !i < len && is_wsp str.[!i] do
    incr i
  done ;
  while !j >= !i && is_wsp str.[!j] do
    decr j
  done ;
  String.sub str !i (!j - !i + 1)

let is_alpha = function 'a' .. 'z' | 'A' .. 'Z' -> true | _ -> false

(* [dmarc-tag = 1*ALPHA equals 1*dmarc-value]. *)
let tag str =
  match String.index_opt str '=' with
  | None -> None
  | Some idx ->
      let name = trim (String.sub str 0 idx) in
      let value =
        trim (String.sub str (idx + 1) (String.length str - idx - 1)) in
      if name = "" || (not (String.for_all is_alpha name)) || value = ""
      then None
      else Some (String.lowercase_ascii name, value)

let segments str = List.map trim (String.split_on_char ';' str)

(* [dmarc-version = "v" equals %s"DMARC1"] and it MUST be the first tag. *)
let is_version str =
  match tag str with Some ("v", "DMARC1") -> true | _ -> false

let is_dmarc str =
  match segments str with first :: _ -> is_version first | [] -> false

let is_digit = function '0' .. '9' -> true | _ -> false

(* NOTE(dinosaure): [obs-dmarc-report-size] (e.g. "!10m") is obsolete and must
   be ignored. *)
let remove_obs_report_size str =
  match String.rindex_opt str '!' with
  | None -> str
  | Some idx ->
      let size = String.sub str (idx + 1) (String.length str - idx - 1) in
      let len = String.length size in
      let digits =
        if
          len > 0
          && String.contains "kmgt" (Char.lowercase_ascii size.[len - 1])
        then String.sub size 0 (len - 1)
        else size in
      if digits <> "" && String.for_all is_digit digits
      then String.sub str 0 idx
      else str

(* NOTE(dinosaure): [dmarc-urilist]: malformed URIs are ignored. *)
let uris str =
  let fn str =
    let str = remove_obs_report_size (trim str) in
    if str = ""
    then None
    else
      let uri = Uri.of_string str in
      match Uri.scheme uri with Some _ -> Some uri | None -> None in
  List.filter_map fn (String.split_on_char ',' str)

(* [dmarc-fo]: "0" and "1" are mutually exclusive and "d" and "s" may appear at
   most once. *)
let fo str =
  let values = List.map Value.fo_of_string (String.split_on_char ':' str) in
  if List.exists Option.is_none values
  then None
  else
    let values = List.filter_map Fun.id values in
    let count v = List.length (List.filter (( = ) v) values) in
    let zero = count `_0 and one = count `_1 in
    if values = [] || zero + one > 1 || count `D > 1 || count `S > 1
    then None
    else Some values

type value = [ `Absent | `Invalid | `Value of Value.policy ]

let of_string str =
  match segments str with
  | first :: rest when is_version first ->
      let tags = List.filter_map tag rest in
      let find name = List.assoc_opt name tags in
      let parse name fn = Option.bind (find name) fn in
      let policy name : value =
        match find name with
        | None -> `Absent
        | Some v ->
        match Value.policy_of_string v with
        | Some v -> `Value v
        | None -> `Invalid in
      let rua = Option.value ~default:[] (Option.map uris (find "rua")) in
      let ruf = Option.value ~default:[] (Option.map uris (find "ruf")) in
      let adkim =
        Option.value ~default:`Relaxed (parse "adkim" Value.mode_of_string)
      in
      let aspf =
        Option.value ~default:`Relaxed (parse "aspf" Value.mode_of_string) in
      let fo = Option.value ~default:[ `_0 ] (parse "fo" fo) in
      let psd =
        Option.value ~default:`Unknown (parse "psd" Value.psd_of_string) in
      let t = Option.value ~default:false (parse "t" Value.yorn_of_string) in
      let to_option = function
        | `Value v -> Some v
        | `Absent | `Invalid -> None in
      let p = policy "p" and sp = policy "sp" and np = policy "np" in
      (* NOTE(dinosaure): see RFC 9989, Section 4.10.1. If a record does not
         contain a valid "p" tag, or contains an "sp" or "np" tag that is not
         valid, we act as if the record contains "p=none" if a valid "rua"
         exists. Otherwise, no DMARC processing applies. An absent "p" tag is
         treated as "p=none" (see Section 4.7). *)
      let invalid = p = `Invalid || sp = `Invalid || np = `Invalid in
      let p, sp, np, usable =
        match (invalid, rua) with
        | false, _ -> (to_option p, to_option sp, to_option np, true)
        | true, _ :: _ -> (Some `None, None, None, true)
        | true, [] -> (None, None, None, false) in
      Ok { p; sp; np; adkim; aspf; fo; psd; t; rua; ruf; usable }
  | _ -> Error `Not_a_DMARC_record

let policy t = Option.value ~default:`None t.p
