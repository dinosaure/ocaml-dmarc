let is_prefix affix str =
  if String.length affix > String.length str
  then false
  else
    let idx = ref 0 in
    while !idx < String.length affix
       && affix.[!idx] = str.[!idx]
    do incr idx done ;
    if !idx = String.length affix
    then true else false

let rec of_filename filename =
  let fd = Unix.openfile filename Unix.[ O_RDONLY ] 0o600 in
  let rs = go [] (Unix.in_channel_of_descr fd) in
  Unix.close fd ; rs
and go acc ic = match input_line ic with
  | "" -> go acc ic
  | line when not (is_prefix "//" line) ->
    ( match Domain_name.of_string line with
    | Ok domain_name -> go (domain_name :: acc) ic
    | Error (`Msg _err) -> go acc ic )
  | _comment -> go acc ic
  | exception End_of_file -> List.rev acc

let serialize ppf organization_domains =
  Format.fprintf ppf "let organization_domains = [\n%!" ;
  List.iter (fun domain_name -> Format.fprintf ppf "\t%S;\n%!" (Domain_name.to_string domain_name)) organization_domains ;
  Format.fprintf ppf "];;\n%!" ;
  Format.fprintf ppf
    "\nlet organization_domains = List.map Domain_name.of_string_exn organization_domains\
     \n%!"

let default_source = ref "public_suffix_list.dat"
let default_output = ref "organization_domains.ml"

let args =
  [ "--source", Arg.String (fun source -> default_source := source), "The public suffix list." ]

let usage = Format.asprintf
   "Public Suffix serializer.\
  \n\
  \nA simple serializer to OCaml of the public suffix list.
  \nUsage: %s [--source <filename>] [filename]
  \n" Sys.argv.(0)

let anon_args str = default_output := str

let () =
  try Arg.parse args anon_args usage ;
      let ods = of_filename !default_source in
      let fd  = Unix.openfile !default_output Unix.[ O_CREAT; O_WRONLY; O_TRUNC; O_APPEND; ] 0o600 in
      let ods = List.sort (fun a b -> String.length (Domain_name.to_string b) - String.length (Domain_name.to_string a)) ods in
      serialize (Format.formatter_of_out_channel (Unix.out_channel_of_descr fd)) ods ;
      Unix.close fd
  with exn -> Format.eprintf "%s: %s\n%!" Sys.argv.(0) (Printexc.to_string exn)
