let to_fd fd str =
  Unix.write fd (Bytes.unsafe_of_string str) 0 (String.length str)

let run uri filename =
  let fd = Unix.openfile filename Unix.[ O_CREAT; O_WRONLY; O_TRUNC; O_APPEND ] 0o600 in
  let curl = Curl.init () in
  Curl.set_url curl uri ;
  Curl.set_writefunction curl (to_fd fd) ;
  Curl.perform curl

let default_uri = ref "https://publicsuffix.org/list/public_suffix_list.dat"
let default_filename = ref "public_suffix_list.dat"

let args =
  [ "--source", Arg.String (fun uri -> default_uri := uri), "Source of the public suffix list." ]

let usage = Format.asprintf
   "Public Suffix List downloader.\
  \n\
  \nA simple downloader to get the public suffix list.
  \nUsage: %s [--source <uri>] [filename]
  \n" Sys.argv.(0)

let anon_args str = default_filename := str

let () =
  try Arg.parse args anon_args usage ;
      run !default_uri !default_filename
  with exn -> Format.eprintf "%s: %s\n%!" Sys.argv.(0) (Printexc.to_string exn)
