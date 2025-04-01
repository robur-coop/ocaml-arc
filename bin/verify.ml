let reporter ppf =
  let report src level ~over k msgf =
    let k _ = over () ; k () in
    let with_metadata header _tags k ppf fmt =
      Format.kfprintf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let () = Fmt_tty.setup_std_outputs ~style_renderer:`Ansi_tty ~utf_8:true ()
let () = Logs.set_reporter (reporter Fmt.stdout)
let () = Logs.set_level ~all:true (Some Logs.Debug)

let () =
  let buf = Bytes.create 0x7ff in
  let ( let* ) = Result.bind in
  let rec go decoder =
    match Arc.Verify.decode decoder with
    | `Await decoder ->
        let len = input stdin buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let str = String.split_on_char '\n' str in
        let str = String.concat "\r\n" str in
        let decoder = Arc.Verify.src decoder str 0 (String.length str) in
        go decoder
    | `Query set ->
        let* _queries = Arc.Verify.queries set in
        let* decoder = Arc.Verify.response decoder [] in
        go decoder
    | `Sets sets -> Ok sets
    | `Malformed err -> Error (`Msg err) in
  go (Arc.Verify.decoder ()) |> function
  | Ok _ -> ()
  | Error (`Msg msg) -> failwith msg
