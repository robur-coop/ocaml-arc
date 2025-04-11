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
let ( % ) = Fun.compose

let dns_queries t dns =
  let fn dn =
    let result = Dns_client_unix.get_resource_record t Dns.Rr_map.Txt dn in
    let response =
      match result with
      | Error (`Msg msg) -> `DNS_error msg
      | Error (`No_data (dn, _soa)) ->
          `DNS_error (Fmt.str "No TXT record for %a" Domain_name.pp dn)
      | Error (`No_domain (dn, _soa)) ->
          `DNS_error (Fmt.str "domain-name %a does not exist" Domain_name.pp dn)
      | Ok (_ttl, txts) -> (
          let txts =
            Dns.Rr_map.Txt_set.fold (fun elt acc -> elt :: acc) txts [] in
          let txts =
            List.map (String.concat "" % String.split_on_char ' ') txts in
          let txts = String.concat "" txts in
          match Dkim.domain_key_of_string txts with
          | Ok dk -> `Domain_key dk (* TODO(dinosaure): expire. *)
          | Error (`Msg msg) -> `DNS_error msg) in
    (dn, response) in
  List.map fn dns

let rec pp ppf = function
  | Arc.Verify.Nil m -> Fmt.pf ppf "%a" Emile.pp_mailbox m
  | Valid { set; next; _ } ->
      let domain_name = Arc.domain set in
      let uid = Arc.uid set in
      Fmt.pf ppf "%a -✓-> [%02d]%a" pp next uid Domain_name.pp domain_name
  | Broken (set, next) ->
      let domain_name = Arc.domain set in
      let uid = Arc.uid set in
      Fmt.pf ppf "%a -⨯-> [%02d]%a" pp next uid Domain_name.pp domain_name

let rec collect ?prev setters = function
  | Arc.Verify.Nil _ -> setters
  | Valid { fields = `Intact; body = `Intact; set; next } ->
      collect ~prev:set setters next
  | Valid { fields = `Changed; body = `Intact; set; next } ->
      let prev = Option.get prev in
      let domain_name = Arc.domain prev in
      let uid = Arc.uid prev in
      collect ~prev:set (`Fields (uid, domain_name) :: setters) next
  | Valid { fields = `Intact; body = `Changed; set; next } ->
      let prev = Option.get prev in
      let domain_name = Arc.domain prev in
      let uid = Arc.uid prev in
      collect ~prev:set (`Body (uid, domain_name) :: setters) next
  | Valid { fields = `Changed; body = `Changed; set; next } ->
      let prev = Option.get prev in
      let domain_name = Arc.domain prev in
      let uid = Arc.uid prev in
      collect ~prev:set
        (`Fields (uid, domain_name) :: `Body (uid, domain_name) :: setters)
        next
  | Broken (set, next) -> collect ~prev:set setters next

let show_setter = function
  | `Fields (uid, domain_name) ->
      Fmt.pr "[%02d]%a has changed fields\n%!" uid Domain_name.pp domain_name
  | `Body (uid, domain_name) ->
      Fmt.pr "[%02d]%a has modified the content\n%!" uid Domain_name.pp
        domain_name

let () =
  let buf = Bytes.create 0x7ff in
  let dns = Dns_client_unix.create () in
  let ( let* ) = Result.bind in
  let rec go decoder =
    match Arc.Verify.decode decoder with
    | `Await decoder ->
        let len = input stdin buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        (*
        let str = String.split_on_char '\n' str in
        let str = String.concat "\r\n" str in
        *)
        let decoder = Arc.Verify.src decoder str 0 (String.length str) in
        go decoder
    | `Queries (decoder, set) ->
        let* queries = Arc.Verify.queries set in
        let responses = dns_queries dns queries in
        let* decoder = Arc.Verify.response decoder responses in
        go decoder
    | `Chain chain -> Ok chain
    | `Malformed err -> Error (`Msg err) in
  go (Arc.Verify.decoder ()) |> function
  | Ok chain ->
      Fmt.pr "%a\n%!" pp chain ;
      let setters = collect [] chain in
      List.iter show_setter setters
  | Error (`Msg msg) -> failwith msg
