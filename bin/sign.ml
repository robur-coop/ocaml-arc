let ( % ) f g = fun x -> f (g x)
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

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

(* let () = Logs.set_level ~all:true (Some Logs.Debug) *)
let () = Logs_threaded.enable ()

module Bqueue = struct
  type 'a t = {
      buffer : 'a option array
    ; mutable rd_pos : int
    ; mutable wr_pos : int
    ; lock : Miou.Mutex.t
    ; non_empty : Miou.Condition.t
    ; non_full : Miou.Condition.t
    ; mutable closed : bool
  }

  let create size =
    let lock = Miou.Mutex.create () in
    let non_empty = Miou.Condition.create () in
    let non_full = Miou.Condition.create () in
    {
      buffer = Array.make size None
    ; lock
    ; rd_pos = 0
    ; wr_pos = 0
    ; non_empty
    ; non_full
    ; closed = false
    }

  let put t data =
    Miou.Mutex.protect t.lock @@ fun () ->
    if t.closed then invalid_arg "Bounded_stream.put closed stream" ;
    while (t.wr_pos + 1) mod Array.length t.buffer = t.rd_pos do
      Miou.Condition.wait t.non_full t.lock
    done ;
    t.buffer.(t.wr_pos) <- Some data ;
    t.wr_pos <- (t.wr_pos + 1) mod Array.length t.buffer ;
    Miou.Condition.signal t.non_empty

  let get t =
    Miou.Mutex.protect t.lock @@ fun () ->
    while t.wr_pos = t.rd_pos && not t.closed do
      Miou.Condition.wait t.non_empty t.lock
    done ;
    if t.closed && t.wr_pos = t.rd_pos
    then None
    else
      let data = t.buffer.(t.rd_pos) in
      t.buffer.(t.rd_pos) <- None ;
      t.rd_pos <- (t.rd_pos + 1) mod Array.length t.buffer ;
      Miou.Condition.signal t.non_full ;
      data

  let close t =
    Miou.Mutex.protect t.lock @@ fun () ->
    t.closed <- true ;
    Miou.Condition.signal t.non_empty

  let rec iter fn t =
    match get t with
    | None -> ()
    | Some v ->
        let prm = Miou.async @@ fun () -> fn v in
        Miou.await_exn prm ; iter fn t

  let of_list vs =
    let size = List.length vs + 1 in
    let stream = create size in
    List.iter (put stream) vs ;
    close stream ;
    stream
end

let sign seal msgsig keys newline receiver queue results chain =
  let signer = Arc.Sign.signer ~seal ~msgsig ~receiver ~results keys chain in
  let rec go t =
    match Arc.Sign.sign t with
    | `Await t -> (
        match Queue.pop queue with
        | str when newline = `CRLF ->
            go (Arc.Sign.fill t str 0 (String.length str))
        | str ->
            let str = String.split_on_char '\n' str in
            let str = String.concat "\r\n" str in
            go (Arc.Sign.fill t str 0 (String.length str))
        | exception Queue.Empty -> go (Arc.Sign.fill t String.empty 0 0))
    | `Malformed err -> Fmt.failwith "%s." err
    | `Set set ->
        let new_line = match newline with `CRLF -> "\r\n" | `LF -> "\n" in
        let str = Prettym.to_string ~new_line Arc.Encoder.stamp set in
        output_string stdout str in
  go signer

let dns_queries t dns =
  let fn dn =
    let result = Dns_client_miou_unix.get_resource_record t Dns.Rr_map.Txt dn in
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

let chain dns newline stream =
  let ( let* ) = Result.bind in
  let rec go decoder =
    match Arc.Verify.decode decoder with
    | `Await decoder -> (
        match Bqueue.get stream with
        | None -> go (Arc.Verify.src decoder String.empty 0 0)
        | Some str when newline = `CRLF ->
            go (Arc.Verify.src decoder str 0 (String.length str))
        | Some str ->
            let str = String.split_on_char '\n' str in
            let str = String.concat "\r\n" str in
            go (Arc.Verify.src decoder str 0 (String.length str)))
    | `Queries (decoder, set) ->
        let* queries = Arc.Verify.queries set in
        let responses = dns_queries dns queries in
        let* decoder = Arc.Verify.response decoder responses in
        go decoder
    | `Chain chain -> Ok chain
    | `Malformed err -> Error (`Msg err) in
  go (Arc.Verify.decoder ())

let verify dns newline stream =
  let decoder = Dmarc.Verify.decoder () in
  let rec go decoder =
    match Dmarc.Verify.decode decoder with
    | #Dmarc.Verify.error as err ->
        Logs.err (fun m -> m "Error from DMARC: %a" Dmarc.Verify.pp_error err) ;
        Error err
    | `Await decoder -> (
        match Bqueue.get stream with
        | None -> go (Dmarc.Verify.src decoder String.empty 0 0)
        | Some str when newline = `CRLF ->
            go (Dmarc.Verify.src decoder str 0 (String.length str))
        | Some str ->
            let str = String.split_on_char '\n' str in
            let str = String.concat "\r\n" str in
            go (Dmarc.Verify.src decoder str 0 (String.length str)))
    | `Info value -> Ok value
    | `Query (decoder, domain_name, Dns.Rr_map.K record) ->
        let response =
          Dns_client_miou_unix.get_resource_record dns record domain_name in
        let decoder = Dmarc.Verify.response decoder record response in
        go decoder in
  go decoder

let run _quiet seal msgsig keys newline receiver input =
  Miou_unix.run @@ fun () ->
  let daemon, he = Happy_eyeballs_miou_unix.create () in
  let rng = Mirage_crypto_rng_miou_unix.(initialize (module Pfortuna)) in
  let finally () =
    Happy_eyeballs_miou_unix.kill daemon ;
    Mirage_crypto_rng_miou_unix.kill rng in
  Fun.protect ~finally @@ fun () ->
  let dns = Dns_client_miou_unix.create he in
  let ic, ic_close =
    if input = "-" then (stdin, ignore) else (open_in input, close_in) in
  let finally () = ic_close ic in
  Fun.protect ~finally @@ fun () ->
  let stream0 = Bqueue.create 0x10 in
  let stream1 = Bqueue.create 0x10 in
  let msg = Queue.create () in
  let producer =
    Miou.async @@ fun () ->
    let buf = Bytes.create 0x7ff in
    let rec go () =
      let len = Stdlib.input ic buf 0 (Bytes.length buf) in
      Logs.debug (fun m -> m "Got %d byte(s)" len) ;
      if len > 0
      then (
        let str = Bytes.sub_string buf 0 len in
        Logs.debug (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str) ;
        Bqueue.put stream0 str ;
        Bqueue.put stream1 str ;
        Queue.push str msg ;
        go ())
      else (Bqueue.close stream0 ; Bqueue.close stream1) in
    go () in
  Miou.await_exn producer ;
  let prm0 = Miou.async @@ fun () -> verify dns newline stream0 in
  let prm1 = Miou.async @@ fun () -> chain dns newline stream1 in
  let results = Miou.await_exn prm0 and chain = Miou.await_exn prm1 in
  match (results, chain) with
  | Ok results, Ok chain ->
      sign seal msgsig keys newline receiver msg results chain
  | Error err, _ -> Fmt.failwith "%a." Dmarc.Verify.pp_error err
  | _, Error (`Msg msg) -> Fmt.failwith "%s." msg

let priv_of_seed ?(bits = 4096) (alg : Dkim.algorithm) seed : Dkim.key =
  match X509.Private_key.generate ~seed ~bits (alg :> X509.Key_type.t) with
  | #Dkim.key as key -> key
  | _ -> assert false

let setup_keys bits seal_alg seed seal_key msgsig_key =
  match (seed, seal_key, msgsig_key) with
  | None, Some key, msgsig_key -> `Ok (key, msgsig_key)
  | Some seed, None, msgsig_key ->
      `Ok (priv_of_seed ?bits seal_alg seed, msgsig_key)
  | _, Some key, msgsig_key -> `Ok (key, msgsig_key)
  | None, None, _ ->
      `Error (true, "A private key or a seed is required to sign an email")

open Cmdliner

let private_key : Dkim.key Arg.conv =
  let parser str =
    let ( let* ) = Result.bind in
    let key =
      let* key = Base64.decode ~pad:true str in
      match X509.Private_key.decode_der key with
      | Ok #Dkim.key as key -> key
      | Ok _ -> error_msgf "Invalid algorithm used for DKIM signature"
      | Error _ as err -> err in
    match (key, Fpath.of_string str) with
    | (Ok _ as v), _ -> v
    | Error _, Ok filename
      when Sys.file_exists str && not (Sys.is_directory str) -> (
        let ic = open_in (Fpath.to_string filename) in
        let len = in_channel_length ic in
        let buf = Bytes.create len in
        really_input ic buf 0 len ;
        close_in ic ;
        let str = Bytes.unsafe_to_string buf in
        match X509.Private_key.decode_pem str with
        | Ok #Dkim.key as key -> key
        | Ok _ -> error_msgf "Invalid algorithm used for DKIM signature"
        | Error _ as err -> err)
    | (Error _ as err), _ -> err in
  let pp ppf (pk : Dkim.key) =
    Fmt.string ppf (X509.Private_key.encode_der (pk :> X509.Private_key.t))
  in
  Arg.conv (parser, pp)

let hash =
  let parser str =
    match String.trim (String.lowercase_ascii str) with
    | "sha1" -> Ok `SHA1
    | "sha256" -> Ok `SHA256
    | _ -> error_msgf "Invalid hash: %S" str in
  let pp ppf = function
    | `SHA1 -> Fmt.string ppf "sha1"
    | `SHA256 -> Fmt.string ppf "sha256" in
  Arg.conv (parser, pp)

let algorithm =
  let parser str =
    match String.trim (String.lowercase_ascii str) with
    | "rsa" -> Ok `RSA
    | "ed25519" -> Ok `ED25519
    | _ -> error_msgf "Invalid algorithm: %S" str in
  let pp ppf = function
    | `RSA -> Fmt.string ppf "rsa"
    | `ED25519 -> Fmt.string ppf "ed25519" in
  Arg.conv (parser, pp)

let pot x = x land (x - 1) == 0 && x != 0

let bits =
  let parser str =
    try
      let v = int_of_string str in
      if pot v then Ok v else error_msgf "The given value is not a power of two"
    with _ -> error_msgf "Invalid number" in
  Arg.conv (parser, Fmt.int)

let seed =
  let parser str = Base64.decode ~pad:true str in
  let pp ppf seed = Fmt.string ppf (Base64.encode_exn ~pad:true seed) in
  Arg.conv (parser, pp)

let bits =
  let doc = "Size of key in bits." in
  Arg.(value & opt (some bits) None & info [ "b"; "bits" ] ~doc ~docv:"NUMBER")

let seal_algorithm =
  let doc = "The algorithm use to encrypt/decrypt ARC-Set." in
  let open Arg in
  value & opt algorithm `RSA & info [ "a"; "algorithm" ] ~doc ~docv:"ALGORITHM"

let msgsig_algorithm =
  let doc = "The algorithm use to encrypt/decrypt fields." in
  let open Arg in
  value
  & opt algorithm `RSA
  & info [ "signature-algorithm" ] ~doc ~docv:"ALGORITHM"

let seed =
  let doc =
    "The seed (encoded in base64) used to generate an RSA key (with the \
     Fortuna random number generator)." in
  Arg.(value & opt (some seed) None & info [ "seed" ] ~doc ~docv:"SEED")

let seal_key =
  let doc = "The key used to generate the $(i,Seal) signature." in
  let open Arg in
  value & opt (some private_key) None & info [ "seal" ] ~doc ~docv:"PRIVATE-KEY"

let msgsig_key =
  let doc = "The key used to generate the $(i,Message-Signature) signature." in
  let open Arg in
  value
  & opt (some private_key) None
  & info [ "signature" ] ~doc ~docv:"PRIVATE-KEY"

let setup_keys =
  let open Term in
  const setup_keys $ bits $ seal_algorithm $ seed $ seal_key $ msgsig_key |> ret

let domain_name = Arg.conv (Domain_name.of_string, Domain_name.pp)

let canon =
  let parser str =
    let v = String.trim str in
    let v = String.lowercase_ascii v in
    match String.split_on_char '/' v with
    | [ "simple"; "simple" ] | [] | [ "simple" ] -> Ok (`Simple, `Simple)
    | [ "simple"; "relaxed" ] -> Ok (`Simple, `Relaxed)
    | [ "relaxed"; "simple" ] -> Ok (`Relaxed, `Simple)
    | [ "relaxed"; "relaxed" ] | [ "relaxed" ] -> Ok (`Relaxed, `Relaxed)
    | _ -> error_msgf "Invalid canonicalization specification: %S" str in
  let pp ppf = function
    | `Simple, `Simple -> Fmt.string ppf "simple"
    | `Relaxed, `Relaxed -> Fmt.string ppf "relaxed"
    | `Simple, `Relaxed -> Fmt.string ppf "simple/relaxed"
    | `Relaxed, `Simple -> Fmt.string ppf "relaxed/simple" in
  Arg.conv (parser, pp)

let field_name = Arg.conv (Mrmime.Field_name.of_string, Mrmime.Field_name.pp)

let msgsig_selector =
  let doc =
    "ARC-Message-Signature selector. A domain (see $(b,domain)) can store \
     several public-key. Each of them are identified by a $(i,selector) such \
     as the public-key is stored into $(i,selector)._domainkey.$(i,domain). It \
     can refer to a date, a location or an user. This selector is specific for \
     the ARC-Message-Signature field. The user must specify another selector \
     for the ARC-Seal field." in
  let open Arg in
  required & opt (some domain_name) None & info [ "signature-selector" ] ~doc

let canon =
  let doc =
    "Canonicalization algorithm used to digest ARC-Set's fields and body. \
     Default value is $(i,relaxed/relaxed). A $(i,simple) canonicalization can \
     be used. The format of the argument is: $(i,canon)/$(i,canon) or \
     $(i,canon) to use the same canonicalization for both header's fields and \
     body." in
  Arg.(value & opt (some canon) None & info [ "c" ] ~doc)

let default_hostname =
  let str = Unix.gethostname () in
  match Domain_name.of_string str with
  | Ok domain_name -> domain_name
  | Error (`Msg msg) -> Fmt.failwith "%s." msg

let hostname =
  let doc =
    "The domain where the DNS TXT record is available (which contains the \
     public-key). This also the domain-name used as the receiver of the given \
     email." in
  Arg.(value & opt domain_name default_hostname & info [ "h"; "hostname" ] ~doc)

let fields =
  let doc = "Fields which will be used to generate the DKIM signature." in
  let open Arg in
  value
  & opt_all field_name [ Mrmime.Field_name.from ]
  & info [ "f"; "field" ] ~doc

let setup_msgsig selector fields algorithm hash (default, key) canon domain_name
    =
  let key = Option.value ~default key in
  match (algorithm, key) with
  | `RSA, `RSA _ | `ED25519, `ED25519 _ ->
      let dkim =
        Dkim.v ~selector ~fields ~algorithm ?hash ?canonicalization:canon
          domain_name in
      `Ok dkim
  | _ ->
      let msg =
        "The algorithm used by the key is different from the one specified for \
         ARC-Message-Signature." in
      `Error (true, msg)

let msgsig_hash =
  let doc =
    "Hash algorithm to digest header's fields and body. User can digest with \
     SHA1 or SHA256 algorithm." in
  Arg.(value & opt (some hash) None & info [ "signature-hash" ] ~doc)

let setup_msgsig =
  let open Term in
  const setup_msgsig
  $ msgsig_selector
  $ fields
  $ msgsig_algorithm
  $ msgsig_hash
  $ setup_keys
  $ canon
  $ hostname
  |> ret

let seal_selector =
  let doc =
    "ARC-Seal selector. A domain (see $(b,domain)) can store several \
     public-key. Each of them are identified by a $(i,selector) such as the \
     public-key is stored into $(i,selector)._domainkey.$(i,domain). It can \
     refer to a date, a location or an user. This selector is specific for the \
     ARC-Seal field. The user must specify another selector for the \
     ARC-Message-Signature field." in
  let open Arg in
  required & opt (some domain_name) None & info [ "seal-selector" ] ~doc

let setup_seal selector algorithm hash (key, _) domain_name =
  match (algorithm, key) with
  | `RSA, `RSA _ | `ED25519, `ED25519 _ ->
      let seal = Arc.Sign.seal ~algorithm ?hash ~selector domain_name in
      `Ok seal
  | _ ->
      let msg =
        "The algorithm used by the key is different from the one specified for \
         ARC-Message-Signature." in
      `Error (true, msg)

let seal_hash =
  let doc =
    "Hash algorithm to digest ARC-Sets. User can digest with SHA1 or SHA256 \
     algorithm." in
  Arg.(value & opt (some hash) None & info [ "seal-hash" ] ~doc)

let setup_seal =
  let open Term in
  const setup_seal
  $ seal_selector
  $ seal_algorithm
  $ seal_hash
  $ setup_keys
  $ hostname
  |> ret

let newline =
  let parser str =
    match String.lowercase_ascii str with
    | "crlf" -> Ok `CRLF
    | "lf" -> Ok `LF
    | _ -> error_msgf "Invalid newline" in
  let pp ppf = function
    | `CRLF -> Fmt.string ppf "crlf"
    | `LF -> Fmt.string ppf "lf" in
  let newline = Arg.conv (parser, pp) in
  let doc = "The newline used by emails." in
  let open Arg in
  value & opt newline `LF & info [ "newline" ] ~doc ~docv:"NEWLINE"

let to_domain domain_name =
  let segs = Domain_name.to_strings domain_name in
  `Domain segs

let input =
  let doc = "The email to sign. Use $(b,-) for $(b,stdin)." in
  let open Arg in
  value & pos 0 file "-" & info [] ~doc ~docv:"FILE"

let sign =
  let open Term in
  const run
  $ const ()
  $ setup_seal
  $ setup_msgsig
  $ setup_keys
  $ newline
  $ map to_domain hostname
  $ input

let cmd = Cmd.v (Cmd.info "sign") sign
let () = exit (Cmd.eval cmd)
