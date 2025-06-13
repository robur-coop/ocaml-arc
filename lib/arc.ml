let src = Logs.Src.create "arc"

module Log = (val Logs.src_log src : Logs.LOG)

[@@@warning "-30"]

(* An ARC set *)
type t = { results : results; msgsig : signature; seal : seal; uid : int }

and signature = {
    field_name : Mrmime.Field_name.t
  ; unstrctrd : Unstrctrd.t
  ; signature : Dkim.signed Dkim.t
}

and seal = {
    field_name : Mrmime.Field_name.t
  ; unstrctrd : Unstrctrd.t
  ; seal : Dkim.signed Dkim.t
  ; map : Dkim.map
}

and results = {
    field_name : Mrmime.Field_name.t
  ; unstrctrd : Unstrctrd.t
  ; results : Dmarc.Authentication_results.t
}

and domain_key = Dkim.domain_key

let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let domain { seal; _ } = Dkim.domain seal.seal
let uid { uid; _ } = uid

let p =
  let open Mrmime in
  let unstructured = Field.(Witness Unstructured) in
  let open Field_name in
  Map.empty
  |> Map.add date unstructured
  |> Map.add from unstructured
  |> Map.add sender unstructured
  |> Map.add reply_to unstructured
  |> Map.add (v "To") unstructured
  |> Map.add cc unstructured
  |> Map.add bcc unstructured
  |> Map.add subject unstructured
  |> Map.add message_id unstructured
  |> Map.add comments unstructured
  |> Map.add content_type unstructured
  |> Map.add content_encoding unstructured

module Field_name = Mrmime.Field_name

let get_authentication_results field_name unstrctrd :
    (int * results, [> `Msg of string ]) result =
  let open Angstrom in
  let p = Dmarc.Authentication_results.Decoder.authres_payload in
  let is_white = function ' ' | '\t' -> true | _ -> false in
  let is_digit = function '0' .. '9' -> true | _ -> false in
  let ignore_spaces = skip_while is_white in
  let p =
    ignore_spaces
    *> string "i"
    *> ignore_spaces
    *> char '='
    *> ignore_spaces
    *> take_while1 is_digit
    >>= fun uid ->
    ignore_spaces *> char ';' >>= fun _ ->
    p >>= fun v -> return (int_of_string uid, v) in
  let ( let* ) = Result.bind in
  let v = Unstrctrd.fold_fws unstrctrd in
  let* v = Unstrctrd.without_comments v in
  let str = Unstrctrd.to_utf_8_string v in
  Log.debug (fun m -> m "ARC-Authentication-Results: %s" str) ;
  match Angstrom.parse_string ~consume:All p str with
  | Ok (uid, results) -> Ok (uid, { field_name; unstrctrd; results })
  | Error msg ->
      Log.err (fun m -> m "Invalid ARC-Authentication-Results: %s" msg) ;
      error_msgf "Invalid ARC-Authentication-Results value"

let field_arc_message_signature = Field_name.v "ARC-Message-Signature"
let field_arc_seal = Field_name.v "ARC-Seal"
let field_arc_authentication_results = Field_name.v "ARC-Authentication-Results"
let is_arc_message_signature = Field_name.equal field_arc_message_signature
let is_arc_seal = Field_name.equal field_arc_seal
let is_from = Field_name.equal Mrmime.Field_name.from

let is_arc_authentication_results =
  Field_name.equal field_arc_authentication_results

let to_unstrctrd unstructured =
  let fold acc = function #Unstrctrd.elt as elt -> elt :: acc | _ -> acc in
  let unstrctrd = List.fold_left fold [] unstructured in
  Result.get_ok (Unstrctrd.of_list (List.rev unstrctrd))

let get_unstrctrd_exn : type a. a Mrmime.Field.t -> a -> Unstrctrd.t =
 fun w v ->
  match w with
  | Mrmime.Field.Unstructured -> to_unstrctrd v
  | _ ->
      invalid_arg
        "get_unstrctrd_exn: the given value is not an Unstructured value"
(* should never appear *)

let get_signature :
       Unstrctrd.t
    -> (int * Dkim.signed Dkim.t * Dkim.map, [> `Msg of string ]) result =
 fun unstrctrd ->
  let ( let* ) = Result.bind in
  let* m = Dkim.of_unstrctrd_to_map unstrctrd in
  let* i =
    Option.to_result ~none:(msgf "Missing i field") (Dkim.get_key "i" m) in
  let* t = Dkim.map_to_t m in
  try
    let i = int_of_string i in
    Ok (i, t, m)
  with _exn -> error_msgf "Invalid Agent or User Identifier"

module Verify = struct
  type decoder = {
      input : bytes
    ; input_pos : int
    ; input_len : int
    ; state : state
    ; mutable sender : Emile.mailbox option
  }

  and decode =
    [ `Await of decoder
    | `Queries of decoder * t
    | `Chain of chain
    | `Malformed of string ]

  and state =
    | Extraction of Mrmime.Hd.decoder * arc_field list * field list
    | Queries of string * field list * t list * set_and_dk list
    | Body of Dkim.Body.decoder * [ `CRLF | `Spaces of string ] list * ctx list

  and arc_field =
    | Msgsig of int * signature
    | Results of int * results
    | Seal of int * seal

  and field = Mrmime.Field_name.t * Unstrctrd.t

  and ctx =
    | Ctx : {
          bh : string
        ; b : (Dkim.signed, 'k) Dkim.Digest.value
        ; set_and_dk : set_and_dk
        ; cv : [ `None | `Fail | `Pass ]
      }
        -> ctx

  and response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  and set_and_dk = {
      results : results
    ; msgsig : signature * Dkim.domain_key
    ; seal : seal * Dkim.domain_key
    ; uid : int
  }

  and chain =
    | Nil : Emile.mailbox -> chain
    | Valid : {
          fields : [ `Intact | `Changed ]
        ; body : [ `Intact | `Changed ]
        ; set : t
        ; next : chain
      }
        -> chain
    | Broken : t * chain -> chain

  let rec length = function
    | Nil _ -> 0
    | Valid { next; _ } | Broken (_, next) -> 1 + length next

  let rec is_valid_chain = function
    | Nil _ -> true
    | Valid { next; _ } -> is_valid_chain next && true
    | Broken _ -> false

  let compare_arc_field a b =
    match (a, b) with
    | ( (Results (a, _) | Msgsig (a, _) | Seal (a, _))
      , (Results (b, _) | Msgsig (b, _) | Seal (b, _)) )
      when a <> b ->
        Int.compare a b
    | Results _, Results _ -> 0
    | Results _, _ -> -1
    | Msgsig _, Msgsig _ -> 0
    | Msgsig _, Seal _ -> -1
    | Seal _, Seal _ -> 0
    | _, _ -> 1

  let decoder () =
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Extraction (dec, [], []) in
    { input; input_pos; input_len; state; sender = None }

  let end_of_input decoder =
    { decoder with input = Bytes.empty; input_pos = 0; input_len = min_int }

  let src decoder src idx len =
    if idx < 0 || len < 0 || idx + len > String.length src
    then Fmt.invalid_arg "Arc.Verify.src: source out of bounds" ;
    let input = Bytes.unsafe_of_string src in
    let input_pos = idx in
    let input_len = idx + len - 1 in
    let decoder = { decoder with input; input_pos; input_len } in
    match decoder.state with
    | Extraction (v, _, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Queries _ -> assert false
    | Body (v, _, _) ->
        Dkim.Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let hashp : type a. a Digestif.hash -> Digestif.hash' -> bool =
   fun a b ->
    let a = Digestif.hash_to_hash' a in
    a = b

  let with_set ~canon ~feed_string ctx (cur : t) =
    let field_name = cur.results.field_name in
    let unstrctrd = cur.results.unstrctrd in
    let ctx = canon field_name unstrctrd feed_string ctx in
    let field_name = cur.msgsig.field_name in
    let unstrctrd = cur.msgsig.unstrctrd in
    let ctx = canon field_name unstrctrd feed_string ctx in
    let field_name = cur.seal.field_name in
    let unstrctrd = cur.seal.unstrctrd in
    canon field_name unstrctrd feed_string ctx

  let verify sender ctxs =
    let fn (Ctx { set_and_dk; _ }) = set_and_dk in
    let sets = List.map fn ctxs in
    let max = List.length sets in
    let fn chain (Ctx { bh; b = (dkim, _) as value; set_and_dk = set; cv }) =
      let (Hash_algorithm a) = Dkim.hash_algorithm (fst set.seal).seal in
      let module Hash = (val Digestif.module_of a) in
      let feed_string ctx str = Hash.feed_string ctx str in
      let canon0 = Dkim.Canon.of_fields (fst set.seal).seal in
      let canon1 = Dkim.Canon.of_dkim_fields (fst set.seal).seal in
      let ctx =
        match cv with
        | `None | `Fail ->
            Log.debug (fun m ->
                m "calculate the seal signature from nothing for [%02d]" set.uid) ;
            Hash.empty
        | `Pass ->
            let older = List.filter (fun set' -> set'.uid < set.uid) sets in
            let older =
              let fn ({ results; msgsig; seal; uid } : set_and_dk) : t =
                { results; msgsig = fst msgsig; seal = fst seal; uid } in
              List.map fn older in
            let fn = with_set ~canon:canon0 ~feed_string in
            List.fold_left fn Hash.empty older in
      let field_name = set.results.field_name in
      let unstrctrd = set.results.unstrctrd in
      let ctx = canon0 field_name unstrctrd feed_string ctx in
      let field_name = (fst set.msgsig).field_name in
      let unstrctrd = (fst set.msgsig).unstrctrd in
      let ctx = canon0 field_name unstrctrd feed_string ctx in
      let field_name = (fst set.seal).field_name in
      let unstrctrd = (fst set.seal).unstrctrd in
      let ctx = canon1 field_name unstrctrd feed_string ctx in
      let hash = Hash.get ctx in
      let msg = Hash.to_raw_string hash in
      let hashp = hashp a in
      let signature, _ =
        (Dkim.signature_and_hash (fst set.seal).seal
          :> string * Dkim.hash_value) in
      let pk = Dkim.public_key (snd set.seal) in
      let alg = Dkim.algorithm (fst set.seal).seal in
      let seal_ok =
        match (X509.Public_key.decode_der pk, alg) with
        | Ok (`RSA key), `RSA ->
            Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature
              (`Digest msg)
        | Ok (`ED25519 key), `ED25519 ->
            Mirage_crypto_ec.Ed25519.verify ~key signature ~msg
        | _ -> false in
      let b, bh_ok =
        Dkim.Digest.verify ~fields:bh ~domain_key:(snd set.msgsig) value in
      let _, Dkim.Hash_value (k, b') =
        (Dkim.signature_and_hash dkim :> string * Dkim.hash_value) in
      let b' = Digestif.to_raw_string k b' in
      let b_ok = Eqaf.equal b b' in
      Log.debug (fun m -> m "[%02d] seal is ok? %b" set.uid seal_ok) ;
      Log.debug (fun m -> m "[%02d] bh is ok? %b" set.uid bh_ok) ;
      Log.debug (fun m -> m "[%02d] b is ok? %b" set.uid b_ok) ;
      let set : t =
        {
          results = set.results
        ; msgsig = fst set.msgsig
        ; seal = fst set.seal
        ; uid = set.uid
        } in
      match cv with
      | (`Pass | `None) when seal_ok ->
          let fields = if bh_ok then `Intact else `Changed in
          let body = if b_ok then `Intact else `Changed in
          let last = Int.equal set.uid max in
          if last && b_ok && bh_ok
          then Valid { fields; body; set; next = chain }
          else if not last
          then Valid { fields; body; set; next = chain }
          else Broken (set, chain)
      | _ -> Broken (set, chain) in
    List.fold_left fn (Nil sender) ctxs

  (* extract ARC sets *)
  let rec extract t decoder arc_fields fields =
    let open Mrmime in
    let rec go arc_fields fields =
      match Hd.decode decoder with
      | `Field field ->
          let (Field.Field (fn, w, v)) = Location.prj field in
          if is_arc_message_signature fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_signature unstrctrd with
            | Ok (uid, signature, _) ->
                let field_name = fn in
                let msgsig = { field_name; unstrctrd; signature } in
                go (Msgsig (uid, msgsig) :: arc_fields) fields
            | Error (`Msg msg) ->
                Log.warn (fun m ->
                    m "Ignoring a malformed ARC-Message-Signature: %s" msg) ;
                go arc_fields fields)
          else if is_arc_seal fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_signature unstrctrd with
            | Ok (uid, seal, map) ->
                (* NOTE(dinosaure): the default canonicalization of DKIM is
                   [`Simple] but [`Relaxed] must be used for ARC. *)
                let seal =
                  Dkim.with_canonicalization seal (`Relaxed, `Relaxed) in
                let seal = { field_name = fn; unstrctrd; seal; map } in
                go (Seal (uid, seal) :: arc_fields) fields
            | Error (`Msg msg) ->
                Log.warn (fun m -> m "Ignoring a malformed ARC-Seal: %s" msg) ;
                go arc_fields fields)
          else if is_arc_authentication_results fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_authentication_results fn unstrctrd with
            | Ok (uid, t) ->
                go (Results (uid, t) :: arc_fields) ((fn, unstrctrd) :: fields)
            | Error (`Msg _) ->
                Log.warn (fun m ->
                    m "Ignoring a malformed ARC-Authentication-Results") ;
                go arc_fields fields)
          else if is_from fn
          then
            let unstrctrd = get_unstrctrd_exn w v in
            let str = Unstrctrd.to_utf_8_string unstrctrd in
            match Emile.of_string str with
            | Ok mailbox ->
                t.sender <- Some mailbox ;
                let field = (fn, unstrctrd) in
                go arc_fields (field :: fields)
            | Error _ -> `Malformed "Invalid From: value"
          else
            let unstrctrd = get_unstrctrd_exn w v in
            let field = (fn, unstrctrd) in
            go arc_fields (field :: fields)
      | `Malformed _ as err -> err
      | `End prelude ->
          let arc_fields = List.sort compare_arc_field arc_fields in
          let rec aggregate sets = function
            | [] -> sets
            | Results (u0, results)
              :: Msgsig (u1, msgsig)
              :: Seal (u2, seal)
              :: rest ->
                if u0 = u1 && u1 = u2
                then
                  let set = ({ uid = u0; results; msgsig; seal } : t) in
                  aggregate (set :: sets) rest
                else aggregate sets rest
            | _ :: rest -> aggregate sets rest in
          let rem = src_rem t in
          let sets = aggregate [] arc_fields in
          let state = Queries (prelude, fields, sets, []) in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          decode t
      | `Await ->
          let state = Extraction (decoder, arc_fields, fields) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t in
    go arc_fields fields

  and queries t prelude others todo sets =
    match todo with
    | [] ->
        let prelude = Bytes.unsafe_of_string prelude in
        let fn set_and_dk =
          let msgsig, dk = set_and_dk.msgsig in
          let v = (msgsig.field_name, msgsig.unstrctrd, msgsig.signature, dk) in
          let bh, Dkim.Digest.Value b = Dkim.Digest.digest_fields others v in
          let seal, _ = set_and_dk.seal in
          let cv =
            match
              Option.map String.lowercase_ascii (Dkim.get_key "cv" seal.map)
            with
            | Some "none" | None -> `None
            | Some "fail" -> `Fail
            | Some "pass" -> `Pass
            | Some _ -> failwith "Invalid cv value"
            (* TODO *) in
          Ctx { bh; b; set_and_dk; cv } in
        (* digest_sets sets ; *)
        let ctxs = List.map fn sets in
        let decoder = Dkim.Body.decoder () in
        if Bytes.length prelude > 0
        then Dkim.Body.src decoder prelude 0 (Bytes.length prelude) ;
        let state = Body (decoder, [], ctxs) in
        decode { t with state }
    | set :: _todo -> `Queries (t, set)

  and digest t decoder stack ctxs =
    let rec go stack results =
      match Dkim.Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) results
      | `Data x ->
          let fn (Ctx { bh; b; set_and_dk; cv }) =
            Ctx
              {
                bh
              ; b = Dkim.Digest.digest_wsp (List.rev stack) b
              ; set_and_dk
              ; cv
              } in
          let results = List.map fn results in
          let fn (Ctx { bh; b; set_and_dk; cv }) =
            Ctx { bh; b = Dkim.Digest.digest_str x b; set_and_dk; cv } in
          let results = List.map fn results in
          go [] results
      | `Await ->
          let state = Body (decoder, stack, results) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End -> (
          let fn (Ctx { bh; b; set_and_dk; cv }) =
            Ctx { bh; b = Dkim.Digest.digest_wsp [ `CRLF ] b; set_and_dk; cv }
          in
          let results = List.map fn results in
          match t.sender with
          | None -> `Malformed "From: field not found"
          | Some sender -> `Chain (verify sender results)) in
    go stack ctxs

  and decode t =
    match t.state with
    | Extraction (decoder, arc_fields, fields) ->
        extract t decoder arc_fields fields
    | Queries (prelude, others, todo, sets) ->
        queries t prelude others todo sets
    | Body (decoder, stack, ctxs) -> digest t decoder stack ctxs

  let queries (set : t) =
    let seal = Dkim.Verify.domain_key set.seal.seal
    and msgsig = Dkim.Verify.domain_key set.msgsig.signature in
    match (seal, msgsig) with
    | Ok seal, Ok msgsig ->
        if Domain_name.equal seal msgsig
        then Ok [ seal ]
        else Ok [ seal; msgsig ]
    | (Error _ as err), _ | _, (Error _ as err) -> err

  let response decoder responses =
    match decoder.state with
    | Queries (prelude, others, set :: todo, sets) -> (
        let seal = Result.get_ok (Dkim.Verify.domain_key set.seal.seal) in
        let msgsig =
          Result.get_ok (Dkim.Verify.domain_key set.msgsig.signature) in
        if Domain_name.equal seal msgsig
        then
          match responses with
          | [ (dn, `Domain_key dk) ] when Domain_name.equal dn seal ->
              let set_and_dk =
                {
                  results = set.results
                ; msgsig = (set.msgsig, dk)
                ; seal = (set.seal, dk)
                ; uid = set.uid
                } in
              let state = Queries (prelude, others, todo, set_and_dk :: sets) in
              Ok { decoder with state }
          | [ (dn, _) ] when Domain_name.equal dn seal ->
              let state = Queries (prelude, others, todo, sets) in
              Ok { decoder with state }
          | _ ->
              error_msgf
                "Missing or invalid domain-key from the current ARC-set"
        else
          let seal = List.assoc_opt seal responses in
          let msgsig = List.assoc_opt msgsig responses in
          match (seal, msgsig) with
          | Some (`Domain_key sdk), Some (`Domain_key msdk) ->
              let set_and_dk =
                {
                  results = set.results
                ; msgsig = (set.msgsig, msdk)
                ; seal = (set.seal, sdk)
                ; uid = set.uid
                } in
              let state = Queries (prelude, others, todo, set_and_dk :: sets) in
              Ok { decoder with state }
          | Some _, Some _ ->
              let state = Queries (prelude, others, todo, sets) in
              Ok { decoder with state }
          | _ -> error_msgf "Missing domain-key from the current ARC-set")
    | Queries (_, _, [], _) ->
        error_msgf "Invalid decoder state: no current ARC-set"
    | _ -> error_msgf "Invalid decoder state"
end

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

let assoc field_name fields =
  let res = ref None in
  List.iter
    (fun ((field_name', _) as v) ->
      if Mrmime.Field_name.equal field_name field_name' && Option.is_none !res
      then res := Some v)
    fields ;
  !res

let remove_assoc field_name fields =
  let fold (res, deleted) ((field_name', _) as v) =
    if Mrmime.Field_name.equal field_name field_name' && not deleted
    then (res, true)
    else (v :: res, deleted) in
  let res, _ = List.fold_left fold ([], false) fields in
  List.rev res

module Encoder0 = struct
  open Prettym
  open Dkim.Encoder

  let option_with_fws fmt ppf = function
    | None -> ppf
    | Some v -> eval ppf [ !!fmt; fws ] v

  let int ppf v = string ppf (string_of_int v)

  let cv ppf = function
    | `Pass -> string ppf "cv=pass;"
    | `Fail -> string ppf "cv=fail;"

  let seal_signature ppf (seal : (int * string * [ `Pass | `Fail ]) Dkim.t) =
    let uid, b, result = Dkim.signature_and_hash seal in
    let a = (Dkim.algorithm seal, Dkim.hash_algorithm seal) in
    let d = Dkim.domain seal in
    let s = Dkim.selector seal in
    eval ppf
      [
        string $ "i="; !!int; char $ ';'; fws; !!algorithm; fws; !!domain; fws
      ; !!selector; fws; !!(option_with_fws timestamp)
      ; !!(option_with_fws expiration); !!(option_with_fws length); !!cv; fws
      ; !!signature; fws
      ]
      uid a d s None None None result b (* TODO(dinosaure): [t], [q] and [e]. *)

  let seal_as_field ppf seal =
    eval ppf
      [
        string $ "ARC-Seal"; char $ ':'; tbox 1; spaces 1; !!seal_signature
      ; close; new_line
      ]
      seal

  let msgsig_as_field ppf (uid, dkim) =
    eval ppf
      [
        string $ "ARC-Message-Signature"; char $ ':'; tbox 1; spaces 1
      ; string $ "i="; !!int; char $ ';'; fws; !!dkim_signature; close; new_line
      ]
      uid dkim

  let results_as_field ppf (receiver, uid, results) =
    eval ppf
      [
        string $ "ARC-Authentication-Results"; char $ ':'; tbox 1; spaces 1
      ; string $ "i="; !!int; char $ ';'; fws; !!(Dmarc.Encoder.value ~receiver)
      ; close; new_line
      ]
      uid results
end

module Sign = struct
  type authentication_results =
    [ `User's_result of user's_results | `Mail's_result of Unstrctrd.t ]

  and user's_results = Dmarc.Verify.info * Dmarc.DKIM.t list * [ `Fail | `Pass ]

  type signer = {
      input : bytes
    ; input_pos : int
    ; input_len : int
    ; state : state
    ; seal : key * Dkim.unsigned Dkim.t
    ; msgsig : key * Dkim.unsigned Dkim.t
    ; mutable results : [ authentication_results | `Unspecified ]
    ; chain : Verify.chain
    ; receiver : Emile.domain
  }

  and state =
    | Fields of Mrmime.Hd.decoder * fields
    | Sign : {
          decoder : Dkim.Body.decoder
        ; fields : (Dkim.unsigned, 'k) Dkim.Digest.value
        ; stack : [ `CRLF | `Spaces of string ] list
        ; body : (Dkim.unsigned, 'k) Dkim.Digest.value
      }
        -> state

  and fields = (Mrmime.Field_name.t * Unstrctrd.t) list

  and action =
    [ `Await of signer
    | `Malformed of string
    | `Missing_authentication_results
    | `Set of set ]

  and set = {
      seal : (string * [ `Pass | `Fail ]) Dkim.t
    ; msgsig : (string * Dkim.hash_value) Dkim.t
    ; results : authentication_results
    ; uid : int
    ; receiver : Emile.domain
  }

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  let end_of_input decoder =
    { decoder with input = Bytes.empty; input_pos = 0; input_len = min_int }

  let fill decoder src idx len =
    if idx < 0 || len < 0 || idx + len > String.length src
    then invalid_arg "Arc.Sign.fill: source out of bounds" ;
    let input = Bytes.unsafe_of_string src in
    let input_pos = idx in
    let input_len = idx + len - 1 in
    let decoder = { decoder with input; input_pos; input_len } in
    match decoder.state with
    | Fields (v, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder
    | Sign { decoder = v; _ } ->
        Dkim.Body.src v input idx len ;
        if len == 0 then end_of_input decoder else decoder

  let field_and_value =
    let open Angstrom in
    let open Mrmime in
    let buf = Bytes.create 0x7f in
    let is_wsp = function ' ' | '\t' -> true | _ -> false in
    Field_name.Decoder.field_name >>= fun field_name ->
    skip_while is_wsp *> char ':' *> Unstrctrd_parser.unstrctrd buf
    >>| fun value -> (field_name, value)

  let raw encoder value =
    let str = Prettym.to_string ~new_line:"\r\n" encoder value in
    let v = Angstrom.parse_string ~consume:All field_and_value str in
    Result.get_ok v

  let bbh_of_msgsig : type k0 k1.
         signer
      -> fields:(Dkim.unsigned, k0) Dkim.Digest.value
      -> body:(Dkim.unsigned, k1) Dkim.Digest.value
      -> string * Dkim.hash_value =
   fun t ~fields ~body ->
    let _, Dkim.Digest.Digest { m = (module Hash); ctx } = body in
    let (Hash_algorithm k) = Dkim.hash_algorithm (snd t.msgsig) in
    let bh =
      Dkim.Hash_value
        (k, Digestif.of_raw_string k Hash.(to_raw_string (get ctx))) in
    let uid = Verify.length t.chain + 1 in
    let fake = Dkim.with_signature_and_hash (snd t.msgsig) ("", bh) in
    let fake =
      Prettym.to_string ~new_line:"\r\n" Encoder0.msgsig_as_field (uid, fake)
    in
    let unstrctrd = Angstrom.parse_string ~consume:All field_and_value fake in
    let _, unstrctrd = Result.get_ok unstrctrd in
    Log.debug (fun m ->
        m "sign %a field with:" Mrmime.Field_name.pp field_arc_message_signature) ;
    Log.debug (fun m -> m "%s" (Unstrctrd.to_utf_8_string unstrctrd)) ;
    let _, Dkim.Digest.Digest { m = (module Hash); ctx } = fields in
    let feed_string ctx str = Hash.feed_string ctx str in
    let canon = Dkim.Canon.of_dkim_fields in
    let dkim = snd t.msgsig in
    let ctx = canon dkim field_arc_message_signature unstrctrd feed_string ctx in
    let b =
      match fst t.msgsig with
      | `RSA key ->
          let hash = Digestif.hash_to_hash' k in
          let msg = Hash.(to_raw_string (get ctx)) in
          let msg = `Digest msg in
          Mirage_crypto_pk.Rsa.PKCS1.sign ~hash ~key msg
      | `ED25519 key ->
          let msg = Hash.(to_raw_string (get ctx)) in
          Mirage_crypto_ec.Ed25519.sign ~key msg in
    (b, bh)

  let valid_sets t =
    let rec go acc = function
      | Verify.Nil _ -> acc
      | Verify.Valid { set; next; _ } -> go (set :: acc) next
      | Verify.Broken _ -> List.rev acc in
    go [] t.chain

  let bh_of_seal t (bbh : string * Dkim.hash_value) results =
    let uid = Verify.length t.chain + 1 in
    let chains = valid_sets t in
    let cv = if Verify.is_valid_chain t.chain then `Pass else `Fail in
    let (Hash_algorithm a) = Dkim.hash_algorithm (snd t.seal) in
    let module Hash = (val Digestif.module_of a) in
    let feed_string ctx str = Hash.feed_string ctx str in
    let canon0 = Dkim.Canon.of_fields (snd t.seal) in
    let canon1 = Dkim.Canon.of_dkim_fields (snd t.seal) in
    let ctx =
      List.fold_left
        (Verify.with_set ~canon:canon0 ~feed_string)
        Hash.empty chains in
    let field_name, unstrctrd =
      match results with
      | `User's_result results ->
          raw Encoder0.results_as_field (t.receiver, uid, results)
      | `Mail's_result unstrctrd -> (field_arc_authentication_results, unstrctrd)
    in
    let ctx = canon0 field_name unstrctrd feed_string ctx in
    let msgsig = Dkim.with_signature_and_hash (snd t.msgsig) bbh in
    let field_name, unstrctrd = raw Encoder0.msgsig_as_field (uid, msgsig) in
    let ctx = canon0 field_name unstrctrd feed_string ctx in
    let seal = Dkim.with_signature_and_hash (snd t.seal) (uid, "", cv) in
    let field_name, unstrctrd = raw Encoder0.seal_as_field seal in
    let ctx = canon1 field_name unstrctrd feed_string ctx in
    match fst t.seal with
    | `RSA key ->
        let hash = Digestif.hash_to_hash' a in
        let msg = `Digest Hash.(to_raw_string (get ctx)) in
        (Mirage_crypto_pk.Rsa.PKCS1.sign ~hash ~key msg, cv)
    | `ED25519 key ->
        let msg = Hash.(to_raw_string (get ctx)) in
        (Mirage_crypto_ec.Ed25519.sign ~key msg, cv)

  let rec fields t decoder fields =
    let open Mrmime in
    let rec go fields =
      match Hd.decode decoder with
      | `Await ->
          let state = Fields (decoder, fields) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t
      | `Field field ->
          let (Field.Field (field_name, w, v)) = Location.prj field in
          let fn, unstrctrd =
            match w with
            | Field.Unstructured -> (field_name, to_unstrctrd v)
            | _ -> assert false in
          let results =
            match (t.results, is_arc_authentication_results field_name) with
            | (`User's_result _ | `Mail's_result _), _ -> t.results
            | `Unspecified, false -> `Unspecified
            | `Unspecified, true -> (
                let uid = Verify.length t.chain + 1 in
                match get_authentication_results fn unstrctrd with
                | Ok (uid', _) when uid = uid' ->
                    Log.debug (fun m ->
                        m "Get an ARC-Authentication-Results with uid:%d" uid') ;
                    `Mail's_result unstrctrd
                | _ -> `Unspecified) in
          t.results <- results ;
          go ((fn, unstrctrd) :: fields)
      | `Malformed _ as err -> err
      | `End prelude ->
          let (Hash_algorithm k) = Dkim.hash_algorithm (snd t.msgsig) in
          let module Hash = (val Digestif.module_of k) in
          let feed_string ctx str = Hash.feed_string ctx str in
          let canon = Dkim.Canon.of_fields (snd t.msgsig) in
          let fn (ctx, fields) reqs =
            Log.debug (fun m -> m "sign %a field" Mrmime.Field_name.pp reqs) ;
            match assoc reqs fields with
            | Some (field_name, unstrctrd) ->
                let ctx = canon field_name unstrctrd feed_string ctx in
                (ctx, remove_assoc field_name fields)
            | None -> (ctx, fields) in
          let ctx, _ =
            List.fold_left fn
              (Hash.empty, List.rev fields)
              (Dkim.fields (snd t.msgsig)) in
          let fields = Dkim.Digest.Digest { m = (module Hash); ctx } in
          let fields = (snd t.msgsig, fields) in
          let body =
            Dkim.Digest.Digest { m = (module Hash); ctx = Hash.empty } in
          let body = (snd t.msgsig, body) in
          let decoder = Dkim.Body.decoder () in
          let prelude = Bytes.unsafe_of_string prelude in
          if Bytes.length prelude > 0
          then Dkim.Body.src decoder prelude 0 (Bytes.length prelude) ;
          let state = Sign { decoder; fields; stack = []; body } in
          sign { t with state } in
    go fields

  and digest : type k.
         signer
      -> Dkim.Body.decoder
      -> (Dkim.unsigned, k) Dkim.Digest.value
      -> [ `Spaces of string | `CRLF ] list
      -> (Dkim.unsigned, k) Dkim.Digest.value
      -> action =
   fun t decoder fields stack body ->
    let rec go stack body =
      match Dkim.Body.decode decoder with
      | (`Spaces _ | `CRLF) as x -> go (x :: stack) body
      | `Data x ->
          let body = Dkim.Digest.digest_wsp (List.rev stack) body in
          let body = Dkim.Digest.digest_str x body in
          go [] body
      | `Await ->
          let state = Sign { decoder; fields; stack; body } in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          `Await { t with state; input_pos }
      | `End ->
      match t.results with
      | #authentication_results as results ->
          let body = Dkim.Digest.digest_wsp [ `CRLF ] body in
          let bbh = bbh_of_msgsig t ~fields ~body in
          let bh_and_cv = bh_of_seal t bbh results in
          let seal = Dkim.with_signature_and_hash (snd t.seal) bh_and_cv in
          let msgsig = Dkim.with_signature_and_hash (snd t.msgsig) bbh in
          let uid = Verify.length t.chain + 1 in
          let receiver = t.receiver in
          let set = { seal; msgsig; results; uid; receiver } in
          `Set set
      | `Unspecified -> `Missing_authentication_results in
    go stack body

  and sign t =
    match t.state with
    | Fields (decoder, fs) -> fields t decoder fs
    | Sign { decoder; fields; stack; body } ->
        digest t decoder fields stack body

  type seal = Dkim.unsigned Dkim.t

  let seal ?(algorithm = `RSA) ?(hash = `SHA256) ?timestamp ?expiration
      ~selector domain =
    Dkim.v ~canonicalization:(`Relaxed, `Relaxed) ~algorithm ~hash
      ~fields:[ Mrmime.Field_name.from ] ?timestamp ?expiration ~selector domain

  let signer ~seal ~msgsig ~receiver ?results key chain =
    let key_seal, key_msgsig =
      match key with
      | key_seal, None ->
          (* TODO(dinosaure): verify that the selector and the domain of [msgsig]
             is the same as [seal]. *)
          (key_seal, key_seal)
      | key_seal, Some key_msgsig -> (key_seal, key_msgsig) in
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Fields (dec, []) in
    let seal = (key_seal, seal) in
    let msgsig = (key_msgsig, msgsig) in
    let results =
      match results with
      | None -> `Unspecified
      | Some results -> `User's_result results in
    {
      input
    ; input_pos
    ; input_len
    ; seal
    ; msgsig
    ; state
    ; receiver
    ; results
    ; chain
    }
end

module Encoder = struct
  open Prettym

  let stamp ppf { Sign.seal; msgsig; results; uid; receiver } =
    let bh, cv = Dkim.signature_and_hash seal in
    let seal = Dkim.with_signature_and_hash seal (uid, bh, cv) in
    match results with
    | `User's_result results ->
        eval ppf
          [
            !!Encoder0.seal_as_field; !!Encoder0.msgsig_as_field
          ; !!Encoder0.results_as_field
          ]
          seal (uid, msgsig) (receiver, uid, results)
    | `Mail's_result _ ->
        eval ppf
          [ !!Encoder0.seal_as_field; !!Encoder0.msgsig_as_field ]
          seal (uid, msgsig)

  let stamp_results ~receiver ~uid ppf results =
    eval ppf [ !!Encoder0.results_as_field ] (receiver, uid, results)
end
