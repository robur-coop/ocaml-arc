let src = Logs.Src.create "arc"

module Log = (val Logs.src_log src : Logs.LOG)

(* An ARC set *)
type t = {
    results : results
  ; message_signature : signature
  ; seal : seal
  ; uid : int
}

and signature = Dkim.signed Dkim.t
and seal = Dkim.signed Dkim.t
and results = Dmarc.Authentication_results.t

let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

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

let get_authentication_results unstrctrd :
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
    ignore_spaces *> char ';' *> p >>= fun v -> return (int_of_string uid, v)
  in
  let ( let* ) = Result.bind in
  let v = Unstrctrd.fold_fws unstrctrd in
  let* v = Unstrctrd.without_comments v in
  let str = Unstrctrd.to_utf_8_string v in
  match Angstrom.parse_string ~consume:All p str with
  | Ok _ as results -> results
  | Error _ -> error_msgf "Invalid ARC-Authentication-Results value"

let field_arc_message_signature = Field_name.v "ARC-Message-Signature"
let field_arc_seal = Field_name.v "ARC-Seal"
let field_arc_authentication_results = Field_name.v "ARC-Authentication-Results"
let is_arc_message_signature = Field_name.equal field_arc_message_signature
let is_arc_seal = Field_name.equal field_arc_seal

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
    Unstrctrd.t -> (int * Dkim.signed Dkim.t, [> `Msg of string ]) result =
 fun unstrctrd ->
  let ( let* ) = Result.bind in
  let* m = Dkim.of_unstrctrd_to_map unstrctrd in
  let* i =
    Option.to_result ~none:(msgf "Missing i field") (Dkim.get_key "i" m) in
  let* t = Dkim.map_to_t m in
  try
    let i = int_of_string i in
    Ok (i, t)
  with _exn -> error_msgf "Invalid Agent or User Identifier"

module Verify = struct
  type decoder = {
      input : bytes
    ; input_pos : int
    ; input_len : int
    ; state : state
  }

  and decode = [ `Await of decoder | `Sets of t list | `Malformed of string ]
  and state =
    | Extraction of Mrmime.Hd.decoder * field list
    | Queries of string * t list * t list

  and field =
    | Message_signature of int * Dkim.signed Dkim.t
    | Authentication_results of int * Dmarc.Authentication_results.t
    | Seal of int * Dkim.signed Dkim.t

  let pp_field ppf = function
    | Message_signature _ -> Fmt.string ppf "Message-Signature"
    | Authentication_results _ -> Fmt.string ppf "Authentication-Results"
    | Seal _ -> Fmt.string ppf "Seal"

  let compare_field a b =
    match (a, b) with
    | ( (Authentication_results (a, _) | Message_signature (a, _) | Seal (a, _))
      , (Authentication_results (b, _) | Message_signature (b, _) | Seal (b, _))
      )
      when a <> b ->
        Int.compare a b
    | Authentication_results _, Authentication_results _ -> 0
    | Authentication_results _, _ -> -1
    | Message_signature _, Message_signature _ -> 0
    | Message_signature _, Seal _ -> -1
    | Seal _, Seal _ -> 0
    | _, _ -> 1

  let decoder () =
    let input, input_pos, input_len = (Bytes.empty, 1, 0) in
    let dec = Mrmime.Hd.decoder p in
    let state = Extraction (dec, []) in
    { input; input_pos; input_len; state }

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
    | Extraction (v, _) ->
        Mrmime.Hd.src v src idx len ;
        if len == 0 then end_of_input decoder else decoder

  let src_rem decoder = decoder.input_len - decoder.input_pos + 1

  (* extract ARC sets *)
  let rec extract t decoder fields =
    let open Mrmime in
    let rec go fields =
      match Hd.decode decoder with
      | `Field field ->
          let (Field.Field (fn, w, v)) = Location.prj field in
          if is_arc_message_signature fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_signature unstrctrd with
            | Ok (uid, dkim) -> go (Message_signature (uid, dkim) :: fields)
            | Error (`Msg msg) ->
                Log.warn (fun m ->
                    m "Ignoring a malformed ARC-Message-Signature: %s" msg) ;
                go fields)
          else if is_arc_seal fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_signature unstrctrd with
            | Ok (uid, dkim) -> go (Seal (uid, dkim) :: fields)
            | Error (`Msg msg) ->
                Log.warn (fun m -> m "Ignoring a malformed ARC-Seal: %s" msg) ;
                go fields)
          else if is_arc_authentication_results fn
          then (
            let unstrctrd = get_unstrctrd_exn w v in
            match get_authentication_results unstrctrd with
            | Ok (uid, t) -> go (Authentication_results (uid, t) :: fields)
            | Error (`Msg _) ->
                Log.warn (fun m ->
                    m "Ignoring a malformed ARC-Authentication-Results") ;
                go fields)
          else go fields
      | `Malformed _ as err -> err
      | `End prelude ->
          let fields : field list = fields in
          let fields = List.sort compare_field fields in
          Fmt.epr ">>> @[<hov>%a@]\n%!" Fmt.(Dump.list pp_field) fields;
          let rec aggregate sets = function
            | [] -> sets
            | Authentication_results (u0, results)
              :: Message_signature (u1, message_signature)
              :: Seal (u2, seal)
              :: rest ->
                if u0 = u1 && u1 = u2
                then
                  let set = { uid = u0; results; message_signature; seal } in
                  aggregate (set :: sets) rest
                else aggregate sets rest
            | _ :: rest -> aggregate sets rest in
          let rem = src_rem t in
          let todo = aggregate [] fields in
          let state = Queries (prelude, todo, []) in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          decode t
      | `Await ->
          let state = Extraction (decoder, fields) in
          let rem = src_rem t in
          let input_pos = t.input_pos + rem in
          let t = { t with state; input_pos } in
          `Await t in
    go fields

  and queries todo sets = match todo with
    | [] -> assert false
    | set :: todo -> `Query set

  and decode t =
    match t.state with
    | Extraction (decoder, fields) -> extract t decoder fields
end
