type t
type domain_key = Dkim.domain_key

module Verify : sig
  type decoder

  type decode =
    [ `Await of decoder
    | `Queries of decoder * t
    | `Sets of t list
    | `Malformed of string ]

  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]
  type query

  val decoder : unit -> decoder
  val decode : decoder -> decode

  val response :
       decoder
    -> ([ `raw ] Domain_name.t * response) list
    -> (decoder, [> `Msg of string ]) result

  val queries : t -> ([ `raw ] Domain_name.t list, [> `Msg of string ]) result
  val src : decoder -> string -> int -> int -> decoder
end
