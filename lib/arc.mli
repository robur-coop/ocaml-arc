type t
type domain_key

module Verify : sig
  type decoder

  type decode =
    [ `Await of decoder | `Query of t | `Sets of t list | `Malformed of string ]

  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]
  type query

  val decoder : unit -> decoder
  val decode : decoder -> decode
  val response : decoder -> t -> response list -> decoder
  val queries : t -> query list
  val src : decoder -> string -> int -> int -> decoder
end
