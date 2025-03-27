type t
type signature
type domain_key

module Verify : sig
  type decoder
  type decode = [ `Await of decoder | `Query of signature | Sets of t list | `Malformed of string ]
  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  val decoder : unit -> decoder
  val decode : decoder -> decode
  val response : decoder -> signature -> response -> decoder
  val src : decoder -> string -> int -> int -> decoder
end
