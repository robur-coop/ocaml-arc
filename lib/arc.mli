type t
type domain_key = Dkim.domain_key

val domain : t -> [ `raw ] Domain_name.t
val uid : t -> int

module Verify : sig
  type decoder

  type chain = private
    | Nil : chain
    | Valid : {
          fields : [ `Intact | `Changed ]
        ; body : [ `Intact | `Changed ]
        ; set : t
        ; next : chain
      }
        -> chain
    | Broken : t * chain -> chain

  type decode =
    [ `Await of decoder
    | `Queries of decoder * t
    | `Chain of chain
    | `Malformed of string ]

  type response = [ `Expired | `Domain_key of domain_key | `DNS_error of string ]

  val decoder : unit -> decoder
  val decode : decoder -> decode

  val response :
       decoder
    -> ([ `raw ] Domain_name.t * response) list
    -> (decoder, [> `Msg of string ]) result

  val queries : t -> ([ `raw ] Domain_name.t list, [> `Msg of string ]) result
  val src : decoder -> string -> int -> int -> decoder
end
