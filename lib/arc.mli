type t
type domain_key = Dkim.domain_key

val domain : t -> [ `raw ] Domain_name.t
val uid : t -> int

module Verify : sig
  type decoder

  type chain = private
    | Nil : Emile.mailbox -> chain
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

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

module Sign : sig
  type signer
  type set
  type seal
  type action = [ `Await of signer | `Malformed of string | `Set of set ]
  type user's_results = Dmarc.Verify.info * Dmarc.DKIM.t list * [ `Fail | `Pass ]

  val sign : signer -> action
  val fill : signer -> string -> int -> int -> signer

  val seal :
       ?algorithm:Dkim.algorithm
    -> ?hash:Dkim.hash
    -> ?timestamp:int64
    -> ?expiration:int64
    -> selector:[ `raw ] Domain_name.t
    -> [ `raw ] Domain_name.t
    -> seal

  val signer :
       seal:seal
    -> msgsig:Dkim.unsigned Dkim.t
    -> receiver:Emile.domain
    -> ?results:user's_results
    -> key * key option
    -> Verify.chain
    -> signer
end

module Encoder : sig
  val stamp : Sign.set Prettym.t

  val stamp_results :
    receiver:Emile.domain -> uid:int -> Sign.user's_results Prettym.t
end
