let dns_queries t dns =
  let fn dn = (dn, `Domain_key (Hashtbl.find t dn)) in
  List.map fn dns

let parse dns filename =
  let ic = open_in filename in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
  let buf = Bytes.create 0x7ff in
  let rec go decoder =
    match Arc.Verify.decode decoder with
    | `Await decoder ->
        let len = input ic buf 0 (Bytes.length buf) in
        let str = Bytes.sub_string buf 0 len in
        let decoder = Arc.Verify.src decoder str 0 (String.length str) in
        go decoder
    | `Queries (decoder, set) ->
        let queries = Arc.Verify.queries set in
        let queries = Result.get_ok queries in
        let responses = dns_queries dns queries in
        let decoder = Arc.Verify.response decoder responses in
        let decoder = Result.get_ok decoder in
        go decoder
    | `Chain chain -> chain
    | `Malformed err -> failwith err in
  go (Arc.Verify.decoder ())

let domain = Alcotest.testable Domain_name.pp Domain_name.equal

let rec test chain expect =
  match (chain, expect) with
  | Arc.Verify.Nil _, _ :: _ -> Alcotest.failf "Empty chain"
  | Arc.Verify.Nil _, [] -> Alcotest.(check pass) "chain" () ()
  | _, [] -> Alcotest.failf "Longer chain"
  | Valid { set; next; _ }, `Valid dn :: expect ->
      let dn' = Arc.domain set in
      let uid = Arc.uid set in
      Alcotest.(check domain) (Fmt.str "%02d" uid) dn dn' ;
      test next expect
  | Broken (set, next), `Broken dn :: expect ->
      let dn' = Arc.domain set in
      let uid = Arc.uid set in
      Alcotest.(check domain) (Fmt.str "%02d" uid) dn dn' ;
      test next expect
  | Valid _, `Broken _ :: _ -> Alcotest.failf "Expect a broken set"
  | Broken _, `Valid _ :: _ -> Alcotest.failf "Expect a valid set"

let make dns filename expect =
  Alcotest.test_case filename `Quick @@ fun () ->
  let chain = parse dns filename in
  test chain expect

[@@@ocamlformat "disable"]

let _microsoft_com = Domain_name.of_string_exn "microsoft.com"
let _subspace_kernel_org = Domain_name.of_string_exn "subspace.kernel.org"
let _google_com = Domain_name.of_string_exn "google.com"
let _zohomail_com = Domain_name.of_string_exn "zohomail.com"
let _webhostingserver_nl = Domain_name.of_string_exn "webhostingserver.nl"
let _arc_2024_01_16__domain_key_subspace_kernel_org = Domain_name.of_string_exn "arc-20240116._domainkey.subspace.kernel.org"
let _arcselector10001__domain_key_microsoft_com = Domain_name.of_string_exn "arcselector10001._domainkey.microsoft.com"
let _arc_20160816__domainkey_google_com = Domain_name.of_string_exn "arc-20160816._domainkey.google.com"
let _zohoarc__domainkey_zohomail_com = Domain_name.of_string_exn "zohoarc._domainkey.zohomail.com"
let _whs1__domain_key_webhostingserver_nl = Domain_name.of_string_exn "whs1._domainkey.webhostingserver.nl"

let tests =
  [ "raw/001.mail",
    [ `Broken _subspace_kernel_org; `Valid _microsoft_com; `Valid _microsoft_com ]
  ; "raw/002.mail",
    [ `Broken _subspace_kernel_org; `Valid _microsoft_com; `Valid _microsoft_com ]
  ; "raw/003.mail",
    [ `Broken _subspace_kernel_org; `Valid _microsoft_com ]
  ; "raw/004.mail",
    [ `Valid _google_com ]
  ; "raw/005.mail",
    [ `Broken _subspace_kernel_org; `Valid _microsoft_com ]
  ; "raw/006.mail",
    [ `Broken _subspace_kernel_org; `Valid _microsoft_com; `Valid _microsoft_com ]
  ; "raw/007.mail",
    [ `Valid _subspace_kernel_org; `Valid _zohomail_com ]
  ; "raw/008.mail",
    [ `Valid _subspace_kernel_org; `Valid _webhostingserver_nl; `Valid _webhostingserver_nl ]
  ]

let dns =
  let t = Hashtbl.create 0x100 in
  let str = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8bBweNGbY7NPgfcmEcH//5Hg/lfNJwol10xQOOZsnvNR6pRDmop8Lph/A5Jy32VDw+c7uKS+x++090jnp6Upd7WiPzqelBKr/tNc1reJQJ6zkPtn6Z67F0iRUcKE+2q8q4JiB3qjJBQLpxNOyCJww1HS4kW4V6yNQHa4vETwGfwIDAQAB" in
  let v = Dkim.domain_key_of_string str in
  let v = Result.get_ok v in
  Hashtbl.add t _arc_2024_01_16__domain_key_subspace_kernel_org v;
  let str = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzXBaxYIoWlL1E1RK3QPh2KHH+Mi5XsdFAW7Wz6HDJVXhFTlYqL939p1S9e/VfG3cu210r+O2YR2n1Q3Zp9rTUBCVI8qEfpDaCANKwGTjQdKcJsGw9QlIS/j+lK6qzF00qVQLVkrqWFewBy4TU6IDj3WtySBJL6AMg1FfOMooK55J8/GoglNJNoCDyL47q+57nNmAQ26o7AyPLSm0aAzzebkEGvialcdrT48sfZcAo1+fkTYRb5+iTWf0EHSmR0ZeMd0zn5leBSPW2lfi+3JBcAwoc7+dqdI6lPhnpvdymw1GdN0RHcU4NBPoGRl2KTnlQaYW78ZDP+0l5ov/RqrAaQIDAQAB" in
  let v = Dkim.domain_key_of_string str in
  let v = Result.get_ok v in
  Hashtbl.add t _arcselector10001__domain_key_microsoft_com v;
  let str = "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Lztpxs7yUxQEsbDFhjMc9kZVZu5P/COYEUIX4B39IL4SXAbv4viIlT9E6F6iZmTh1go7+9WQLywwgwjXMJx/Dz0RgMoPeyp5NRy4l320DPYibNqVMWa5iQ2WiImQC0en1O9uhLLvzaSZJ03fvGmCo9jMo0GwKzLNe14xMgn/px2L5N/3IKlKX4bqUAJTUt8L993ZlWzvgMnSFSt8B+euSKSrtAiopdy4r1yO4eN5goBASrGW0eLQc1lYouNvCrcTQpos4/GEAqiGzpqueJLmBfOO4clNvVvpPkvQs2BHw9I9LmIjaMxTNGxkGBRaP3utDiKXXqu1K+LRzl0HCNSdQIDAQAB" in
  let v = Dkim.domain_key_of_string str in
  let v = Result.get_ok v in
  Hashtbl.add t  _arc_20160816__domainkey_google_com v;
  let str = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgwY/tRY07mmV309YXkmJSyyeb3/oTobaAn5T7CTTAbLFRH8c1zAS+vu4bkNnqGUPN6eOIzqOqukrQXYg8PYpYdFVSJX7e/uT92+kNdWX0euH2/dI3RB7LguwdILnLnq6qnP0h1xxQ38Hz1SQ815pGYlZiDoECY3wKwgioJNQ17QIDAQAB" in
  let v = Dkim.domain_key_of_string str in
  let v = Result.get_ok v in
  Hashtbl.add t _zohoarc__domainkey_zohomail_com v;
  let str = "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzx9rOCWB+Wpls0eQwsqKqUHNO7vZAyWNfEQy/OxPlapkORuJSlcbT/2iyLdDwzmcsWPaxEVo++uR/hZISjRakOfteC96ruicbcaZPxFOHg4MTu6SXR88XWh0qPnI7FtGObEWIhj1xkpgfATY80uLw8LpyOOEe5Vb/gxuPW124DwV8JImEAJcxT2cLdRzTqeZN4fun9Su31eX21SbrX6bNYWehQ64kwzXfH1Zfe1aywGmwOBIs01PygMROj+14ta/P+oPtFnuwewAEm88zYBLazO9jYrL47xAjyNhZnjtULVBctpKw8AFsIJ7VMDACY270s+ZMmJIbd2v8v6gPJ3/KwIDAQAB" in
  let v = Dkim.domain_key_of_string str in
  let v = Result.get_ok v in
  Hashtbl.add t _whs1__domain_key_webhostingserver_nl v;
  t
[@@@ocamlformat "enable"]

let tests = List.map (fun (filename, expect) -> make dns filename expect) tests
let () = Alcotest.run "arc" [ ("verify", tests) ]
