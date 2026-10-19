## v0.0.4 (2026-10-19)

- Upgrade to `dmarc.0.0.3` (@dinosaure, 0fede01, 7d423c1)
- Fix how we decode ED25519 keys (@dinosaure, [!7][7])

[7]: https://git.robur.coop/robur/ocaml-arc/pulls/7

## v0.0.3 (2026-08-07)

- Use `mirage-crypto-rng.unix` instead of `mirage-crypto-rng-miou-unix`
  (@hannesm, [!6][6])

[6]: https://git.robur.coop/robur/ocaml-arc/pulls/6

## v0.0.2 (2026-04-30)

- Be able to use an unverified chain when we sign an email (@dinosaure, [!3][3])
- Don't print v=1 on our ARC-Message-Signature (@dinosaure, c568290)

[3]: https://git.robur.coop/robur/ocaml-arc/pulls/3

## v0.0.1 (2025-11-27)

- First release of `ocaml-arc`
