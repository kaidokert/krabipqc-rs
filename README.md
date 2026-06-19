# krabipqc-rs

[![Rust](https://github.com/kaidokert/krabipqc-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabipqc-rs/actions/workflows/rust.yml)
[![Cortex-M](https://github.com/kaidokert/krabipqc-rs/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/krabipqc-rs/actions/workflows/cortex_m.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabipqc-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabipqc-rs?branch=main)

Prototype `no_std` ML-DSA and ML-KEM for microcontrollers.

## Scope

- ML-DSA: `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87` — keygen / sign / verify.
- ML-KEM: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024` — keygen / encaps / decaps.
- no unsafe, no heap, no `alloc`

## Status

Very experimental. APIs will change; side-channel properties are not analyzed; not audited. Do not use for anything that matters.

## License

Apache-2.0; see [`LICENSE`](LICENSE).
