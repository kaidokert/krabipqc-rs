# krabipqc-rs

[![Rust](https://github.com/kaidokert/krabipqc-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabipqc-rs/actions/workflows/rust.yml)
[![Cortex-M](https://github.com/kaidokert/krabipqc-rs/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/krabipqc-rs/actions/workflows/cortex_m.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabipqc-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabipqc-rs?branch=main)

Prototype `no_std` ML-DSA and ML-KEM for microcontrollers.

## Scope

- ML-DSA: `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87` — keygen / sign / verify.
- ML-KEM: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024` — keygen / encaps / decaps.
- no unsafe, no heap, no `alloc`

## Footprint

Measured under QEMU from the last CI run. `.text` is the linked example binary
size; stack is the peak high-water mark. Larger parameter sets scale up
proportionally.

| Operation                    | Cortex-M3 .text | Cortex-M3 stack | RISC-V .text | RISC-V stack |
|------------------------------|----------------:|----------------:|-------------:|-------------:|
| ML-DSA-44 verify             |        14.5 KiB |       23 868 B  |    17.2 KiB  |    23 736 B  |
| ML-DSA-44 sign (`lowmem`)    |        16.5 KiB |       67 956 B  |    20.3 KiB  |    67 940 B  |
| ML-KEM-512 decaps            |        17.8 KiB |       28 156 B  |    21.7 KiB  |    28 116 B  |

Default sign peak is ~80 KiB stack; `lowmem` re-derives NTT vectors per retry
to bring it down to ~68 KiB at the cost of extra cycles on rejection.

## Status

Very experimental. APIs will change; side-channel properties are not analyzed; not audited. Do not use for anything that matters.

## License

Apache-2.0; see [`LICENSE`](LICENSE).
