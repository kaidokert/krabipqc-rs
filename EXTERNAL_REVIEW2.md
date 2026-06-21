# External Review 2 — Core Crate

This review focuses on the core `krabipqc` crate and intentionally excludes auxiliary Cortex-M / RISC-V footprint harnesses except where test execution necessarily touches the crate as a package.

## Scope and process

Reviewed areas:

- Public crate surface in `krabipqc/src/lib.rs`.
- ML-DSA per-parameter facades in `krabipqc/src/ml_dsa.rs`.
- ML-KEM per-parameter facades in `krabipqc/src/ml_kem.rs`.
- Core ML-DSA signing / verification internals in `krabipqc/src/internal.rs`.
- RustCrypto compatibility layer in `krabipqc/src/rustcrypto.rs`.
- Supporting encoding and sampling code where it affects API correctness, timing, or compactness.

Commands run during review:

- `cargo test`
- `cargo clippy --all-targets -- -D warnings`

## Executive summary

No obvious functional correctness blocker was found in the focused core-crate review. The crate has a compact and mostly idiomatic embedded-Rust shape: `no_std`, no unsafe code, const-sized public facades, fallible APIs where malformed input can matter, sealed parameter marker traits for RustCrypto compatibility, and KAT/unit coverage across all advertised parameter sets.

The main review findings are not immediate correctness bugs. They are risk/maintenance points:

- ML-DSA signing has the expected variable-latency rejection-loop shape, and the source explicitly says the constant-time story is partial.
- Some RustCrypto trait methods are forced through structurally unreachable `.expect` arms because those trait signatures cannot return the lower-level `EncodeError`.
- There are leftover TODO comments in the RustCrypto layer around exactly those `.expect` paths and possible future typestate / const-generic cleanup.
- The raw byte-array facades are compact, but they necessarily encode fewer invariants in the type system than the RustCrypto wrapper types.
- HashML-DSA only exposes SHA-256 and SHA-512 pre-hash selectors even though FIPS 204 permits additional pre-hash functions.

## Correctness

### No obvious functional correctness blocker found

The core crate's unit tests and KAT suites pass, including ML-DSA keygen tests, ML-KEM keygen / encaps / decaps KATs, and internal NTT / encoding / sampling tests.

This is not a proof of correctness, but it is a strong baseline: the code is not merely compiling; the exposed parameter-set behavior is exercised against known-answer material and internal algebra/encoding round trips.

### Public facades are appropriately const-sized

The ML-KEM wrappers expose fixed-size byte-array APIs for each parameter set and route through the generic internal implementation with parameter-specific constants. This keeps the public API compact while avoiding runtime-sized buffers for normal callers.

Relevant shape:

- `keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> Result<([u8; EK_BYTES], [u8; DK_BYTES]), EncodeError>`
- `encaps_from_seed(ek: &[u8; EK_BYTES], m: &[u8; 32]) -> Result<([u8; SS_BYTES], [u8; CT_BYTES]), EncodeError>`
- `decaps(dk: &[u8; DK_BYTES], ct: &[u8; CT_BYTES]) -> Result<[u8; SS_BYTES], EncodeError>`

This is a good compact target design. It gets a lot of type-level length checking without introducing heavyweight key objects for the raw facade.

### ML-DSA context-length handling looks correct at the facade layer

`sign`, `hash_sign`, `sign_random`, and `hash_sign_random` reject contexts over 255 bytes before constructing the FIPS message representative.

That is the right behavior for the FIPS 204 `ctx` length byte. It also avoids accidental truncation from `ctx.len() as u8`; the cast is only reached after the length check.

### Internal signing path defends against shape mismatches

`sign_internal_impl_pieces` checks:

- secret-key length,
- signature-output length,
- and the maximum number of message-representative pieces.

Malformed shapes return `EncodeError::BufferTooSmall` rather than panicking. This is compact and appropriate for `no_std`, but the single error variant does multiplex several different shape-contract violations.

### ML-KEM raw facades preserve fallibility

The ML-KEM raw facades return `Result` even though the in-tree const-sized paths should not hit structural buffer errors. That is the right choice because malformed peer input and canonicality failures need a non-panic path.

## Detritus / leftover cleanup items

### RustCrypto TODO comments remain

There are still TODO comments in the core RustCrypto layer. They are not debug garbage like `dbg!` or `println!`, but they read as unfinished design notes around `.expect` usage and typestate / const-generic improvements.

The relevant areas are:

- `Encapsulate::encapsulate_with_rng` for `Ek<P>`.
- `Generate for Dk<P>`.
- `Generate for MlDsaSigner<P>`.

These comments are understandable, but they should probably become either tracked issues or clearer design comments. They currently read like work accidentally left mid-stream.

### Redundant explanatory comments around unreachable errors

The module-level docs already explain that infallible RustCrypto trait paths cross structurally unreachable `EncodeError` arms via `.expect`. The individual TODO comments repeat the same concern less cleanly.

This is not a correctness issue. It is documentation hygiene.

### `EncodeError::BufferTooSmall` multiplexes unrelated shape failures

The code explicitly documents that `BufferTooSmall` covers multiple shape contracts in `sign_internal_impl_pieces`. This is compact, but it means diagnostics do not distinguish:

- malformed secret-key length,
- malformed signature-output length,
- too many message-representative pieces.

That tradeoff is probably acceptable for the compact target, but worth being aware of.

## Risks / documentation gaps

### Side-channel status is partial and should be understood as partial

The README broadly says the crate is experimental and side-channel properties are not analyzed. The source is more specific: ML-DSA keygen/sign use constant-time Montgomery multiplication for NTT-domain arithmetic, but time-domain post-processing, including `sample_in_ball` and rounding helpers, is not yet constant-time.

This is an important distinction. The code makes meaningful constant-time efforts in selected places, but the whole signing operation should not be documented or treated as fully constant-time.

### ML-DSA signing has an unbounded rejection loop

The signing path has the expected ML-DSA rejection-loop structure. It retries by incrementing `kappa` and continuing when norm or hint conditions fail.

That is expected for ML-DSA-style signing, but it has two implications:

- signing latency is variable;
- any API/security documentation should avoid implying fixed-time signing.

### `kappa` uses `u16::wrapping_add`

The signing loop increments `kappa` with `wrapping_add(L as u16)` on rejection.

In practice, rejection counts should be nowhere near wraparound. Still, from a pure review perspective, this is a theoretical risk point: if the impossible happens and the retry schedule wraps, the deterministic mask schedule can repeat.

I would not necessarily change this immediately because a larger counter may affect compactness or downstream assumptions. But I would document the reasoning or add a defensive bound if the compactness cost is acceptable.

### HashML-DSA pre-hash coverage is intentionally incomplete

`PreHash` only exposes SHA-256 and SHA-512, while the public docs state that FIPS 204 also approves SHA3 variants, SHA-384, and SHAKE pre-hashes that cannot currently be verified through this API.

That is well documented in the crate docs. It remains an API limitation users need to see before choosing this crate for protocols that require the other pre-hash modes.

### RustCrypto `.expect` paths are structurally unreachable but still visible

The RustCrypto module explains why `.expect` is used: the trait methods are infallible or can only return RNG errors, while the lower-level facade preserves `EncodeError`.

That design is defensible. However, the presence of `.expect` in a cryptographic crate will catch reviewer attention. The intended invariant should either be very clearly documented or encoded with stronger types where feasible.

### Raw byte-array APIs trade type safety for compactness

The per-parameter facades use compact `&[u8; N]` and `[u8; N]` forms. This is good for `no_std`, no-heap, embedded targets.

The tradeoff is that the raw API does not distinguish these concepts at the type level:

- canonical public key vs arbitrary byte array,
- secret key vs public key,
- ciphertext vs signature,
- validated vs unvalidated peer input.

The RustCrypto layer partially addresses this with wrapper types, marker traits, and `TryKeyInit`. The raw facades intentionally stay compact.

## Opportunities to better use Rust strengths without compromising compactness

### Typestate for canonical ML-KEM encapsulation keys

The biggest type-system win would be making canonical ML-KEM encapsulation keys explicit with an internal typestate such as `CanonicalEk`.

That would directly address the TODO around `Encapsulate::encapsulate_with_rng`, where the current invariant is: this key was canonicalized at construction, and all buffer sizes are pinned by the parameter marker.

This could remove or isolate one `.expect` without changing the raw compact facade.

### Centralize structurally unreachable error handling

Instead of repeating `.expect("... facade-pinned buffer sizes")`, a tiny internal helper could centralize this invariant, for example conceptually:

```rust
fn expect_pinned<T>(label: &str, result: Result<T, EncodeError>) -> T { ... }
```

That would keep messages consistent and make future audit easier. It would not change public APIs, allocation behavior, or stack shape in any meaningful way.

### Keep the sealed parameter traits

The sealed parameter traits are a good Rust pattern here. `MlKemParams` and `MlDsaParams` keep parameter-set dispatch type-driven and prevent downstream implementations.

For cryptographic parameter sets, that is a strength. It avoids unsupported third-party parameter combinations while preserving a generic implementation internally.

### The `Infallible` lifting is idiomatic

The `lift_sign_err` function maps `SignError<Infallible>` into `SignError<E>` and handles the impossible RNG arm with `match never {}`.

That is a good Rust-native way to express impossible control flow without allocation or dynamic dispatch.

### Fixed-capacity message-piece handling is reasonable

`sign_internal_impl_pieces` caps the number of message-representative pieces because the absorb list is a fixed-size array.

That is sensible for `no_std`. If many more callers are added, an internal fixed-capacity piece-list type might make the invariant clearer, but the current runtime check is probably the right compact tradeoff.

## Things I would not change casually

### Do not replace the raw byte-array facades by default

The current raw facades are compact and embedded-friendly. Replacing them with newtype-heavy APIs everywhere would make the simple `no_std` use case heavier.

The better split is probably the current one:

- raw facades for compact byte-array use;
- RustCrypto compatibility types for users who want typed key objects and trait integration.

### Do not remove `Result` from raw facades

Even where errors are structurally unreachable for in-tree callers, the fallible return shape is useful and safer. It keeps malformed external input and canonicality failures out of panic paths.

### Do not remove every `.expect` without considering trait constraints

The RustCrypto trait signatures constrain what can be returned. The code already chooses `TryDecapsulate` rather than infallible `Decapsulate`, which is the right direction where the trait ecosystem permits it.

For `Generate` and `Encapsulate`, the remaining `.expect` paths are more about trait/API impedance than casual panic usage.

## Specific follow-up recommendations

1. Convert the RustCrypto TODO comments into either tracked issues or explicit invariant comments.
2. Consider an internal `CanonicalEk` typestate for the RustCrypto ML-KEM encapsulation key path.
3. Decide whether `kappa` wraparound should be documented as impossible-by-probability or prevented with a defensive bound.
4. Keep the raw byte-array facades compact; do not over-newtype the embedded-facing API.
5. If protocol users need broader HashML-DSA support, extend `PreHash` to cover the remaining FIPS 204-approved pre-hash modes.
6. Consider centralizing structurally unreachable `EncodeError` handling in the RustCrypto layer to make audit review simpler.

## Verification performed

- `cargo test` passed.
- `cargo clippy --all-targets -- -D warnings` passed.
