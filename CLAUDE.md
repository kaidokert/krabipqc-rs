# krabipqc

Prototype `no_std` ML-DSA / ML-KEM for microcontrollers. See
[`README.md`](README.md) for scope.

## Invariants

These hold across the crate; changes that break them need a deliberate
reason, not silence.

- **No `unsafe`, no heap, no `alloc`.** Fixed-size stack buffers only.
- **No reachable panics.** `[]` indexing, slice ranges, `unwrap`/`expect`,
  unchecked integer arithmetic, and `copy_from_slice` length mismatches
  are all implicit panics, and a panic on a microcontroller is a hang.
  Remove them by construction — see [`PANIC_TOOLSET.md`](PANIC_TOOLSET.md)
  for the techniques (fallible APIs, slice carving, type-level sizes,
  typestate) and when to reach for each.
- **All Z_q arithmetic flows through `modmath`.** Keygen/sign and
  encaps/decaps run the constant-time-leaning (`Ct`) Montgomery path;
  verify runs the variable-time (`Nct`) path, since its inputs are public.
- **ACVP-conformant.** Output is byte-exact against the NIST vectors on
  all six parameter sets; the KATs are the contract.

## Comment discipline

Comments explain **why** — a hidden constraint, a subtle invariant, a
non-obvious workaround. What the code does and how it does it must fall out
of types, names, and structure.

Specifically off-limits:

- Restatements of the code on the next line or the function signature.
- Section-divider banners (`// === ML-KEM ===`) — the type declaration below
  is already the label.
- History or evolution references: "arriving with PR N", "previously", "will
  be", "used to". The file is the present state; git log is the history.
- `pub(crate)` rustdoc that describes implementation mechanics at length —
  internal callers read the code, not the prose.

Exception: `///` and `//!` API-facing doc may describe what/how for external
callers, but should still be concise. A rustdoc that restates the function
name or return type adds nothing.

## API surface

Decisions made for the published (`0.1.0`) surface; don't reverse without a
clear reason.

- **`RandomizedSigner` only, no `Signer`.** `Signer` implies deterministic
  signing with a zeroed `rnd` buffer, which is unsafe for ML-DSA. Only
  `try_sign_with_rng` / `RandomizedSigner` is exposed on `MlDsaSigner<P>`.
- **Sealed parameter traits.** `MlKemParams` and `MlDsaParams` use the
  `mod private { pub trait Sealed {} }` pattern so external crates cannot
  add parameter sets. The six marker types (`MlKem512` … `MlDsa87`) are the
  closed set.
- **`#[doc(hidden)]` on dispatch methods.** The trait methods
  (`kem_keygen`, `dsa_sign`, etc.) are required by the sealed traits but are
  implementation plumbing, not API. `#[doc(hidden)]` keeps them out of
  generated docs without changing accessibility.
- **`RandError<E>` for RNG-driven entry points.** `KeyGenError<E>` and
  `KemError<E>` were structurally identical; they were merged into a single
  neutral `RandError<E> { Rng(E), Encode(EncodeError) }`.
- **`acvp` feature gate for internal sign/verify.** `sign_msg_repr`,
  `verify_msg_repr`, `sign_internal_impl`, and `verify_internal_impl` are
  gated behind `--features acvp`. They take the raw message representative
  `M'` and are only needed for ACVP KAT test suites and the `print_vector`
  example. The default build exposes only the FIPS §5.2 `sign`/`verify`
  wrappers that construct `M'` from `(m, ctx)`.

## Panic avoidance patterns

In addition to the general toolset in `PANIC_TOOLSET.md`, two patterns that
came up in practice:

- **Slice extraction from a typed array:** prefer `.get(start..end).and_then(|s| s.try_into().ok()).ok_or(Err)?`
  over `default()` + `copy_from_slice`. The former is a single fallible
  chain; the latter has a hidden panic if lengths diverge.
- **Infallible `copy_from_slice`:** safe only when the slice length is
  statically guaranteed equal to the destination. When that guarantee comes
  from sealed-trait constants (as in `Dk::TryKeyInit::new`), the `.get()`
  guard is still required to make the proof explicit and avoid the panicking
  `[]` indexing form.

## Deferred work

### `Params` const-generic typestate (shelved until `adt_const_params` stabilizes)

The original plan was `Params<const K: usize, const L: usize, const ETA: Eta, const GAMMA2: Gamma2>`
so that `sk_bytes`/`pk_bytes`/`sig_bytes` become `const fn`s usable in array-size position, and
internal functions can take `&mut [u8; sk_bytes::<K,L,ETA>()]` instead of length-checked slices.

Why it's shelved:

- **Nightly required.** `const ETA: Eta` needs `#![feature(adt_const_params)]`;
  computed array sizes in function signatures need `#![feature(generic_const_exprs)]`.
  Both are unstable on Rust stable (verified on 1.96).
- **Integer fallback loses safety.** Replacing `eta: Eta` with `const ETA: u32` discards the
  exhaustive-match guarantee that the `Eta`/`Gamma2` closed-enum typestate added. Not a trade worth making.
- **No binary benefit.** Zero `eta`/`gamma2` symbols survive into release ASM — LLVM already
  constant-folds all dispatches at the optimizer level because `params` is always a reference to a
  known `const` static (`&ML_DSA_44` etc.). Confirmed by inspecting the emitted `.s` file.
- **Public API already achieves the goal.** The per-set facade's
  `const PK_BYTES: usize = $params.pk_bytes` and `[0u8; PK_BYTES]` allocations give callers
  typed-length arrays at every surface they touch. Only the internal functions would gain typed
  buffers, saving a few dead-code length checks the optimizer likely eliminates anyway.

Revisit when `adt_const_params` stabilizes; at that point it becomes a clean swap with real
type-checker enforcement and no nightly dependency.

### Encoder buffer typing (blocked on the above)

`pk_encode`/`sk_encode` take `&mut [u8]` with a top-of-fn length check. The check becomes
provably dead once the internal functions take typed-length arrays. Unblock by doing the
`Params` const-generic work above first.

## Footprint

The crate targets cortex-m3; stack high-water marks and cycles are
measured under QEMU (`mps2-an385`) via `krabipqc_cortex_m3`. Use
`-icount shift=0` for deterministic cycle counts. Stack is the
deterministic axis; sign cycles vary with the rejection-retry rate of
the specific vector and aren't comparable across parameter sets.
