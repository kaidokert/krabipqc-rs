# ML-KEM-512 hardware constant-time campaign

This campaign runs the existing ML-KEM-512 decapsulation CT fixture on the
J-Trace STM32F407VG. One public ciphertext is held fixed while two independently
generated decapsulation keys are measured in balanced A/B order at 30 MHz with
zero flash wait states. The ciphertext is valid for key A and drives implicit
rejection under key B, exercising the constant-time validity/select boundary
without changing the public input.

The hardware adapter calls the same public decapsulation operation covered by
the assembly and ctgrind fixtures. A variable-time early-exit fixture runs as
the negative control, so a campaign cannot pass unless the hardware gate still
distinguishes known timing differences.

The initial campaign intentionally covers one operation and parameter set:
ML-KEM-512 decapsulation. Larger ML-KEM parameter sets and ML-DSA are separate
coverage decisions.

Run through the campaign driver:

```sh
cargo krabi-caliper run krabipqc-mlkem512-ct-jtrace-f407
```

The bench supplies `KRABI_PROBE`; no physical probe selector is committed.
