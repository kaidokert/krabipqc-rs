use subtle::{Choice, ConditionallySelectable};

// All callers pass pre-reduced values (< q). subtle::ConditionallySelectable
// emits CT arithmetic (xor-mask, no branch) regardless of optimisation level
// or target — no reliance on LLVM emitting cmov.

#[inline(always)]
pub(crate) fn sb_add(a: u32, b: u32, q: u32) -> u32 {
    let sum = a.wrapping_add(b);
    u32::conditional_select(&sum, &sum.wrapping_sub(q), Choice::from((sum >= q) as u8))
}

#[inline(always)]
pub(crate) fn sb_sub(a: u32, b: u32, q: u32) -> u32 {
    let diff = a.wrapping_sub(b);
    u32::conditional_select(&diff, &diff.wrapping_add(q), Choice::from((a < b) as u8))
}
