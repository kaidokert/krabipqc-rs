// All callers pass pre-reduced values (< q). These avoid the per-call
// SchoolbookField construction and the `% q` in SchoolbookField::reduce, but
// the `if sum >= q` branch is identical to modmath's basic_mod_add_pr — not
// provably branchless. CT-clean implementations of callers (e.g. Ct-personality
// NTT) rely on LLVM emitting cmov, which it does in practice but doesn't
// guarantee. A genuinely CT add/sub would use arithmetic masking or subtle.

#[inline(always)]
pub(crate) fn sb_add(a: u32, b: u32, q: u32) -> u32 {
    let sum = a.wrapping_add(b);
    if sum >= q { sum.wrapping_sub(q) } else { sum }
}

#[inline(always)]
pub(crate) fn sb_sub(a: u32, b: u32, q: u32) -> u32 {
    let diff = a.wrapping_sub(b);
    if a < b { diff.wrapping_add(q) } else { diff }
}
