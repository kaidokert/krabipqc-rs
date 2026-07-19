use modmath::basic;

// All callers pass pre-reduced values (< q). The add/sub formulas below
// are the same branchless pre-reduced cores that modmath uses internally;
// they avoid both the per-call SchoolbookField construction and the `% q`
// reduction that SchoolbookField::reduce performs on already-canonical inputs.
// mul/exp delegate to the public modmath::basic free functions which also
// handle pre-reduced inputs correctly.

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

#[inline(always)]
pub(crate) fn sb_mul(a: u32, b: u32, q: u32) -> u32 {
    basic::mul(a, b, q)
}

#[inline(always)]
pub(crate) fn sb_exp(base: u32, exp: u32, q: u32) -> u32 {
    basic::exp(base, exp, q)
}
