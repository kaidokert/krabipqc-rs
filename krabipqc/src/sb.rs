// All callers pass pre-reduced values (< q). These formulas are the same
// branchless pre-reduced cores that modmath uses internally; they avoid both
// the per-call SchoolbookField construction and the `% q` reduction that
// SchoolbookField::reduce performs on already-canonical inputs.

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
