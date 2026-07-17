use modmath::{FieldOps, SchoolbookField};

#[inline(always)]
pub(crate) fn sb_add(a: u32, b: u32, q: u32) -> u32 {
    let f = SchoolbookField::new(q).unwrap();
    f.into_raw(&f.add(&f.reduce(&a), &f.reduce(&b)))
}

#[inline(always)]
pub(crate) fn sb_sub(a: u32, b: u32, q: u32) -> u32 {
    let f = SchoolbookField::new(q).unwrap();
    f.into_raw(&f.sub(&f.reduce(&a), &f.reduce(&b)))
}

#[inline(always)]
pub(crate) fn sb_mul(a: u32, b: u32, q: u32) -> u32 {
    let f = SchoolbookField::new(q).unwrap();
    f.into_raw(&f.mul(&f.reduce(&a), &f.reduce(&b)))
}

#[inline(always)]
pub(crate) fn sb_exp(base: u32, exp: u32, q: u32) -> u32 {
    let f = SchoolbookField::new(q).unwrap();
    f.into_raw(&f.exp(&f.reduce(&base), &exp))
}
