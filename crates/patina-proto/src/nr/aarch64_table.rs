//! The table built with the arm64 numbers on x86_64 (a test), so that every row's
//! compile-time checks (one row per call, numbers inside the table) also run for arm64.
#![allow(dead_code, clippy::duplicate_mod)]

mod nr {
    pub use crate::nr::aarch64::*;
    pub use crate::nr::present;
}

#[path = "../table/mod.rs"]
mod table;

#[test]
fn absent_call_has_no_row() {
    assert!(!nr::present(nr::OPEN));
    assert!(table::known().all(|r| r.name != "open"));
    let r = table::row(nr::OPENAT as u32);
    assert!(r.written && r.name == "openat");
}
