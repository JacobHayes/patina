//! System call numbers by name, for the architecture being built. A call's name is its
//! identity: the table's rows, the runtime's handlers and its own calls name the constant, so
//! each is written once for every architecture. Both files are generated
//! (`scripts/gen-syscalls.py`).
//!
//! A call the architecture lacks is `absent(k)`: distinct, so `match` arms naming it stay
//! valid, and above `u32::MAX`, so no trap ever carries it (the trap entry gives every number
//! above `u32::MAX` the `unknown` row, which stops the run) and `Row::new` leaves it out of
//! the table.

#[cfg(any(test, target_arch = "x86_64"))]
pub(crate) mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(any(test, target_arch = "aarch64"))]
pub(crate) mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("no system call numbers for this architecture");

/// The value of a call this architecture lacks (`k` keeps the values distinct).
pub const fn absent(k: u64) -> u64 {
    1 << 40 | k
}

/// Does this architecture have the call?
pub const fn present(nr: u64) -> bool {
    nr <= u32::MAX as u64
}

/// The table built with the arm64 numbers on x86_64.
#[cfg(all(test, target_arch = "x86_64"))]
mod aarch64_table;

#[cfg(test)]
mod tests {
    use super::{aarch64, present, x86_64};

    /// One architecture's constants: a present number is below `NR_COUNT` and is that name's
    /// slot in `NAMES` (so no two names share one); an absent one is above `u32::MAX`, unique,
    /// and has no slot; every name in `NAMES` has a constant.
    fn consistent(by_name: &[(&str, u64)], names: &[Option<&str>], count: usize) {
        for (i, &(name, v)) in by_name.iter().enumerate() {
            if present(v) {
                assert!((v as usize) < count, "{name}");
                assert_eq!(names[v as usize], Some(name), "{name}");
            } else {
                assert!(v > u32::MAX as u64, "{name}");
                assert!(!names.contains(&Some(name)), "{name}");
                assert!(by_name[..i].iter().all(|&(_, w)| w != v), "{name}");
            }
        }
        for n in names.iter().flatten() {
            assert!(by_name.iter().any(|&(m, _)| m == *n), "{n} has no constant");
        }
    }

    #[test]
    fn numbers() {
        consistent(x86_64::BY_NAME, &x86_64::NAMES, x86_64::NR_COUNT);
        consistent(aarch64::BY_NAME, &aarch64::NAMES, aarch64::NR_COUNT);
        // The same names on both.
        assert_eq!(x86_64::BY_NAME.len(), aarch64::BY_NAME.len());
        for (name, _) in aarch64::BY_NAME {
            assert!(x86_64::BY_NAME.iter().any(|(m, _)| m == name), "{name}");
        }
    }
}
