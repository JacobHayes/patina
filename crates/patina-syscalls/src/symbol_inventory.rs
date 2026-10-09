//! One symbol inventory emits both target rows and host-independent build metadata.

use crate::{Platform, Serves, SymbolRow, SymbolStatus};

pub(super) const fn s(
    name: &'static str,
    platform: Platform,
    serves: Serves,
    status: SymbolStatus,
) -> SymbolRow {
    SymbolRow {
        name,
        platform,
        serves,
        status,
    }
}

macro_rules! symbol_rows {
    ($($(#[cfg(target_arch = $arch:tt)])? s($name:expr, $platform:expr, $serves:expr, $status:expr $(,)?),)*) => {
        pub(super) const ROWS: &[SymbolRow] = &[
            $($(#[cfg(target_arch = $arch)])? s($name, $platform, $serves, $status),)*
        ];
        /// Complete symbol metadata for code generators, including architecture-gated rows.
        #[doc(hidden)]
        pub(super) const METADATA: &[(SymbolRow, Option<&str>)] = &[
            $((s($name, $platform, $serves, $status), symbol_rows!(@arch $($arch)?)),)*
        ];
    };
    (@arch) => { None };
    (@arch $arch:tt) => { Some($arch) };
}

/// Join concern-specific inventories in const data, with no runtime allocation.
pub(super) const fn concat<T: Copy, const N: usize>(left: &[T], right: &[T]) -> [T; N] {
    assert!(N == left.len() + right.len());
    let mut rows = [left[0]; N];
    let mut i = 0;
    while i < N {
        rows[i] = if i < left.len() {
            left[i]
        } else {
            right[i - left.len()]
        };
        i += 1;
    }
    rows
}
