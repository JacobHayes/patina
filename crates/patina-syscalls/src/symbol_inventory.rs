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
        const ROWS: &[SymbolRow] = &[
            $($(#[cfg(target_arch = $arch)])? s($name, $platform, $serves, $status),)*
        ];
        /// Complete symbol metadata for code generators, including gated x86 rows.
        #[doc(hidden)]
        pub const ALL_SYMBOLS_WITH_ARCH: &[(SymbolRow, bool)] = &[
            $((s($name, $platform, $serves, $status), symbol_rows!(@arch $($arch)?)),)*
        ];
    };
    (@arch) => { false };
    (@arch "x86_64") => { true };
}
