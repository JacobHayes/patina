//! setlocale: the C locale, the only one the virtual machine holds.
//!
//! glibc loads a named locale from the locale archive or a locale directory;
//! the deterministic filesystem ships neither, so every name but `C` and
//! `POSIX` fails there as it fails here (`NULL`, `ENOENT`), and the locale
//! never leaves `C`. That is what lets the C-locale string, wide-character
//! and conversion functions stand as pure functions of their arguments (the
//! audit's C-locale group). `""` names the locale the environment asks for
//! (`LC_ALL`, then the category's own variable, then `LANG`), checked the
//! same way.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{CStr, c_char, c_int};
use core::ptr::null;

/// The categories and their environment variables, `LC_ALL` aside.
const CATEGORIES: &[(c_int, &CStr)] = &[
    (libc::LC_CTYPE, c"LC_CTYPE"),
    (libc::LC_NUMERIC, c"LC_NUMERIC"),
    (libc::LC_TIME, c"LC_TIME"),
    (libc::LC_COLLATE, c"LC_COLLATE"),
    (libc::LC_MONETARY, c"LC_MONETARY"),
    (libc::LC_MESSAGES, c"LC_MESSAGES"),
    #[cfg(target_os = "linux")]
    (libc::LC_PAPER, c"LC_PAPER"),
    #[cfg(target_os = "linux")]
    (libc::LC_NAME, c"LC_NAME"),
    #[cfg(target_os = "linux")]
    (libc::LC_ADDRESS, c"LC_ADDRESS"),
    #[cfg(target_os = "linux")]
    (libc::LC_TELEPHONE, c"LC_TELEPHONE"),
    #[cfg(target_os = "linux")]
    (libc::LC_MEASUREMENT, c"LC_MEASUREMENT"),
    #[cfg(target_os = "linux")]
    (libc::LC_IDENTIFICATION, c"LC_IDENTIFICATION"),
];

/// The environment's value of `name`, if set and not empty.
fn variable(name: &CStr) -> Option<&'static [u8]> {
    // SAFETY: env_lookup takes a NUL-terminated key and answers NULL or a
    // NUL-terminated value the environment keeps.
    let value = unsafe { crate::posix_env::env_lookup(name.as_ptr()) };
    // SAFETY: as above.
    let value = (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_bytes())?;
    (!value.is_empty()).then_some(value)
}

/// Whether the virtual machine holds the locale `name`: the C locale only.
fn held(name: &[u8]) -> bool {
    matches!(name, b"C" | b"POSIX")
}

/// # Safety
/// `locale` is NULL or NUL-terminated.
#[unsafe(no_mangle)]
unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let categories: Vec<&CStr> = if category == libc::LC_ALL {
        CATEGORIES.iter().map(|(_, name)| *name).collect()
    } else if let Some((_, name)) = CATEGORIES.iter().find(|(id, _)| *id == category) {
        vec![*name]
    } else {
        super::error(libc::EINVAL);
        return null();
    };
    if !locale.is_null() {
        // SAFETY: nonnull and NUL-terminated, per the contract.
        let locale = unsafe { CStr::from_ptr(locale) }.to_bytes();
        let available = if locale.is_empty() {
            categories.iter().all(|name| {
                let asked = variable(c"LC_ALL")
                    .or_else(|| variable(name))
                    .or_else(|| variable(c"LANG"))
                    .unwrap_or(b"C");
                held(asked)
            })
        } else {
            held(locale)
        };
        if !available {
            super::error(libc::ENOENT);
            return null();
        }
    }
    c"C".as_ptr()
}
