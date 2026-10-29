//! Attribution and classification of preinit entries.

use super::{EARLY_INIT_CATEGORY, SANITIZER_RUNTIME_CATEGORY, Target, category, foreign_entries};

const SHIM: u64 = 0x1180;

/// Only the shim's own preinit entry is clean: an entry beside it, one
/// naming another image's function or of an unknown kind, and any entry in a
/// stripped binary (nothing can be the shim's) are foreign.
#[test]
fn only_the_shims_own_entry_is_clean() {
    let shim = Target::Address(SHIM);
    assert!(foreign_entries(std::slice::from_ref(&shim), Some(SHIM)).is_empty());
    let guest = Target::Address(0x2000);
    assert_eq!(foreign_entries(&[shim.clone(), guest], Some(SHIM)), [1]);
    let imported = Target::Symbol("__asan_init".into());
    assert_eq!(foreign_entries(&[imported, shim.clone()], Some(SHIM)), [0]);
    assert_eq!(foreign_entries(&[Target::Unknown], Some(SHIM)), [0]);
    assert_eq!(foreign_entries(&[shim], None), [0]);
}

#[test]
fn sanitizer_initializers_are_their_own_class() {
    assert_eq!(category(Some("__asan_init")), SANITIZER_RUNTIME_CATEGORY);
    assert_eq!(category(Some("guest_preinit")), EARLY_INIT_CATEGORY);
    assert_eq!(category(None), EARLY_INIT_CATEGORY);
}
