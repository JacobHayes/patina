//! Attribution and classification of preinit entries.

use super::{EARLY_INIT_CATEGORY, SANITIZER_RUNTIME_CATEGORY, Target, category, foreign_entries};

const SHIM: u64 = 0x1180;

#[test]
fn the_shims_entry_alone_is_clean() {
    assert!(foreign_entries(&[Target::Address(SHIM)], Some(SHIM)).is_empty());
    assert!(foreign_entries(&[], Some(SHIM)).is_empty());
}

#[test]
fn an_entry_beside_the_shims_is_foreign() {
    let guest = Target::Address(0x2000);
    let shim = Target::Address(SHIM);
    assert_eq!(
        foreign_entries(&[guest.clone(), shim.clone()], Some(SHIM)),
        [0]
    );
    assert_eq!(foreign_entries(&[shim, guest], Some(SHIM)), [1]);
}

#[test]
fn an_unattributable_entry_is_foreign() {
    let shim = Target::Address(SHIM);
    // A relocation naming another image's function, or of an unknown kind.
    let imported = Target::Symbol("__asan_init".into());
    assert_eq!(foreign_entries(&[imported, shim.clone()], Some(SHIM)), [0]);
    assert_eq!(foreign_entries(&[Target::Unknown], Some(SHIM)), [0]);
    // No symbol table (a stripped binary): nothing can be the shim's.
    assert_eq!(foreign_entries(&[shim], None), [0]);
}

#[test]
fn sanitizer_initializers_are_their_own_class() {
    assert_eq!(category(Some("__asan_init")), SANITIZER_RUNTIME_CATEGORY);
    assert_eq!(category(Some("__tsan_init")), SANITIZER_RUNTIME_CATEGORY);
    assert_eq!(category(Some("guest_preinit")), EARLY_INIT_CATEGORY);
    assert_eq!(category(None), EARLY_INIT_CATEGORY);
}
