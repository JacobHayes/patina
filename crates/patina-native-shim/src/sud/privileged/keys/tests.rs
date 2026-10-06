//! Unit tests for this module and its focused submodules.

use super::*;
use crate::identity::credential;

/// The thread that makes the process keyring.
const MAIN: c_int = 2;

/// A model holding just `MAIN`'s process keyring, and its serial.
fn with_process_keyring() -> (Keys, i32) {
    let mut keys = Keys::new();
    let Ok((ring, _)) = keys.lookup(
        credential(),
        MAIN,
        KEY_SPEC_PROCESS_KEYRING,
        true,
        Some(NEED_WRITE),
    ) else {
        panic!("the process keyring");
    };
    (keys, ring)
}

fn add(keys: &mut Keys, ring: i32, description: &[u8], data: &[u8]) -> Result<i32, u32> {
    match keys.create_or_update(credential(), ring, description.to_vec(), data.to_vec()) {
        Ok(serial) => Ok(serial as i32),
        Err(Stop::Refuse(code)) => Err(code),
        Err(Stop::End(end)) => panic!("{end:?}"),
    }
}

/// SEARCH's unsupported destination form stops after valid arguments.
/// Class pairing: argument-order checks below and the live key oracle.
#[test]
fn search_with_destination_stops_by_name() {
    assert!(matches!(
        keyctl_at(credential(), MAIN, &[10, KEY_SPEC_SESSION_KEYRING as u64, c"user".as_ptr() as u64, c"missing".as_ptr() as u64, KEY_SPEC_PROCESS_KEYRING as u64, 0], 0),
        Err(Stop::End(Unmodeled::Path(reason))) if reason.contains("KEYCTL_SEARCH")
    ));
}

/// Class pairing: the live oracle's SEARCH argument refusals.
#[test]
fn search_destination_checks_arguments_before_stopping() {
    let kind = c"user".as_ptr() as u64;
    let description = c"missing".as_ptr() as u64;
    for (kind, description, expected) in [
        (0, description, errno::EFAULT),
        (kind, 0, errno::EFAULT),
        (kind, description, errno::EINVAL),
    ] {
        assert!(
            matches!(
                keyctl_at(credential(), MAIN, &[10, 0, kind, description, KEY_SPEC_PROCESS_KEYRING as u64, 0], 0),
                Err(Stop::Refuse(code)) if code == expected
            ),
            "expected errno {expected} before the destination stop"
        );
    }
}

#[test]
fn search_unknown_type_is_enokey() {
    assert!(matches!(
        keyctl_at(
            credential(),
            MAIN,
            &[
                10,
                KEY_SPEC_SESSION_KEYRING as u64,
                c"unregistered-type".as_ptr() as u64,
                c"missing".as_ptr() as u64,
                0,
                0
            ],
            0
        ),
        Err(Stop::Refuse(errno::ENOKEY))
    ));
}

#[test]
fn nested_search_skips_unsearchable_rings() {
    let mut keys = Keys::new();
    let persistent = keys.persistent(credential(), FIRST_SERIAL, 0).unwrap() as i32;
    add(&mut keys, persistent, b"nested", b"v").unwrap();
    keys.keys.get_mut(&persistent).unwrap().perm = 0;
    assert!(matches!(
        keys.search(credential(), FIRST_SERIAL, b"nested", true),
        Err(Stop::Refuse(errno::ENOKEY))
    ));
    assert!(matches!(
        keys.search(credential(), persistent, b"nested", true),
        Err(Stop::Refuse(errno::EACCES))
    ));
}

#[test]
fn link_quota_precedes_cycle_and_nested_checks() {
    let (mut keys, process) = with_process_keyring();
    let used: usize = keys
        .keys
        .values()
        .filter(|k| k.in_quota)
        .map(Key::quota_bytes)
        .sum();
    let room = KERNEL_CONFIG.keys_maxbytes as usize - used - LINK_BYTES - b"full\0".len();
    add(&mut keys, FIRST_SERIAL, b"full", &vec![0; room]).unwrap();
    for serial in [FIRST_SERIAL, process] {
        assert!(matches!(
            keys.link(serial, FIRST_SERIAL),
            Err(Stop::Refuse(errno::EDQUOT))
        ));
    }
}

/// The quota holds `kernel.keys.maxkeys` keys (the process keyring
/// among them) and `kernel.keys.maxbytes` bytes: the keyring's
/// description and NUL, and each key's link, description, NUL and
/// payload.
#[test]
fn the_quota_counts_keys_links_and_bytes() {
    let (mut keys, ring) = with_process_keyring();
    let fits = KERNEL_CONFIG.keys_maxbytes as usize
        - b"_ses\0".len()
        - b"_pid\0".len()
        - LINK_BYTES
        - b"d\0".len();
    assert_eq!(
        add(&mut keys, ring, b"d", &vec![0; fits + 1]),
        Err(errno::EDQUOT)
    );
    assert!(add(&mut keys, ring, b"d", &vec![0; fits]).is_ok());

    let (mut keys, ring) = with_process_keyring();
    for index in 2..KERNEL_CONFIG.keys_maxkeys {
        assert!(add(&mut keys, ring, index.to_string().as_bytes(), b"v").is_ok());
    }
    assert_eq!(
        add(&mut keys, ring, b"one too many", b"v"),
        Err(errno::EDQUOT)
    );
}

/// Class pairing: quota bounds and graph ownership, independent of serials.
#[test]
fn session_and_persistent_links_charge_the_owner_not_each_reference() {
    let mut keys = Keys::new();
    let ring = FIRST_SERIAL;
    assert_eq!(keys.keys[&ring].perm, SESSION_PERM);
    assert_eq!(keys.keys[&ring].description, b"_ses");
    assert_eq!(
        keys.search(credential(), ring, b"d", true)
            .err()
            .map(|e| matches!(e, Stop::Refuse(errno::ENOKEY))),
        Some(true)
    );
    let persistent = keys.persistent(credential(), ring, 0).unwrap() as i32;
    let serial = add(&mut keys, ring, b"d", b"v").unwrap();
    keys.link(serial, persistent).unwrap();
    keys.link(serial, persistent).unwrap();
    assert_eq!(
        keys.keys[&persistent].payload,
        Payload::Keyring(vec![serial])
    );
    let charged: usize = keys
        .keys
        .values()
        .filter(|k| k.in_quota)
        .map(Key::quota_bytes)
        .sum();
    assert_eq!(charged, b"_ses\0".len() + 2 * LINK_BYTES + b"d\0v".len());
    let nested = add(&mut keys, persistent, b"nested", b"v").unwrap();
    assert!(keys.possessed(MAIN, nested));
    assert_eq!(
        keys.search(credential(), ring, b"nested", true).unwrap(),
        nested
    );
    keys.persistent(credential(), ring, 10).unwrap();
    assert!(keys.possessed(MAIN, serial));
    assert!(keys.collect(10 + PERSISTENT_EXPIRY - 1).is_ok());
    assert!(matches!(
        keys.collect(10 + PERSISTENT_EXPIRY),
        Err(Stop::End(_))
    ));
}

/// The session is global; only process rings need thread lifecycle state.
#[test]
fn session_is_shared_without_lifecycle_bookkeeping() {
    let mut keys = Keys::new();
    let serial = add(&mut keys, FIRST_SERIAL, b"d", b"v").unwrap();
    keys.spawned(MAIN, MAIN + 1);
    keys.exited(MAIN);
    keys.exited(MAIN + 1);
    assert!(keys.holders.is_empty());
    assert!(keys.collecting.is_empty());
    assert!(keys.possessed(MAIN + 2, serial));
    assert_eq!(
        keys.lookup(
            credential(),
            MAIN + 2,
            KEY_SPEC_SESSION_KEYRING,
            false,
            Some(NEED_SEARCH)
        )
        .unwrap()
        .0,
        FIRST_SERIAL
    );
    assert_eq!(Keys::new().next_serial, FIRST_SERIAL + 1);
    assert_eq!(Keys::new().keys.len(), 1);
}

/// Class pairing: quota accounting and graph ownership, plus the live oracle.
#[test]
fn invalidation_collects_every_link_and_reclaims_quota_immediately() {
    let (mut keys, process) = with_process_keyring();
    let persistent = keys.persistent(credential(), FIRST_SERIAL, 0).unwrap() as i32;
    let key = add(&mut keys, FIRST_SERIAL, b"d", b"v").unwrap();
    keys.link(key, process).unwrap();
    keys.link(key, persistent).unwrap();
    let used: usize = keys
        .keys
        .values()
        .filter(|k| k.in_quota)
        .map(Key::quota_bytes)
        .sum();
    let full_payload = KERNEL_CONFIG.keys_maxbytes as usize - used + 1;
    keys.update(key, vec![0; full_payload]).unwrap();
    assert!(matches!(
        keys.charge(false, 1),
        Err(Stop::Refuse(errno::EDQUOT))
    ));
    keys.invalidate(key).unwrap();
    assert!(!keys.keys.contains_key(&key));
    assert!(!keys.collecting.contains(&key));
    assert!(matches!(
        keys.lookup(credential(), MAIN, key, false, None),
        Err(Stop::Refuse(errno::ENOKEY))
    ));
    for ring in [FIRST_SERIAL, process, persistent] {
        assert!(matches!(
            keys.search(credential(), ring, b"d", true),
            Err(Stop::Refuse(errno::ENOKEY))
        ));
    }
    assert_eq!(
        keys.keys[&FIRST_SERIAL].payload,
        Payload::Keyring(vec![persistent])
    );
    assert_eq!(keys.keys[&process].payload, Payload::Keyring(vec![]));
    assert_eq!(keys.keys[&persistent].payload, Payload::Keyring(vec![]));
    let remaining: usize = keys
        .keys
        .values()
        .filter(|k| k.in_quota)
        .map(Key::quota_bytes)
        .sum();
    assert_eq!(remaining, b"_ses\0_pid\0".len() + LINK_BYTES);
    assert!(
        keys.charge(true, KERNEL_CONFIG.keys_maxbytes as usize - remaining)
            .is_ok()
    );
    let replacement = add(&mut keys, FIRST_SERIAL, b"d", &vec![0; full_payload]).unwrap();
    assert!(replacement > key);
}

#[test]
fn displacement_preserves_other_links() {
    let mut keys = Keys::new();
    let ring = FIRST_SERIAL;
    let persistent = keys.persistent(credential(), ring, 0).unwrap() as i32;
    let first = add(&mut keys, ring, b"d", b"v").unwrap();
    keys.link(first, persistent).unwrap();
    keys.keys.get_mut(&first).unwrap().revoked_at = Some(0);
    let second = add(&mut keys, ring, b"d", b"w").unwrap();
    assert_ne!(first, second);
    assert!(keys.keys.contains_key(&first));
    keys.link(second, persistent).unwrap();
    assert!(!keys.keys.contains_key(&first));
    assert_eq!(keys.search(credential(), ring, b"d", true).unwrap(), second);
}

#[test]
fn unsupported_key_service_surface_still_stops_by_name() {
    for op in [
        1, 5, 7, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 23, 24, 25, 26, 27, 28, 29, 30, 32,
    ] {
        assert!(matches!(
            keyctl_at(credential(), MAIN, &[op, 0, 0, 0, 0, 0], 0),
            Err(Stop::End(Unmodeled::Path(reason))) if reason == KEYCTL_NAMES[op as usize]
        ));
    }
    let mut keys = Keys::new();
    for ring in [
        KEY_SPEC_THREAD_KEYRING,
        KEY_SPEC_USER_KEYRING,
        KEY_SPEC_USER_SESSION_KEYRING,
    ] {
        assert!(matches!(
            keys.lookup(credential(), MAIN, ring, true, Some(NEED_SEARCH)),
            Err(Stop::End(_))
        ));
    }
}

/// A revoked key's description is free again: a new key displaces it
/// at once, and its serial names nothing.
#[test]
fn a_new_key_displaces_a_revoked_one() {
    let (mut keys, ring) = with_process_keyring();
    let first = add(&mut keys, ring, b"d", b"v").unwrap();
    keys.keys.get_mut(&first).unwrap().revoked_at = Some(0);
    let second = add(&mut keys, ring, b"d", b"w").unwrap();
    assert_ne!(first, second);
    assert!(matches!(
        keys.lookup(credential(), MAIN, first, false, None),
        Err(Stop::Refuse(errno::ENOKEY))
    ));
    assert_eq!(keys.keys[&ring].payload, Payload::Keyring(vec![second]));
}

/// Past `kernel.keys.gc_delay` a revoked key would be collected: the
/// model ends there, not before.
#[test]
fn the_collector_is_where_the_model_ends() {
    let (mut keys, ring) = with_process_keyring();
    let serial = add(&mut keys, ring, b"d", b"v").unwrap();
    keys.keys.get_mut(&serial).unwrap().revoked_at = Some(10);
    assert!(keys.collect(10 + KERNEL_CONFIG.keys_gc_delay - 1).is_ok());
    assert!(matches!(
        keys.collect(10 + KERNEL_CONFIG.keys_gc_delay),
        Err(Stop::End(_))
    ));
}

/// A keyring its last thread left is the collector's, and so are its
/// keys: naming one ends the model, and so does a charge only their
/// going would let fit; one that fits either way is answered.
#[test]
fn a_keyring_its_last_thread_left_is_the_collectors() {
    const WORKER: c_int = MAIN + 1;
    let (mut keys, ring) = with_process_keyring();
    keys.spawned(MAIN, WORKER);
    let key = add(&mut keys, ring, b"d", b"v").unwrap();
    keys.exited(MAIN);
    assert!(keys.lookup(credential(), WORKER, key, false, None).is_ok());
    keys.exited(WORKER);
    for serial in [ring, key] {
        assert!(matches!(
            keys.lookup(credential(), MAIN, serial, false, None),
            Err(Stop::End(_))
        ));
    }
    assert!(keys.charge(true, 1).is_ok());
    let freed_bytes = KERNEL_CONFIG.keys_maxbytes as usize - b"_pid\0".len();
    assert!(matches!(keys.charge(true, freed_bytes), Err(Stop::End(_))));
}
