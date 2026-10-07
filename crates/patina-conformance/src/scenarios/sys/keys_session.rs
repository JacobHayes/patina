//! Session/persistent key lifecycle used by Rust's keyutils credential backend.
//! Class pairing: the live-host differential and strace/replay detectors.
//! The native harness supplies a fresh anonymous session before exec; the guest
//! never joins a session or observes the harness's ambient one.
//! Persistent-ring keys use process-unique descriptions and are invalidated.
use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

const SESSION: i64 = -3;
const GET: i64 = 0;
const UPDATE: i64 = 2;
const REVOKE: i64 = 3;
const DESCRIBE: i64 = 6;
const LINK: i64 = 8;
const SEARCH: i64 = 10;
const READ: i64 = 11;
const INVALIDATE: i64 = 21;
const PERSISTENT: i64 = 22;

fn ctl(p: &Probe, op: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    p.call_unrecorded(Syscall::N_keyctl, [op, a, b, c, d, 0])
}
fn search(p: &Probe, ring: i64, name: &CStr) -> i64 {
    ctl(
        p,
        SEARCH,
        ring,
        c"user".as_ptr() as i64,
        name.as_ptr() as i64,
        0,
    )
}
fn add(p: &Probe, ring: i64, name: &CStr, data: &[u8]) -> i64 {
    p.call_unrecorded(
        Syscall::N_add_key,
        [
            c"user".as_ptr() as i64,
            name.as_ptr() as i64,
            data.as_ptr() as i64,
            data.len() as i64,
            ring,
            0,
        ],
    )
}
fn describe(p: &Probe, id: i64, expected: &str) {
    let mut buf = [0u8; 256];
    let len = ctl(
        p,
        DESCRIBE,
        id,
        buf.as_mut_ptr() as i64,
        buf.len() as i64,
        0,
    );
    p.check(
        "key metadata matches the kernel's ids, mask and description",
        len == expected.len() as i64 + 1
            && CStr::from_bytes_until_nul(&buf).map(CStr::to_bytes) == Ok(expected.as_bytes()),
    );
}
fn read(p: &Probe, id: i64, expected: &[u8]) {
    let mut buf = [0u8; 128];
    p.check(
        "read returns the current payload",
        ctl(p, READ, id, buf.as_mut_ptr() as i64, buf.len() as i64, 0) == expected.len() as i64
            && &buf[..expected.len()] == expected,
    );
}

// Native collection is asynchronous and passes through three states, in
// order: still linked (READ ENOKEY, SEARCH EKEYREVOKED), unlinked but not yet
// destroyed (EACCES, ENOKEY), destroyed (ENOKEY, ENOKEY). Allow only those
// refusals while waiting, and require the final pair. SEARCH goes first: its
// ENOKEY proves the unlink, so a later READ's ENOKEY is destruction, never the
// still-linked ENOKEY of a sample that straddles the unlink. Patina's
// immediate-collection interleaving completes on the first attempt.
fn collected(p: &Probe, ring: i64, key: i64, name: &CStr) -> bool {
    for _ in 0..5000 {
        let found = search(p, ring, name);
        let read = ctl(p, READ, key, 0, 0, 0);
        if read == neg(ENOKEY) && found == neg(ENOKEY) {
            return true;
        }
        if ![neg(ENOKEY), neg(EACCES)].contains(&read)
            || ![neg(ENOKEY), neg(EKEYREVOKED)].contains(&found)
        {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    false
}

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let session = ctl(p, GET, SESSION, 0, 0, 0);
    p.require("session supplied at startup", session > 0);
    p.check(
        "session exists without create",
        ctl(p, GET, SESSION, 0, 0, 0) == session,
    );
    p.check(
        "fresh session is empty",
        ctl(p, READ, SESSION, 0, 0, 0) == 0,
    );
    describe(
        p,
        session,
        &format!("keyring;{};{};3f030000;_ses", p.getuid(), p.getgid()),
    );
    let name = CString::new(format!("patina-session-probe-{}", p.getpid())).unwrap();
    p.check(
        "search initially misses",
        search(p, session, &name) == neg(ENOKEY),
    );
    let key = add(p, session, &name, b"first");
    p.require("session user key", key > 0);
    p.check(
        "add updates in place",
        add(p, session, &name, b"second") == key,
    );
    read(p, key, b"second");
    p.check(
        "request finds session key",
        p.call_unrecorded(
            Syscall::N_request_key,
            [c"user".as_ptr() as i64, name.as_ptr() as i64, 0, 0, 0, 0],
        ) == key,
    );
    p.check("search finds session key", search(p, session, &name) == key);
    p.check(
        "link already present succeeds",
        ctl(p, LINK, key, session, 0, 0) == 0,
    );
    p.check(
        "update succeeds",
        ctl(p, UPDATE, key, b"third".as_ptr() as i64, 5, 0) == 0,
    );
    read(p, key, b"third");
    std::thread::scope(|scope| {
        let name = &name;
        scope
            .spawn(move || {
                p.check(
                    "child inherits session",
                    ctl(p, GET, SESSION, 0, 0, 0) == session,
                );
                p.check(
                    "child searches inherited keys",
                    search(p, SESSION, name) == key,
                );
                read(p, key, b"third");
            })
            .join()
            .unwrap();
    });
    p.check(
        "parent keeps original session",
        ctl(p, GET, SESSION, 0, 0, 0) == session,
    );
    p.check(
        "invalid type pointer is EFAULT before ring lookup",
        ctl(p, SEARCH, 0, 0, name.as_ptr() as i64, 0) == neg(EFAULT),
    );
    p.check(
        "search of a user key is ENOTDIR",
        search(p, key, &name) == neg(ENOTDIR),
    );
    p.check(
        "search unknown type is ENOKEY, not add_key's ENODEV",
        ctl(
            p,
            SEARCH,
            session,
            c"unregistered-type".as_ptr() as i64,
            name.as_ptr() as i64,
            0,
        ) == neg(ENOKEY),
    );
    p.check(
        "link to a user key is ENOTDIR",
        ctl(p, LINK, key, key, 0, 0) == neg(ENOTDIR),
    );
    p.check(
        "another uid's persistent ring is EPERM",
        ctl(p, PERSISTENT, 0, SESSION, 0, 0) == neg(EPERM),
    );
    let persistent = ctl(p, PERSISTENT, -1, SESSION, 0, 0);
    p.require("own persistent ring", persistent > 0);
    p.check(
        "persistent lookup is stable",
        ctl(p, PERSISTENT, p.getuid(), SESSION, 0, 0) == persistent,
    );
    describe(
        p,
        persistent,
        &format!(
            "keyring;{};65534;1f030000;_persistent.{}",
            p.getuid(),
            p.getuid()
        ),
    );
    p.check("persistent link", ctl(p, LINK, key, persistent, 0, 0) == 0);
    p.check(
        "persistent duplicate link",
        ctl(p, LINK, key, persistent, 0, 0) == 0,
    );
    let nested_name = CString::new(format!("patina-persistent-probe-{}", p.getpid())).unwrap();
    let nested = add(p, persistent, &nested_name, b"nested");
    p.require("persistent-only key", nested > 0);
    p.check(
        "recursive search reaches persistent-only key",
        search(p, session, &nested_name) == nested,
    );
    p.check(
        "invalidate nested key",
        ctl(p, INVALIDATE, nested, 0, 0, 0) == 0,
    );
    p.check(
        "nested invalidation collected",
        collected(p, session, nested, &nested_name),
    );
    p.check("invalidate", ctl(p, INVALIDATE, key, 0, 0, 0) == 0);
    p.check("invalidation collected", collected(p, session, key, &name));
    p.check(
        "invalidated read is ENOKEY",
        ctl(p, READ, key, 0, 0, 0) == neg(ENOKEY),
    );
    p.check(
        "invalidated search is ENOKEY",
        search(p, session, &name) == neg(ENOKEY),
    );
    let replacement = add(p, session, &name, b"replacement");
    p.require(
        "invalidated description reused with fresh serial",
        replacement > 0 && replacement != key,
    );
    p.check(
        "link replacement",
        ctl(p, LINK, replacement, persistent, 0, 0) == 0,
    );
    read(p, replacement, b"replacement");
    // Collect every key we put in the host persistent ring. Revocation uses
    // a separate session-only key, so no UNLINK is needed for cleanup.
    p.check(
        "invalidate replacement",
        ctl(p, INVALIDATE, replacement, 0, 0, 0) == 0,
    );
    p.check(
        "replacement collected",
        collected(p, session, replacement, &name),
    );
    let revoked = add(p, session, &name, b"revoked");
    p.require("session-only revocation key", revoked > 0);
    p.check("revoke", ctl(p, REVOKE, revoked, 0, 0, 0) == 0);
    p.check(
        "revoked read",
        ctl(p, READ, revoked, 0, 0, 0) == neg(EKEYREVOKED),
    );
    p.check(
        "revoked update",
        ctl(p, UPDATE, revoked, b"v".as_ptr() as i64, 1, 0) == neg(EKEYREVOKED),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/keys_session",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_add_key,
        Syscall::N_request_key,
        Syscall::N_keyctl,
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_getpid,
    ],
    needs: &[Need::Unprivileged, Need::Keys],
    ..DEFAULTS
};
