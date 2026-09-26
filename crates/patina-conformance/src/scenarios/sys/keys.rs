//! sys/keys — the kernel's key retention service (security/keys/keyctl.c),
//! which an unprivileged caller may use for its own keys:
//!
//! * `add_key` refuses a payload of a megabyte or more (`EINVAL`) before it
//!   reads anything, then the type: unreadable `EFAULT`, empty `EINVAL`,
//!   internal (a leading `.`) `EPERM`; a keyring described with a leading
//!   `.` is `EPERM`; a keyring id that names none (0) is `EINVAL`; a type no
//!   module registers is `ENODEV`;
//! * a `user` key added to the process keyring (created on demand) answers a
//!   serial; adding the same type and description again updates that key in
//!   place (same serial, new payload); `request_key` finds it by type and
//!   description without an upcall (no callout information), and misses
//!   anything else with `ENOKEY`;
//! * `keyctl`: `KEYCTL_READ` answers the payload, and of the process
//!   keyring the serials it links (the one key); `KEYCTL_DESCRIBE`
//!   `type;uid;gid;perm;description` with the caller's ids and the default
//!   permissions `3f010000`, into too little room only its length; handing the key to another user or to a group
//!   the caller is not in needs `CAP_SYS_ADMIN` (`keyctl_chown_key`:
//!   `EACCES`), to itself nothing; a thread keyring not asked to be created
//!   is `ENOKEY`; `KEYCTL_CAPABILITIES` answers the kernel's two bytes and
//!   clears the rest of the room; an unknown operation `EOPNOTSUPP`; a
//!   revoked key reads `EKEYREVOKED`;
//! * the process keyring belongs to the credentials of the thread that made
//!   it, and of the threads created after (`install_process_keyring`,
//!   `copy_creds`): a thread that already existed has none (`ENOKEY`), does
//!   not possess the keys in it (reading one is `EACCES`: their owner may
//!   only view them), and its own `add_key` makes it a keyring and a new
//!   key; a thread created after the keyring reads them.
//!
//! Every key lives in a process keyring, which dies with the probe. The
//! serial is a random number, so it compares as a label; the description's
//! length depends on the ids, so it is checked, not recorded.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CStr;

const KEY_SPEC_THREAD_KEYRING: i64 = -1;
const KEY_SPEC_PROCESS_KEYRING: i64 = -2;
const KEYCTL_GET_KEYRING_ID: i64 = 0;
const KEYCTL_CHOWN: i64 = 4;
const KEYCTL_DESCRIBE: i64 = 6;
const KEYCTL_REVOKE: i64 = 3;
const KEYCTL_READ: i64 = 11;
const KEYCTL_CAPABILITIES: i64 = 31;
/// No `KEYCTL_*` operation.
const KEYCTL_UNKNOWN: i64 = 9999;
/// A group no account is in (gid 0 may hold the caller on some hosts).
const NO_GROUP: i64 = 0x7fff_fff0;
/// One byte past the largest payload `add_key` takes.
const TOO_BIG: i64 = 1024 * 1024;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    std::thread::scope(|scope| {
        // A thread created before any keyring exists.
        let (go, wait) = std::sync::mpsc::channel::<i64>();
        let older = scope.spawn(move || {
            if let Ok(serial) = wait.recv() {
                older_thread(p, serial);
            }
        });
        let serial = main_thread(p);
        let _ = go.send(serial);
        let _ = older.join();
        let newer = scope.spawn(move || {
            let mut buf = [0u8; 8];
            p.call_observed(
                Syscall::N_keyctl,
                [
                    KEYCTL_READ,
                    serial,
                    buf.as_mut_ptr() as i64,
                    buf.len() as i64,
                    0,
                    0,
                ],
            )
        });
        p.check(
            "a thread created after the keyring possesses its keys",
            newer.join().ok() == Some(1),
        );
        rest(p, serial);
    });
}

/// Record `r` as a key's serial, a label.
fn key(p: &Probe, r: i64) -> i64 {
    p.rec
        .event("key", r)
        .norm("ret", Norm::Relative("key"))
        .emit();
    r
}

/// `add_key("user", description, payload, ring)`, unrecorded.
fn add_user_key(p: &Probe, description: &CStr, payload: &[u8], ring: i64) -> i64 {
    p.call_unrecorded(
        Syscall::N_add_key,
        [
            c"user".as_ptr() as i64,
            description.as_ptr() as i64,
            payload.as_ptr() as i64,
            payload.len() as i64,
            ring,
            0,
        ],
    )
}

/// On a thread that existed before the process keyring: `serial` is a key
/// in the keyring another thread made.
fn older_thread(p: &Probe, serial: i64) {
    let mut buf = [0u8; 8];
    p.check(
        "a thread older than the process keyring has none",
        p.call_observed(
            Syscall::N_keyctl,
            [KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0, 0, 0, 0],
        ) == neg(ENOKEY),
    );
    p.check(
        "nor possesses the keys in it: reading one is EACCES",
        p.call_observed(
            Syscall::N_keyctl,
            [
                KEYCTL_READ,
                serial,
                buf.as_mut_ptr() as i64,
                buf.len() as i64,
                0,
                0,
            ],
        ) == neg(EACCES),
    );
    let own = key(
        p,
        add_user_key(p, c"patina:key", b"o", KEY_SPEC_PROCESS_KEYRING),
    );
    p.check(
        "its own add_key makes it a keyring and a new key",
        own > 0 && own != serial,
    );
}

/// The main thread's rows up to its first key, whose serial it answers.
fn main_thread(p: &Probe) -> i64 {
    let add_key = |kind: *const c_char, description: &CStr, payload: &[u8], ring: i64| {
        p.call_observed(
            Syscall::N_add_key,
            [
                kind as i64,
                description.as_ptr() as i64,
                payload.as_ptr() as i64,
                payload.len() as i64,
                ring,
                0,
            ],
        )
    };
    let user = c"user".as_ptr();
    let name = c"patina:key";
    let big = p.call_observed(
        Syscall::N_add_key,
        [0, 0, 0, TOO_BIG, KEY_SPEC_PROCESS_KEYRING, 0],
    );
    p.check(
        "a payload of a megabyte is EINVAL before anything is read",
        big == neg(EINVAL),
    );
    p.check(
        "an unreadable type is EFAULT",
        add_key(std::ptr::null(), name, b"v", KEY_SPEC_PROCESS_KEYRING) == neg(EFAULT),
    );
    p.check(
        "an empty type is EINVAL",
        add_key(c"".as_ptr(), name, b"v", KEY_SPEC_PROCESS_KEYRING) == neg(EINVAL),
    );
    p.check(
        "an internal type is EPERM",
        add_key(c".user".as_ptr(), name, b"v", KEY_SPEC_PROCESS_KEYRING) == neg(EPERM),
    );
    p.check(
        "a keyring described with a leading dot is EPERM",
        add_key(
            c"keyring".as_ptr(),
            c".patina",
            b"",
            KEY_SPEC_PROCESS_KEYRING,
        ) == neg(EPERM),
    );
    p.check(
        "a keyring id that names none is EINVAL",
        add_key(user, name, b"v", 0) == neg(EINVAL),
    );
    p.check(
        "a type no module registers is ENODEV",
        add_key(
            c"patina_no_such_type".as_ptr(),
            name,
            b"v",
            KEY_SPEC_PROCESS_KEYRING,
        ) == neg(ENODEV),
    );

    let serial = key(p, add_user_key(p, name, b"v", KEY_SPEC_PROCESS_KEYRING));
    p.require("a user key in the process keyring", serial > 0);
    serial
}

/// The main thread's rows from its first key on.
fn rest(p: &Probe, serial: i64) {
    let user = c"user".as_ptr();
    let name = c"patina:key";
    let again = key(p, add_user_key(p, name, b"w", KEY_SPEC_PROCESS_KEYRING));
    p.check(
        "adding the same type and description updates that key",
        again == serial,
    );
    let request = |description: &CStr| [user as i64, description.as_ptr() as i64, 0, 0, 0, 0];
    p.check(
        "request_key finds it without an upcall",
        key(p, p.call_unrecorded(Syscall::N_request_key, request(name))) == serial,
    );
    p.check(
        "request_key of a description no key has is ENOKEY",
        p.call_observed(Syscall::N_request_key, request(c"patina:missing")) == neg(ENOKEY),
    );

    let mut buf = [0u8; 256];
    let keyctl = |op: i64, a2: i64, a3: i64, a4: i64| {
        p.call_observed(Syscall::N_keyctl, [op, a2, a3, a4, 0, 0])
    };
    p.check(
        "KEYCTL_READ answers the updated payload",
        keyctl(
            KEYCTL_READ,
            serial,
            buf.as_mut_ptr() as i64,
            buf.len() as i64,
        ) == 1
            && buf[0] == b'w',
    );
    let mut linked = [0i32; 2];
    p.check(
        "KEYCTL_READ of the process keyring answers the serial it links",
        keyctl(
            KEYCTL_READ,
            KEY_SPEC_PROCESS_KEYRING,
            linked.as_mut_ptr() as i64,
            std::mem::size_of_val(&linked) as i64,
        ) == 4
            && i64::from(linked[0]) == serial,
    );
    let uid = p.getuid();
    let gid = p.getgid();
    let described = p.call_unrecorded(
        Syscall::N_keyctl,
        [
            KEYCTL_DESCRIBE,
            serial,
            buf.as_mut_ptr() as i64,
            buf.len() as i64,
            0,
            0,
        ],
    );
    let expected = format!("user;{uid};{gid};3f010000;patina:key");
    p.check(
        "KEYCTL_DESCRIBE answers type, the caller's ids, the default permissions and the description",
        described == expected.len() as i64 + 1
            && CStr::from_bytes_until_nul(&buf).map(CStr::to_bytes) == Ok(expected.as_bytes()),
    );
    buf.fill(0);
    // The length depends on the ids, so it is checked, not recorded.
    let short = p.call_unrecorded(
        Syscall::N_keyctl,
        [KEYCTL_DESCRIBE, serial, buf.as_mut_ptr() as i64, 4, 0, 0],
    );
    p.check(
        "KEYCTL_DESCRIBE into too little room answers the length and copies nothing",
        short == expected.len() as i64 + 1 && buf[..4] == [0; 4],
    );
    p.check(
        "handing the key to another user is EACCES (no CAP_SYS_ADMIN)",
        keyctl(KEYCTL_CHOWN, serial, 0, -1) == neg(EACCES),
    );
    p.check(
        "handing it to a group the caller is not in is EACCES",
        keyctl(KEYCTL_CHOWN, serial, -1, NO_GROUP) == neg(EACCES),
    );
    p.check(
        "handing it to its own user changes nothing",
        keyctl(KEYCTL_CHOWN, serial, uid, -1) == 0,
    );
    p.check(
        "a thread keyring not asked to be created is ENOKEY",
        keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_THREAD_KEYRING, 0, 0) == neg(ENOKEY),
    );
    let mut capabilities = [0xffu8; 4];
    let answered = keyctl(
        KEYCTL_CAPABILITIES,
        capabilities.as_mut_ptr() as i64,
        capabilities.len() as i64,
        0,
    );
    p.rec
        .event("keyctl_capabilities", 0)
        .field(
            "bytes",
            format!("{:02x}{:02x}", capabilities[0], capabilities[1]).as_str(),
        )
        .emit();
    p.check(
        "KEYCTL_CAPABILITIES answers its two bytes and clears the rest of the room",
        answered == 2 && capabilities[2..] == [0, 0],
    );
    p.check(
        "an unknown operation is EOPNOTSUPP",
        keyctl(KEYCTL_UNKNOWN, 0, 0, 0) == neg(EOPNOTSUPP),
    );
    p.check("KEYCTL_REVOKE", keyctl(KEYCTL_REVOKE, serial, 0, 0) == 0);
    p.check(
        "a revoked key reads EKEYREVOKED",
        keyctl(
            KEYCTL_READ,
            serial,
            buf.as_mut_ptr() as i64,
            buf.len() as i64,
        ) == neg(EKEYREVOKED),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/keys",
    run,
    // glibc has no wrapper for these rows (libkeyutils does): the libc
    // spelling would be `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_add_key,
        Syscall::N_request_key,
        Syscall::N_keyctl,
        Syscall::N_getuid,
        Syscall::N_getgid,
    ],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
