//! cred/ids — an unprivileged caller's user and group ids (kernel/sys.c):
//!
//! * the effective ids equal the real ones, and `getresuid`/`getresgid`
//!   answer the same id three times;
//! * `setuid`/`setgid` to the caller's own id succeed, to another are
//!   `EPERM`, to -1 `EINVAL`;
//! * `setreuid`/`setregid` with -1 change nothing and succeed, to the own
//!   ids succeed, and either id another is `EPERM`;
//! * `setresuid`/`setresgid` likewise (-1 is "unchanged" in any position),
//!   and a refusal leaves all three ids as they were;
//! * `setfsuid`/`setfsgid` never fail loudly: each answers the previous
//!   filesystem id — to the own id, to another (refused, unchanged), and to
//!   -1 (a pure query).
//!
//! Ids are recorded by relation (`Norm::Identity`): the virtual kernel runs
//! the guest as its identity knob, the host as whoever runs the test.
//! "Another" id is the caller's plus one, which it does not hold.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::observe::Id;
use crate::probe::{Cred, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let uid = p.getuid() as u32;
    let gid = p.getgid() as u32;
    p.check(
        "the effective uid is the real one",
        p.geteuid() == i64::from(uid),
    );
    p.check(
        "the effective gid is the real one",
        p.getegid() == i64::from(gid),
    );
    let (r, ids) = p.getres(Syscall::N_getresuid, Id::User);
    p.check(
        "getresuid answers the uid three times",
        r == 0 && ids == [uid; 3],
    );
    let (r, ids) = p.getres(Syscall::N_getresgid, Id::Group);
    p.check(
        "getresgid answers the gid three times",
        r == 0 && ids == [gid; 3],
    );

    for (row, own, kind) in [
        (Syscall::N_setuid, uid, Id::User),
        (Syscall::N_setgid, gid, Id::Group),
    ] {
        p.check(
            "setting the own id succeeds",
            p.set_id(row, Cred::Id(own), kind) == 0,
        );
        p.check(
            "setting another is EPERM",
            p.set_id(row, Cred::Id(own + 1), kind) == neg(EPERM),
        );
        p.check(
            "-1 is EINVAL",
            p.set_id(row, Cred::Unchanged, kind) == neg(EINVAL),
        );
    }

    for (row, own, kind) in [
        (Syscall::N_setreuid, uid, Id::User),
        (Syscall::N_setregid, gid, Id::Group),
    ] {
        let (own, other) = (Cred::Id(own), Cred::Id(own + 1));
        p.check(
            "-1 twice changes nothing",
            p.set_re(row, Cred::Unchanged, Cred::Unchanged, kind) == 0,
        );
        p.check("the own ids succeed", p.set_re(row, own, own, kind) == 0);
        p.check(
            "another real id is EPERM",
            p.set_re(row, other, Cred::Unchanged, kind) == neg(EPERM),
        );
        p.check(
            "another effective id is EPERM",
            p.set_re(row, Cred::Unchanged, other, kind) == neg(EPERM),
        );
    }

    for (set, get, own, kind) in [
        (Syscall::N_setresuid, Syscall::N_getresuid, uid, Id::User),
        (Syscall::N_setresgid, Syscall::N_getresgid, gid, Id::Group),
    ] {
        let (mine, other) = (Cred::Id(own), Cred::Id(own + 1));
        p.check(
            "-1 thrice changes nothing",
            p.set_res(set, [Cred::Unchanged; 3], kind) == 0,
        );
        p.check("the own ids succeed", p.set_res(set, [mine; 3], kind) == 0);
        p.check(
            "another saved id is EPERM",
            p.set_res(set, [Cred::Unchanged, Cred::Unchanged, other], kind) == neg(EPERM),
        );
        p.check(
            "another effective id among own ones is EPERM",
            p.set_res(set, [mine, other, mine], kind) == neg(EPERM),
        );
        let (r, ids) = p.getres(get, kind);
        p.check(
            "a refusal left the ids as they were",
            r == 0 && ids == [own; 3],
        );
    }

    for (row, own, kind) in [
        (Syscall::N_setfsuid, uid, Id::User),
        (Syscall::N_setfsgid, gid, Id::Group),
    ] {
        p.check(
            "the own id answers the previous one",
            p.set_id(row, Cred::Id(own), kind) == i64::from(own),
        );
        p.check(
            "another is refused silently, answering the previous one",
            p.set_id(row, Cred::Id(own + 1), kind) == i64::from(own),
        );
        p.check(
            "-1 queries: still the own id",
            p.set_id(row, Cred::Unchanged, kind) == i64::from(own),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "cred/ids",
    run,
    covers: &[
        Syscall::N_getuid,
        Syscall::N_getgid,
        Syscall::N_geteuid,
        Syscall::N_getegid,
        Syscall::N_getresuid,
        Syscall::N_getresgid,
        Syscall::N_setuid,
        Syscall::N_setgid,
        Syscall::N_setreuid,
        Syscall::N_setregid,
        Syscall::N_setresuid,
        Syscall::N_setresgid,
        Syscall::N_setfsuid,
        Syscall::N_setfsgid,
    ],
    symbols: &[
        "getuid", "getgid", "geteuid", "getegid", "setuid", "setgid", "syscall",
    ],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
