//! mem/numa — memory policy on a host with one memory node (man 2
//! set_mempolicy, get_mempolicy, mbind, move_pages, migrate_pages,
//! set_mempolicy_home_node; mm/mempolicy.c, mm/migrate.c):
//!
//! * the task policy starts `MPOL_DEFAULT` with an empty mask; `MPOL_BIND`
//!   to the allowed node reads back; `MPOL_PREFERRED` with no node is local
//!   allocation (`MPOL_LOCAL`); `MPOL_DEFAULT` with a node, an unknown mode,
//!   `MPOL_BIND` with no node or with a node that has no memory are `EINVAL`;
//! * `mbind` sets a range's policy (`MPOL_F_ADDR` reads it back;
//!   `MPOL_F_NODE` names the node of a touched page); a misaligned range or
//!   an unknown flag is `EINVAL`, a range with a hole `EFAULT`;
//! * `move_pages` without target nodes reports a touched page's node and
//!   `-EFAULT` for an unmapped address (a page never touched answers
//!   `-EFAULT` or `-ENOENT` by kernel version, so it is not asked); moving
//!   to the node a page is on succeeds; a node that has no memory is
//!   `ENODEV`; an unknown flag `EINVAL`;
//! * `migrate_pages` between the allowed node and itself moves nothing (0);
//!   a pid that does not exist is `ESRCH`;
//! * `set_mempolicy_home_node` needs a range whose policy is `MPOL_BIND` or
//!   `MPOL_PREFERRED_MANY` (another policy is `EOPNOTSUPP`, none of its own
//!   `ENOENT`) and refuses a flag or a node that is not online (`EINVAL`).
//!
//! The allowed node is the host's (`MPOL_F_MEMS_ALLOWED`); the scenario
//! needs exactly one, so node numbers are compared as it answers them.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `get_mempolicy` flags (uapi/linux/mempolicy.h).
const MPOL_F_NODE: u64 = 1 << 0;
const MPOL_F_ADDR: u64 = 1 << 1;
const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
/// `mbind`/`move_pages` flags.
const MPOL_MF_STRICT: u32 = 1 << 0;
const MPOL_MF_MOVE: u32 = 1 << 1;
/// A mode and a flag no kernel defines: the modes stop at
/// `MPOL_WEIGHTED_INTERLEAVE` (6, 6.9); the `mbind` flags at
/// `MPOL_MF_LAZY` (1 << 3, internal) and the mode flags live in bits 13-15.
const UNKNOWN_MODE: i32 = 99;
const UNKNOWN_FLAG: u32 = 1 << 10;
/// A node number no host has memory on (`MAX_NUMNODES` is 1024 at most).
const NO_SUCH_NODE: u32 = 1023;
/// `MPOL_LOCAL` (uapi/linux/mempolicy.h).
const LOCAL: i32 = 4;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, _, allowed) = p.get_mempolicy(&null, MPOL_F_MEMS_ALLOWED, true);
    p.require("read the allowed nodes", r == 0 && allowed.len() == 1);
    let node = allowed[0];

    // ---- the task policy ----
    let (r, mode, nodes) = p.get_mempolicy(&null, 0, true);
    p.check(
        "the task policy starts MPOL_DEFAULT with no node",
        r == 0 && mode == MPOL_DEFAULT && nodes.is_empty(),
    );
    p.check(
        "MPOL_BIND to the allowed node",
        p.set_mempolicy(MPOL_BIND, Some(&[node])) == 0,
    );
    let (r, mode, nodes) = p.get_mempolicy(&null, 0, true);
    p.check("reads back", r == 0 && mode == MPOL_BIND && nodes == [node]);
    p.check(
        "MPOL_PREFERRED with no node",
        p.set_mempolicy(MPOL_PREFERRED, None) == 0,
    );
    let (r, mode, _) = p.get_mempolicy(&null, 0, false);
    p.check("is local allocation", r == 0 && mode == LOCAL);
    p.check(
        "MPOL_DEFAULT with a node is EINVAL",
        p.set_mempolicy(MPOL_DEFAULT, Some(&[node])) == neg(EINVAL),
    );
    p.check(
        "an unknown mode is EINVAL",
        p.set_mempolicy(UNKNOWN_MODE, None) == neg(EINVAL),
    );
    p.check(
        "MPOL_BIND with no node is EINVAL",
        p.set_mempolicy(MPOL_BIND, Some(&[])) == neg(EINVAL),
    );
    p.check(
        "MPOL_BIND to a node with no memory is EINVAL",
        p.set_mempolicy(MPOL_BIND, Some(&[NO_SUCH_NODE])) == neg(EINVAL),
    );
    p.check(
        "back to MPOL_DEFAULT",
        p.set_mempolicy(MPOL_DEFAULT, None) == 0,
    );

    // ---- a range's policy ----
    let (r, a) = p.mmap(
        "a",
        &null,
        4 * page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map four pages", r >= 0);
    let a = a.unwrap();
    p.check(
        "mbind MPOL_BIND over two pages",
        p.mbind(&a.at(0), 2 * page, MPOL_BIND, Some(&[node]), 0) == 0,
    );
    let (r, mode, nodes) = p.get_mempolicy(&a.at(0), MPOL_F_ADDR, true);
    p.check(
        "MPOL_F_ADDR reads the range's policy",
        r == 0 && mode == MPOL_BIND && nodes == [node],
    );
    let (r, mode, _) = p.get_mempolicy(&a.at(2 * page), MPOL_F_ADDR, false);
    p.check(
        "the rest of the mapping keeps the default",
        r == 0 && mode == MPOL_DEFAULT,
    );
    a.store(0, 1);
    let (r, on, _) = p.get_mempolicy(&a.at(0), MPOL_F_ADDR | MPOL_F_NODE, false);
    p.check(
        "MPOL_F_NODE names the node of a touched page",
        r == 0 && on == node as i32,
    );
    p.check(
        "mbind with MPOL_MF_STRICT | MPOL_MF_MOVE succeeds",
        p.mbind(
            &a.at(0),
            2 * page,
            MPOL_BIND,
            Some(&[node]),
            MPOL_MF_STRICT | MPOL_MF_MOVE,
        ) == 0,
    );
    p.check(
        "a misaligned range is EINVAL",
        p.mbind(&a.at(1), page, MPOL_BIND, Some(&[node]), 0) == neg(EINVAL),
    );
    p.check(
        "an unknown mbind flag is EINVAL",
        p.mbind(&a.at(0), page, MPOL_BIND, Some(&[node]), UNKNOWN_FLAG) == neg(EINVAL),
    );

    // ---- move_pages, migrate_pages ----
    p.check("unmap the last page", p.munmap(&a.at(3 * page), page) == 0);
    let (r, status) = p.move_pages(0, &[a.at(0), a.at(3 * page)], None, 0);
    p.check(
        "move_pages reports a page's node, and -EFAULT for an unmapped address",
        r == 0 && status == [node as i32, -EFAULT],
    );
    let (r, status) = p.move_pages(0, &[a.at(0)], Some(&[node as i32]), MPOL_MF_MOVE as i32);
    p.check(
        "moving a page to its own node succeeds",
        r == 0 && status == [node as i32],
    );
    p.check(
        "a node with no memory is ENODEV",
        p.move_pages(
            0,
            &[a.at(0)],
            Some(&[NO_SUCH_NODE as i32]),
            MPOL_MF_MOVE as i32,
        )
        .0 == neg(ENODEV),
    );
    p.check(
        "an unknown move_pages flag is EINVAL",
        p.move_pages(0, &[a.at(0)], None, UNKNOWN_FLAG as i32).0 == neg(EINVAL),
    );
    p.check(
        "migrate_pages from the allowed node to itself moves nothing",
        p.migrate_pages(0, &[node], &[node]) == 0,
    );
    p.check(
        "migrate_pages of a pid that does not exist is ESRCH",
        p.migrate_pages(99_999_999, &[node], &[node]) == neg(ESRCH),
    );
    p.check(
        "mbind over a hole is EFAULT",
        p.mbind(&a.at(2 * page), 2 * page, MPOL_BIND, Some(&[node]), 0) == neg(EFAULT),
    );

    // ---- set_mempolicy_home_node ----
    p.check(
        "a home node for a MPOL_BIND range",
        p.set_mempolicy_home_node(&a.at(0), 2 * page, u64::from(node), 0) == 0,
    );
    p.check(
        "a flag is EINVAL",
        p.set_mempolicy_home_node(&a.at(0), 2 * page, u64::from(node), 1) == neg(EINVAL),
    );
    p.check(
        "a node that is not online is EINVAL",
        p.set_mempolicy_home_node(&a.at(0), 2 * page, u64::from(NO_SUCH_NODE), 0) == neg(EINVAL),
    );
    p.check(
        "a range with no policy of its own is ENOENT",
        p.set_mempolicy_home_node(&a.at(2 * page), page, u64::from(node), 0) == neg(ENOENT),
    );
    p.check(
        "mbind MPOL_PREFERRED over the third page",
        p.mbind(&a.at(2 * page), page, MPOL_PREFERRED, Some(&[node]), 0) == 0,
    );
    p.check(
        "a MPOL_PREFERRED range is EOPNOTSUPP",
        p.set_mempolicy_home_node(&a.at(2 * page), page, u64::from(node), 0) == neg(EOPNOTSUPP),
    );
    p.check("unmap the rest", p.munmap(&a.at(0), 3 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/numa",
    run,
    covers: &[
        Syscall::N_get_mempolicy,
        Syscall::N_set_mempolicy,
        Syscall::N_mbind,
        Syscall::N_move_pages,
        Syscall::N_migrate_pages,
        Syscall::N_set_mempolicy_home_node,
    ],
    symbols: &["syscall", "mmap", "munmap"],
    needs: &[Need::OneNumaNode],
    kernel_floor: Some(KernelFloor {
        release: "5.17",
        why: "set_mempolicy_home_node first appears in Linux 5.17 (the registry row carries no date)",
    }),
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::ALL,
        what: "get_mempolicy is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no get_mempolicy wrapper)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall get_mempolicy (nr",
        },
    }],
    ..DEFAULTS
};
