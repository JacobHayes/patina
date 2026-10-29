//! Memory policy on the virtual machine's one memory node: `set_mempolicy`,
//! `get_mempolicy`, `mbind`, `move_pages`, `migrate_pages`,
//! `set_mempolicy_home_node`.
//!
//! The virtual machine has one node, 0, holding all memory. Each thread keeps
//! the policy it set (mode and mode flags; the node mask is always node 0 or
//! empty, so it is derived from the mode), and a new thread inherits its
//! creator's (`dup_task_struct`), as `get_mempolicy` reads it back. A request
//! that names any other node is `EINVAL`.
//!
//! Policy of an address range is not kept: `mbind` with the default policy
//! succeeds (there is nothing to undo), and any other mode stops the run by
//! name rather than succeed and be forgotten, so `MPOL_F_ADDR` truthfully
//! reads the default policy.

use crate::{EFAULT, EINVAL, EPERM};
use std::ffi::c_int;

const MPOL_DEFAULT: u32 = 0;
const MPOL_PREFERRED: u32 = 1;
const MPOL_BIND: u32 = 2;
const MPOL_INTERLEAVE: u32 = 3;
const MPOL_LOCAL: u32 = 4;
#[cfg(test)]
const MPOL_PREFERRED_MANY: u32 = 5;
/// One past the last mode of Linux 6.8 (`MPOL_MAX`).
const MPOL_MAX: u32 = 6;

const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;
const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
const MPOL_F_STATIC_NODES: u32 = 1 << 15;
/// `MPOL_MODE_FLAGS`: the flags a mode argument carries.
const MPOL_MODE_FLAGS: u32 = MPOL_F_NUMA_BALANCING | MPOL_F_RELATIVE_NODES | MPOL_F_STATIC_NODES;

const MPOL_F_NODE: u64 = 1 << 0;
const MPOL_F_ADDR: u64 = 1 << 1;
const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
/// The one node, as a node mask's first word.
const NODE0: u64 = 1;
const PAGE: usize = crate::mem::PAGE;

/// A thread's memory policy: the mode and its mode flags, as
/// `get_mempolicy` returns them (`mode | flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    mode: u32,
    flags: u32,
}

impl Policy {
    /// `MPOL_DEFAULT`, which every thread starts with.
    pub(crate) const DEFAULT: Policy = Policy {
        mode: MPOL_DEFAULT,
        flags: 0,
    };

    /// A bind policy on node 0, for the tests that inherit one.
    #[cfg(test)]
    pub(crate) fn bound_to_node_zero() -> Policy {
        Policy {
            mode: MPOL_BIND,
            flags: 0,
        }
    }

    /// The node mask `get_mempolicy` reads for it: node 0 for a mode that
    /// names nodes, none for the default and local policies.
    fn nodes(self) -> u64 {
        match self.mode {
            MPOL_DEFAULT | MPOL_LOCAL => 0,
            _ => NODE0,
        }
    }
}

fn fail(errno: c_int) -> i64 {
    -i64::from(errno)
}

/// Which nodes a caller's node mask (`maxnode - 1` bits, as `get_nodes` reads
/// it) names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nodes {
    None,
    Zero,
    Other,
}

/// The nodes a caller's mask names, or the errno of a malformed one.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
unsafe fn read_nodes(mask: *const u64, maxnode: u64) -> Result<Nodes, c_int> {
    let bits = maxnode.wrapping_sub(1);
    if bits == 0 || mask.is_null() {
        return Ok(Nodes::None);
    }
    if bits > (PAGE as u64) * 8 {
        return Err(EINVAL);
    }
    let (mut zero, mut other) = (false, false);
    for index in 0..bits.div_ceil(64) as usize {
        // SAFETY: per this function's contract.
        let mut word = unsafe { mask.add(index).read_unaligned() };
        let covered = (bits - 64 * index as u64).min(64);
        if covered < 64 {
            word &= (1u64 << covered) - 1;
        }
        if index == 0 {
            zero = word & NODE0 != 0;
            other |= word & !NODE0 != 0;
        } else {
            other |= word != 0;
        }
    }
    Ok(match (zero, other) {
        (_, true) => Nodes::Other,
        (true, false) => Nodes::Zero,
        (false, false) => Nodes::None,
    })
}

/// `sanitize_mpol_flags` and `mpol_new`: the policy a `mode` argument and
/// node mask ask for, or the errno that refuses them. A node other than 0
/// names a node the machine lacks (`EINVAL`).
fn policy_for(mode: i32, nodes: Nodes) -> Result<Policy, c_int> {
    let mode = mode as u32;
    let flags = mode & MPOL_MODE_FLAGS;
    let mode = mode & !MPOL_MODE_FLAGS;
    if mode >= MPOL_MAX
        || (flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0)
        || (flags & MPOL_F_NUMA_BALANCING != 0 && mode != MPOL_BIND)
    {
        return Err(EINVAL);
    }
    if nodes == Nodes::Other && flags & MPOL_F_RELATIVE_NODES == 0 {
        return Err(EINVAL);
    }
    let unplaced = flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0;
    match mode {
        // The default policy takes no nodes, and keeps no flags.
        MPOL_DEFAULT if nodes != Nodes::None => Err(EINVAL),
        MPOL_DEFAULT => Ok(Policy::DEFAULT),
        // A preferred policy with no node is the local one.
        MPOL_PREFERRED if nodes == Nodes::None && unplaced => Err(EINVAL),
        MPOL_PREFERRED if nodes == Nodes::None => Ok(Policy {
            mode: MPOL_LOCAL,
            flags,
        }),
        MPOL_LOCAL if nodes != Nodes::None || unplaced => Err(EINVAL),
        MPOL_LOCAL => Ok(Policy { mode, flags }),
        _ if nodes == Nodes::None => Err(EINVAL),
        _ => Ok(Policy { mode, flags }),
    }
}

/// `set_mempolicy(2)`: the calling thread's policy.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn set_mempolicy(mode: i32, mask: *const u64, maxnode: u64) -> i64 {
    // SAFETY: per this function's contract.
    let nodes = match unsafe { read_nodes(mask, maxnode) } {
        Ok(nodes) => nodes,
        Err(errno) => return fail(errno),
    };
    match policy_for(mode, nodes) {
        // The mask a relative policy was given reads back as given, and only
        // node 0's survives here: not modeled.
        Ok(Policy { flags, .. }) if flags & MPOL_F_RELATIVE_NODES != 0 => crate::trap_fatal(
            "set_mempolicy with MPOL_F_RELATIVE_NODES is not modeled; failing closed",
        ),
        Ok(policy) => {
            crate::thread::sched::set_current_mempolicy(policy);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `mbind(2)`: the default policy over a range succeeds (a range's policy is
/// not kept, so there is none to undo); any other policy stops the run.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn mbind(
    start: usize,
    len: usize,
    mode: i32,
    mask: *const u64,
    maxnode: u64,
    _flags: u32,
) -> i64 {
    if !start.is_multiple_of(PAGE) {
        return fail(EINVAL);
    }
    // SAFETY: per this function's contract.
    let nodes = match unsafe { read_nodes(mask, maxnode) } {
        Ok(nodes) => nodes,
        Err(errno) => return fail(errno),
    };
    match policy_for(mode, nodes) {
        // An empty range is left alone, whatever policy it was given.
        Ok(_) if len == 0 => 0,
        Ok(Policy::DEFAULT) => 0,
        Ok(_) => crate::trap_fatal(
            "mbind with a policy other than MPOL_DEFAULT is not modeled (per-range memory \
             policy is not kept); failing closed",
        ),
        Err(errno) => fail(errno),
    }
}

/// `get_mempolicy(2)`: the calling thread's policy, or (`MPOL_F_ADDR`) the
/// default policy of the address's range, which no `mbind` can have changed.
///
/// # Safety
/// `mode` must be NULL or writable; `mask` NULL or writable for
/// `maxnode - 1` bits.
pub(crate) unsafe fn get_mempolicy(
    mode: *mut i32,
    mask: *mut u64,
    maxnode: u64,
    addr: usize,
    flags: u64,
) -> i64 {
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return fail(EINVAL);
    }
    let allowed = flags & MPOL_F_MEMS_ALLOWED != 0;
    if allowed && flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
        return fail(EINVAL);
    }
    if allowed {
        // Only the allowed nodes are answered: no policy, so no mode and no
        // address to check.
        // SAFETY: per this function's contract.
        return unsafe { write_policy(mode, mask, maxnode, 0, NODE0) };
    }
    if addr != 0 && flags & MPOL_F_ADDR == 0 {
        return fail(EINVAL);
    }
    let task = crate::thread::sched::current_mempolicy();
    let (policy, value) = if flags & MPOL_F_ADDR != 0 {
        // The node holding the address's page is node 0.
        (
            Policy::DEFAULT,
            if flags & MPOL_F_NODE != 0 {
                0
            } else {
                Policy::DEFAULT.mode
            },
        )
    } else if flags & MPOL_F_NODE != 0 {
        // Only an interleave policy has a next node to name; it is node 0.
        if task.mode != MPOL_INTERLEAVE {
            return fail(EINVAL);
        }
        (task, 0)
    } else {
        (task, task.mode | task.flags)
    };
    // SAFETY: per this function's contract.
    unsafe { write_policy(mode, mask, maxnode, value, policy.nodes()) }
}

/// Write `get_mempolicy`'s results: the mode (or node) and the node mask.
///
/// # Safety
/// `mode` must be NULL or writable; `mask` NULL or writable for
/// `maxnode - 1` bits.
unsafe fn write_policy(
    mode: *mut i32,
    mask: *mut u64,
    maxnode: u64,
    value: u32,
    nodes: u64,
) -> i64 {
    // SAFETY: per this function's contract.
    unsafe {
        if !mode.is_null() {
            mode.write(value as i32);
        }
        if !mask.is_null() {
            let bytes = maxnode.saturating_sub(1).div_ceil(64) * 8;
            if bytes > PAGE as u64 {
                return fail(EINVAL);
            }
            for index in 0..(bytes / 8) as usize {
                mask.add(index)
                    .write_unaligned(if index == 0 { nodes } else { 0 });
            }
        }
    }
    0
}

/// `move_pages(2)`: every page is on node 0, so a query reads node 0 for each
/// page and a move to node 0 is a no-op; any other node is `EINVAL`.
///
/// # Safety
/// `pages` must be readable for `count` addresses, `nodes` NULL or readable
/// for `count` nodes, `status` writable for `count` entries.
pub(crate) unsafe fn move_pages(
    _pid: i32,
    count: usize,
    _pages: *const usize,
    nodes: *const i32,
    status: *mut i32,
    _flags: i32,
) -> i64 {
    if count != 0 && status.is_null() {
        return fail(EFAULT);
    }
    for index in 0..count {
        // SAFETY: per this function's contract.
        unsafe {
            if !nodes.is_null() && nodes.add(index).read_unaligned() != 0 {
                return fail(EINVAL);
            }
            status.add(index).write_unaligned(0);
        }
    }
    0
}

/// `migrate_pages(2)`: nothing moves on one node; a target elsewhere is
/// refused.
///
/// # Safety
/// `old` and `new` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn migrate_pages(
    _pid: i32,
    maxnode: u64,
    old: *const u64,
    new: *const u64,
) -> i64 {
    // SAFETY: per this function's contract.
    unsafe {
        if let Err(errno) = read_nodes(old, maxnode) {
            return fail(errno);
        }
        match read_nodes(new, maxnode) {
            Ok(Nodes::Other) => fail(EPERM),
            Ok(_) => 0,
            Err(errno) => fail(errno),
        }
    }
}

/// `set_mempolicy_home_node(2)`: home node 0 only.
pub(crate) fn set_mempolicy_home_node(_start: usize, _len: usize, home: u64, flags: u64) -> i64 {
    if flags != 0 || home != 0 {
        return fail(EINVAL);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_names_node_zero_or_nothing() {
        assert_eq!(policy_for(0, Nodes::None), Ok(Policy::DEFAULT));
        assert_eq!(policy_for(0, Nodes::Zero), Err(EINVAL));
        assert_eq!(
            policy_for(MPOL_BIND as i32, Nodes::Zero).map(Policy::nodes),
            Ok(NODE0)
        );
        assert_eq!(policy_for(MPOL_BIND as i32, Nodes::None), Err(EINVAL));
        assert_eq!(policy_for(MPOL_BIND as i32, Nodes::Other), Err(EINVAL));
        assert_eq!(policy_for(MPOL_LOCAL as i32, Nodes::Zero), Err(EINVAL));
        assert_eq!(policy_for(MPOL_MAX as i32, Nodes::Zero), Err(EINVAL));
    }

    #[test]
    fn a_preferred_policy_without_a_node_is_the_local_one() {
        let local = policy_for(MPOL_PREFERRED as i32, Nodes::None).unwrap();
        assert_eq!((local.mode, local.nodes()), (MPOL_LOCAL, 0));
        let flagged = (MPOL_PREFERRED | MPOL_F_STATIC_NODES) as i32;
        assert_eq!(policy_for(flagged, Nodes::None), Err(EINVAL));
        assert_eq!(
            policy_for(flagged, Nodes::Zero).unwrap().flags,
            MPOL_F_STATIC_NODES
        );
    }

    #[test]
    fn mode_flags_must_agree_with_the_mode() {
        let both = (MPOL_BIND | MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) as i32;
        assert_eq!(policy_for(both, Nodes::Zero), Err(EINVAL));
        let balancing = |mode: u32| (mode | MPOL_F_NUMA_BALANCING) as i32;
        assert!(policy_for(balancing(MPOL_BIND), Nodes::Zero).is_ok());
        assert_eq!(
            policy_for(balancing(MPOL_INTERLEAVE), Nodes::Zero),
            Err(EINVAL)
        );
        assert_eq!(
            policy_for(balancing(MPOL_PREFERRED_MANY), Nodes::Zero),
            Err(EINVAL)
        );
    }

    #[test]
    fn a_node_named_past_the_first_kilobit_is_refused() {
        let mut mask = [0u64; 17];
        mask[16] = 1;
        // SAFETY: the mask covers the 1088 bits named.
        unsafe {
            assert_eq!(read_nodes(mask.as_ptr(), 1089), Ok(Nodes::Other));
        }
    }

    #[test]
    fn the_default_range_policy_binds_and_any_other_stops_by_name() {
        // SAFETY: the masks outlive the calls and cover the bits named.
        unsafe {
            assert_eq!(mbind(0, 4096, 0, std::ptr::null(), 0, 0), 0);
            assert_eq!(mbind(0, 4096, 0, &1u64, 65, 0), fail(EINVAL));
            assert_eq!(mbind(0, 4096, 2, &4u64, 65, 0), fail(EINVAL));
            assert_eq!(mbind(1, 4096, 0, std::ptr::null(), 0, 0), fail(EINVAL));
            // An empty range takes any valid policy without effect.
            assert_eq!(mbind(0, 0, 2, &1u64, 65, 0), 0);
        }
    }

    #[test]
    fn move_pages_without_a_status_buffer_is_efault() {
        let page = 0usize;
        // SAFETY: one readable page address; the status is NULL.
        unsafe {
            assert_eq!(
                move_pages(0, 1, &page, std::ptr::null(), std::ptr::null_mut(), 0),
                fail(EFAULT)
            );
        }
    }

    #[test]
    fn pages_live_on_node_zero() {
        let pages = [0usize, 4096];
        let mut status = [5i32; 2];
        // SAFETY: the arrays cover `count` entries.
        unsafe {
            assert_eq!(
                move_pages(
                    0,
                    2,
                    pages.as_ptr(),
                    std::ptr::null(),
                    status.as_mut_ptr(),
                    0
                ),
                0
            );
            assert_eq!(status, [0, 0]);
            assert_eq!(
                move_pages(
                    0,
                    2,
                    pages.as_ptr(),
                    [0, 1].as_ptr(),
                    status.as_mut_ptr(),
                    0
                ),
                fail(EINVAL)
            );
        }
        assert_eq!(set_mempolicy_home_node(0, 4096, 1, 0), fail(EINVAL));
    }
}
