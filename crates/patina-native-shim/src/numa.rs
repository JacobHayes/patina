//! Memory policy on the virtual machine's one memory node (mm/mempolicy.c,
//! mm/migrate.c): `set_mempolicy`, `get_mempolicy`, `mbind`, `move_pages`,
//! `migrate_pages`, `set_mempolicy_home_node`.
//!
//! The virtual machine has one node, 0, online and holding memory; a kernel
//! built for 1024 nodes (`MAX_NUMNODES`, the distributions' `NODES_SHIFT` 10)
//! judges the masks callers pass. A policy is kernel state the caller reads
//! back, so it is kept, not synthesized: the task policy per task (a new
//! thread inherits its creator's), a range's policy with the address space
//! (`crate::mem`), which clips and moves it with `munmap`, `mremap` and fixed
//! mappings as the kernel's per-VMA policy. Pages never move: every page is on
//! node 0, so a migration to it succeeds and one anywhere else is refused by
//! the node checks first. Whether an address is mapped, and a page resident,
//! is the host's answer about the guest's own memory (`mincore`).

use crate::{EFAULT, EINVAL, ENOENT, EOPNOTSUPP, EPERM, ESRCH, SpinMutex};
use std::collections::BTreeMap;
use std::ffi::c_int;

const MPOL_DEFAULT: i32 = 0;
const MPOL_PREFERRED: i32 = 1;
const MPOL_BIND: i32 = 2;
const MPOL_INTERLEAVE: i32 = 3;
const MPOL_LOCAL: i32 = 4;
const MPOL_PREFERRED_MANY: i32 = 5;
/// `MPOL_MAX` at the virtual ABI level (6.8; `MPOL_WEIGHTED_INTERLEAVE` is
/// 6.9).
const MPOL_MAX: i32 = 6;
const MPOL_F_STATIC_NODES: i32 = 1 << 15;
const MPOL_F_RELATIVE_NODES: i32 = 1 << 14;
const MPOL_F_NUMA_BALANCING: i32 = 1 << 13;
const MPOL_MODE_FLAGS: i32 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;
/// `get_mempolicy` flags.
const MPOL_F_NODE: u64 = 1 << 0;
const MPOL_F_ADDR: u64 = 1 << 1;
const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
/// `mbind`/`move_pages` flags.
const MPOL_MF_STRICT: u32 = 1 << 0;
const MPOL_MF_MOVE: u32 = 1 << 1;
const MPOL_MF_MOVE_ALL: u32 = 1 << 2;
const MPOL_MF_VALID: u32 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
const MAX_NUMNODES: u64 = 1024;
/// `nr_node_ids`: the highest possible node plus one.
const NR_NODE_IDS: u64 = 1;
/// The one node, as a node mask's first word.
const NODE0: u64 = 1;
const PAGE: usize = crate::mem::PAGE;
const ENODEV: c_int = crate::ENODEV;

fn fail(errno: c_int) -> i64 {
    -i64::from(errno)
}

/// A memory policy: its mode (`MPOL_LOCAL` for a preferred policy with no
/// node), its mode flags, the nodes it applies (a mask of the one node), the
/// caller's own mask's first word when a mode flag keeps it, and a home node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    mode: i32,
    flags: i32,
    nodes: u64,
    user: u64,
    home: Option<u64>,
}

/// The task policies, by task; a task without one has the default.
static TASKS: SpinMutex<BTreeMap<c_int, Policy>> = SpinMutex::new(BTreeMap::new());

/// A new thread inherits its creator's task policy.
pub(crate) fn spawned(parent: c_int, child: c_int) {
    let mut tasks = TASKS.lock();
    if let Some(policy) = tasks.get(&parent).copied() {
        tasks.insert(child, policy);
    }
}

/// A caller's node mask, as far as one node can tell nodes apart.
#[derive(Clone, Copy)]
struct Nodes {
    /// Any node is set.
    any: bool,
    /// The mask's first word.
    first: u64,
    /// A node other than the one node is set.
    others: bool,
}

/// `get_nodes`: the mask of `maxnode - 1` bits a caller passed; bits past
/// `MAX_NUMNODES` must be clear (the kernel checks the last word).
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
unsafe fn read_nodes(mask: *const u64, maxnode: u64) -> Result<Nodes, c_int> {
    let mut bits = maxnode.wrapping_sub(1);
    let empty = Nodes {
        any: false,
        first: 0,
        others: false,
    };
    if bits == 0 || mask.is_null() {
        return Ok(empty);
    }
    if bits > (PAGE as u64) * 8 {
        return Err(EINVAL);
    }
    if bits > MAX_NUMNODES {
        // SAFETY: per this function's contract.
        let last = unsafe { mask.add(((bits - 1) / 64) as usize).read_unaligned() };
        if last != 0 {
            return Err(EINVAL);
        }
        bits = MAX_NUMNODES;
    }
    let mut nodes = empty;
    for index in 0..bits.div_ceil(64) as usize {
        // SAFETY: per this function's contract.
        let mut word = unsafe { mask.add(index).read_unaligned() };
        let covered = (bits - 64 * index as u64).min(64);
        if covered < 64 {
            word &= (1u64 << covered) - 1;
        }
        if index == 0 {
            nodes.first = word;
            nodes.others |= word & !NODE0 != 0;
        } else {
            nodes.others |= word != 0;
        }
        nodes.any |= word != 0;
    }
    Ok(nodes)
}

/// `sanitize_mpol_flags`: the mode and its flags.
fn sanitize(mode: i32) -> Result<(i32, i32), c_int> {
    let flags = mode & MPOL_MODE_FLAGS;
    let mode = mode & !MPOL_MODE_FLAGS;
    if !(0..MPOL_MAX).contains(&mode)
        || (flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0)
        || (flags & MPOL_F_NUMA_BALANCING != 0 && mode != MPOL_BIND)
    {
        return Err(EINVAL);
    }
    Ok((mode, flags))
}

/// `mpol_new` then `mpol_set_nodemask`: the policy (`None` for the default),
/// or `EINVAL`.
fn policy(mode: i32, flags: i32, requested: Nodes) -> Result<Option<Policy>, c_int> {
    let (any, first) = (requested.any, requested.first);
    let keeps_user = flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0;
    let mode = match mode {
        MPOL_DEFAULT if any => return Err(EINVAL),
        MPOL_DEFAULT => return Ok(None),
        MPOL_PREFERRED if !any && keeps_user => return Err(EINVAL),
        MPOL_PREFERRED if !any => MPOL_LOCAL,
        MPOL_LOCAL if any || keeps_user => return Err(EINVAL),
        MPOL_LOCAL => MPOL_LOCAL,
        _ if !any => return Err(EINVAL),
        mode => mode,
    };
    // Only the one node has memory; a relative mask maps its first bit onto it.
    let nodes = if mode == MPOL_LOCAL {
        0
    } else if flags & MPOL_F_RELATIVE_NODES != 0 {
        NODE0
    } else {
        first & NODE0
    };
    if mode != MPOL_LOCAL && nodes == 0 {
        return Err(EINVAL);
    }
    Ok(Some(Policy {
        mode,
        flags,
        nodes,
        user: if keeps_user { first } else { 0 },
        home: None,
    }))
}

/// `set_mempolicy(2)`.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn set_mempolicy(mode: i32, mask: *const u64, maxnode: u64) -> i64 {
    let (mode, flags) = match sanitize(mode) {
        Ok(sanitized) => sanitized,
        Err(errno) => return fail(errno),
    };
    // SAFETY: per this function's contract.
    let nodes = match unsafe { read_nodes(mask, maxnode) } {
        Ok(nodes) => nodes,
        Err(errno) => return fail(errno),
    };
    match policy(mode, flags, nodes) {
        Ok(policy) => {
            let task = crate::thread::deterministic_thread_id();
            let mut tasks = TASKS.lock();
            match policy {
                Some(policy) => tasks.insert(task, policy),
                None => tasks.remove(&task),
            };
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `get_mempolicy(2)`.
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
    if !mask.is_null() && maxnode < NR_NODE_IDS {
        return fail(EINVAL);
    }
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return fail(EINVAL);
    }
    let (answer, nodes) = if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
            return fail(EINVAL);
        }
        (0, NODE0)
    } else {
        let policy = if flags & MPOL_F_ADDR != 0 {
            if !crate::mem::mapped(addr & !(PAGE - 1), PAGE) {
                return fail(EFAULT);
            }
            crate::mem::policy_at(addr)
        } else if addr != 0 {
            return fail(EINVAL);
        } else {
            TASKS
                .lock()
                .get(&crate::thread::deterministic_thread_id())
                .copied()
        };
        let answer = if flags & MPOL_F_NODE != 0 {
            if flags & MPOL_F_ADDR != 0 {
                // `lookup_node`: the page faulted in (`EFAULT` where no fault
                // reaches it, a `PROT_NONE` page), then its node.
                if !crate::mem::fault_in(addr) {
                    return fail(EFAULT);
                }
                0
            } else if policy.is_some_and(|policy| policy.mode == MPOL_INTERLEAVE) {
                // The next node of the interleave: the only one.
                0
            } else {
                return fail(EINVAL);
            }
        } else {
            policy.map_or(MPOL_DEFAULT, |policy| policy.mode | policy.flags)
        };
        let nodes = policy.map_or(0, |policy| {
            if policy.flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 {
                policy.user
            } else {
                policy.nodes
            }
        });
        (answer, nodes)
    };
    // SAFETY: per this function's contract.
    unsafe {
        if !mode.is_null() {
            mode.write(answer);
        }
        if !mask.is_null() {
            // `copy_nodes_to_user`: the first word, zeros after it.
            let bytes = (maxnode - 1).div_ceil(64) * 8;
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

/// `mbind(2)`.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn mbind(
    start: usize,
    len: usize,
    mode: i32,
    mask: *const u64,
    maxnode: u64,
    flags: u32,
) -> i64 {
    let (mode, mode_flags) = match sanitize(mode) {
        Ok(sanitized) => sanitized,
        Err(errno) => return fail(errno),
    };
    // SAFETY: per this function's contract.
    let nodes = match unsafe { read_nodes(mask, maxnode) } {
        Ok(nodes) => nodes,
        Err(errno) => return fail(errno),
    };
    if flags & !MPOL_MF_VALID != 0 {
        return fail(EINVAL);
    }
    if flags & MPOL_MF_MOVE_ALL != 0 {
        return fail(EPERM);
    }
    if start % PAGE != 0 {
        return fail(EINVAL);
    }
    let Some(len) = len.checked_add(PAGE - 1).map(|len| len & !(PAGE - 1)) else {
        return fail(EINVAL);
    };
    let Some(end) = start.checked_add(len) else {
        return fail(EINVAL);
    };
    if end == start {
        return 0;
    }
    let policy = match policy(mode, mode_flags, nodes) {
        Ok(policy) => policy,
        Err(errno) => return fail(errno),
    };
    // `queue_pages_range`: a range wholly in a hole is EFAULT; a hole inside
    // it only for a policy other than the default.
    if !crate::mem::mapped(start, len) {
        let any = (start..end)
            .step_by(PAGE)
            .any(|page| crate::mem::mapped(page, PAGE));
        if !any || policy.is_some() {
            return fail(EFAULT);
        }
    }
    crate::mem::set_policy(start, end, policy);
    0
}

/// Whose memory a pid names (`find_mm_struct`, `kernel_migrate_pages`): 0,
/// the guest or one of its threads is the guest's; a pid no process has is
/// `ESRCH`; another process is behind the ptrace-mode check
/// (`identity::ptrace_may_access`), which init, root's, refuses the guest
/// (`EPERM`).
fn memory_of(pid: i32) -> Result<(), c_int> {
    match pid {
        0 => Ok(()),
        pid => match crate::identity::lookup(pid) {
            Some((crate::identity::Process::Guest, _)) => Ok(()),
            Some((process, _)) => {
                if crate::identity::ptrace_may_access(crate::identity::credential(), process) {
                    crate::trap_fatal(&format!(
                        "capability {} granted but another process's memory (move_pages, \
                         migrate_pages) is not modeled: the virtual credential holds it, and what \
                         the kernel does for such a caller is outside the model; failing closed",
                        crate::registry::Capability::SysPtrace.name()
                    ))
                }
                Err(EPERM)
            }
            None => Err(ESRCH),
        },
    }
}

/// `move_pages(2)`.
///
/// # Safety
/// `pages` must be readable for `count` addresses, `nodes` NULL or readable
/// for `count` nodes, `status` writable for `count` entries.
pub(crate) unsafe fn move_pages(
    pid: i32,
    count: usize,
    pages: *const usize,
    nodes: *const i32,
    status: *mut i32,
    flags: i32,
) -> i64 {
    if flags as u32 & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        return fail(EINVAL);
    }
    if flags as u32 & MPOL_MF_MOVE_ALL != 0 {
        return fail(EPERM);
    }
    if let Err(errno) = memory_of(pid) {
        return fail(errno);
    }
    if count > 0 && (pages.is_null() || status.is_null()) {
        return fail(EFAULT);
    }
    let mut answers = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: per this function's contract.
        let page = unsafe { pages.add(index).read_unaligned() };
        if !nodes.is_null() {
            // SAFETY: per this function's contract.
            let node = unsafe { nodes.add(index).read_unaligned() };
            // Only node 0 is online.
            if node != 0 {
                return fail(ENODEV);
            }
        }
        answers.push(match crate::mem::resident(page) {
            None => -EFAULT,
            Some(false) => -ENOENT,
            Some(true) => 0,
        });
    }
    for (index, answer) in answers.into_iter().enumerate() {
        // SAFETY: per this function's contract.
        unsafe { status.add(index).write_unaligned(answer) };
    }
    0
}

/// `migrate_pages(2)`: nothing moves on one node.
///
/// # Safety
/// `old` and `new` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn migrate_pages(
    pid: i32,
    maxnode: u64,
    old: *const u64,
    new: *const u64,
) -> i64 {
    // SAFETY: per this function's contract.
    if let Err(errno) = unsafe { read_nodes(old, maxnode) } {
        return fail(errno);
    }
    // SAFETY: as above.
    let new = match unsafe { read_nodes(new, maxnode) } {
        Ok(nodes) => nodes,
        Err(errno) => return fail(errno),
    };
    if let Err(errno) = memory_of(pid) {
        return fail(errno);
    }
    // A target node outside the caller's allowed set needs CAP_SYS_NICE.
    if new.others {
        return fail(EPERM);
    }
    0
}

/// `set_mempolicy_home_node(2)`.
pub(crate) fn set_mempolicy_home_node(start: usize, len: usize, home: u64, flags: u64) -> i64 {
    if flags != 0 {
        return fail(EINVAL);
    }
    if home >= MAX_NUMNODES || home != 0 {
        return fail(EINVAL);
    }
    if start % PAGE != 0 {
        return fail(EINVAL);
    }
    let Some(len) = len.checked_add(PAGE - 1).map(|len| len & !(PAGE - 1)) else {
        return fail(EINVAL);
    };
    let Some(end) = start.checked_add(len) else {
        return fail(EINVAL);
    };
    if end == start {
        return 0;
    }
    let ranges = crate::mem::policies_in(start, end);
    if ranges.is_empty() {
        return fail(ENOENT);
    }
    for (from, to, policy) in ranges {
        if policy.mode != MPOL_BIND && policy.mode != MPOL_PREFERRED_MANY {
            return fail(EOPNOTSUPP);
        }
        crate::mem::set_policy(
            from,
            to,
            Some(Policy {
                home: Some(home),
                ..policy
            }),
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: usize = (MAX_NUMNODES / 64) as usize;

    fn nodes(mask: &[u64; WORDS]) -> Result<Nodes, c_int> {
        // SAFETY: the mask holds MAX_NUMNODES bits, what maxnode asks for.
        unsafe { read_nodes(mask.as_ptr(), MAX_NUMNODES + 1) }
    }

    #[test]
    fn a_mask_names_the_one_node_or_others() {
        let mut mask = [0u64; WORDS];
        assert!(!nodes(&mask).unwrap().any);
        mask[0] = NODE0;
        let read = nodes(&mask).unwrap();
        assert!(read.any && !read.others);
        mask[WORDS - 1] = 1 << 63;
        assert!(nodes(&mask).unwrap().others);
        // A NULL mask or a maxnode of 1 is empty; a maxnode past a page of
        // bits is refused.
        // SAFETY: NULL and a zero-bit read touch nothing.
        unsafe {
            assert!(!read_nodes(std::ptr::null(), 1025).unwrap().any);
            assert!(!read_nodes(mask.as_ptr(), 1).unwrap().any);
            assert_eq!(
                read_nodes(mask.as_ptr(), (PAGE as u64) * 8 + 2).err(),
                Some(EINVAL)
            );
        }
    }

    #[test]
    fn policies_are_built_as_mpol_new_judges_them() {
        let one = Nodes {
            any: true,
            first: NODE0,
            others: false,
        };
        let elsewhere = Nodes {
            any: true,
            first: 0,
            others: true,
        };
        let none = Nodes {
            any: false,
            first: 0,
            others: false,
        };
        assert_eq!(policy(MPOL_DEFAULT, 0, none), Ok(None));
        assert_eq!(policy(MPOL_DEFAULT, 0, one), Err(EINVAL));
        assert_eq!(
            policy(MPOL_PREFERRED, 0, none).unwrap().unwrap().mode,
            MPOL_LOCAL
        );
        assert_eq!(policy(MPOL_BIND, 0, none), Err(EINVAL));
        // A node with no memory leaves the policy nothing to apply.
        assert_eq!(policy(MPOL_BIND, 0, elsewhere), Err(EINVAL));
        assert_eq!(policy(MPOL_BIND, 0, one).unwrap().unwrap().nodes, NODE0);
        assert_eq!(sanitize(99), Err(EINVAL));
        assert_eq!(
            sanitize(MPOL_BIND | MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES),
            Err(EINVAL)
        );
        assert_eq!(
            sanitize(MPOL_PREFERRED | MPOL_F_NUMA_BALANCING),
            Err(EINVAL)
        );
    }
}
