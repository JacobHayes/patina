//! Memory policy on the virtual machine's one memory node, as constants:
//! `set_mempolicy`, `get_mempolicy`, `mbind`, `move_pages`, `migrate_pages`,
//! `set_mempolicy_home_node`.
//!
//! The virtual machine has one node, 0, holding all memory. Every task and
//! range has the default policy (`MPOL_DEFAULT`), a request for node 0 (or
//! for none) succeeds without being kept, and a request that names any other
//! node is `EINVAL`. This is the answer allocators and databases probe for
//! (a NUMA-aware allocator asking for its policy, a single-node `mbind`); a
//! policy is not remembered, so a read after a set still reads the default.

use crate::{EFAULT, EINVAL, EPERM};
use std::ffi::c_int;

const MPOL_F_NODE: u64 = 1 << 0;
const MPOL_F_ADDR: u64 = 1 << 1;
const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
/// The one node, as a node mask's first word.
const NODE0: u64 = 1;
const PAGE: usize = crate::mem::PAGE;

fn fail(errno: c_int) -> i64 {
    -i64::from(errno)
}

/// Whether a caller's node mask (`maxnode - 1` bits, as `get_nodes` reads it)
/// names a node other than node 0, or is malformed.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
unsafe fn names_other_node(mask: *const u64, maxnode: u64) -> Result<bool, c_int> {
    let bits = maxnode.wrapping_sub(1);
    if bits == 0 || mask.is_null() {
        return Ok(false);
    }
    if bits > (PAGE as u64) * 8 {
        return Err(EINVAL);
    }
    let mut other = false;
    for index in 0..bits.div_ceil(64) as usize {
        // SAFETY: per this function's contract.
        let mut word = unsafe { mask.add(index).read_unaligned() };
        let covered = (bits - 64 * index as u64).min(64);
        if covered < 64 {
            word &= (1u64 << covered) - 1;
        }
        other |= if index == 0 { word & !NODE0 } else { word } != 0;
    }
    Ok(other)
}

/// A request for `mask`'s nodes: success for node 0 or none, `EINVAL` else.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
unsafe fn request(mask: *const u64, maxnode: u64) -> i64 {
    // SAFETY: per this function's contract.
    match unsafe { names_other_node(mask, maxnode) } {
        Ok(false) => 0,
        Ok(true) => fail(EINVAL),
        Err(errno) => fail(errno),
    }
}

/// `set_mempolicy(2)`.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn set_mempolicy(_mode: i32, mask: *const u64, maxnode: u64) -> i64 {
    // SAFETY: per this function's contract.
    unsafe { request(mask, maxnode) }
}

/// `mbind(2)`.
///
/// # Safety
/// `mask` must be NULL or readable for `maxnode - 1` bits.
pub(crate) unsafe fn mbind(
    start: usize,
    _len: usize,
    _mode: i32,
    mask: *const u64,
    maxnode: u64,
    _flags: u32,
) -> i64 {
    if !start.is_multiple_of(PAGE) {
        return fail(EINVAL);
    }
    // SAFETY: per this function's contract.
    unsafe { request(mask, maxnode) }
}

/// `get_mempolicy(2)`: the default policy, on node 0.
///
/// # Safety
/// `mode` must be NULL or writable; `mask` NULL or writable for
/// `maxnode - 1` bits.
pub(crate) unsafe fn get_mempolicy(
    mode: *mut i32,
    mask: *mut u64,
    maxnode: u64,
    _addr: usize,
    flags: u64,
) -> i64 {
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return fail(EINVAL);
    }
    let allowed = flags & MPOL_F_MEMS_ALLOWED != 0;
    if allowed && flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
        return fail(EINVAL);
    }
    // SAFETY: per this function's contract.
    unsafe {
        if !mode.is_null() {
            // The policy mode is `MPOL_DEFAULT` (0) and a queried node is 0.
            mode.write(0);
        }
        if !mask.is_null() {
            let bytes = maxnode.saturating_sub(1).div_ceil(64) * 8;
            if bytes > PAGE as u64 {
                return fail(EINVAL);
            }
            for index in 0..(bytes / 8) as usize {
                let word = if allowed && index == 0 { NODE0 } else { 0 };
                mask.add(index).write_unaligned(word);
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
        if let Err(errno) = names_other_node(old, maxnode) {
            return fail(errno);
        }
        match names_other_node(new, maxnode) {
            Ok(false) => 0,
            Ok(true) => fail(EPERM),
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
    fn node_zero_requests_succeed_and_other_nodes_are_refused() {
        // SAFETY: the masks outlive the calls and cover the bits named.
        unsafe {
            assert_eq!(set_mempolicy(0, std::ptr::null(), 0), 0);
            assert_eq!(set_mempolicy(2, &1u64, 65), 0);
            assert_eq!(set_mempolicy(2, &2u64, 65), fail(EINVAL));
            assert_eq!(mbind(0, 4096, 2, &1u64, 65, 0), 0);
            assert_eq!(mbind(0, 4096, 2, &4u64, 65, 0), fail(EINVAL));
        }
    }

    #[test]
    fn a_node_named_past_the_first_kilobit_is_refused() {
        let mut mask = [0u64; 17];
        mask[16] = 1;
        // SAFETY: the mask covers the 1088 bits named.
        unsafe {
            assert_eq!(set_mempolicy(2, mask.as_ptr(), 1089), fail(EINVAL));
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
    fn the_task_policy_reads_as_the_default_on_the_one_node() {
        let mut mode = 7;
        let mut mask = [9u64; 2];
        // SAFETY: the outputs are writable for what the call names.
        unsafe {
            assert_eq!(get_mempolicy(&mut mode, mask.as_mut_ptr(), 65, 0, 0), 0);
            assert_eq!((mode, mask[0]), (0, 0));
            assert_eq!(
                get_mempolicy(&mut mode, mask.as_mut_ptr(), 65, 0, MPOL_F_MEMS_ALLOWED),
                0
            );
            assert_eq!(mask[0], NODE0);
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
