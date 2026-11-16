//! Memory placement.
use super::misc::n;
use super::*;

const G: Group = Group::Mem;

const RANGE: &str = "Passed for guest ranges (the effect is on mappings whose addresses the runtime chose); ranges inside the runtime's region are refused.";
const LOCK: &str = "Answered 0 without locking: memory is never paged out from the guest's point of view, and the host's RLIMIT_MEMLOCK must not show through (the guest reads it as unlimited). Ranges in the runtime's region are refused.";
const NUMA: &str = "NUMA placement has no guest-visible effect in a one-core sandbox; a kernel without NUMA support answers ENOSYS.";

pub const ROWS: &[Row] = &[
    Row::new(G, n(9, "mmap"), Place, C, "The runtime chooses every address without MAP_FIXED: the guest's hint when that range is free, else a top-down cursor below 0x5f00_0000_0000 that is never reused. Fresh anonymous memory is zero. Fixed mappings into the runtime's region are refused.")
        .fd(4),
    Row::new(G, n(12, "brk"), Place, C, "Emulated over a 64 GiB reservation at 0x5800_0000_0000: growth makes pages accessible, shrinking replaces them with fresh ones."),
    Row::new(G, n(11, "munmap"), Place, C, RANGE),
    Row::new(G, n(10, "mprotect"), Place, C, RANGE),
    Row::new(G, n(329, "pkey_mprotect"), Place, C, "As mprotect; protection keys cannot be allocated (pkey_alloc is refused), so the key is always -1."),
    Row::new(G, n(25, "mremap"), Place, C, "In-place resize is passed; a move goes to an address the runtime chooses (MREMAP_FIXED at its cursor)."),
    Row::new(G, n(28, "madvise"), Place, C, "Passed, with MADV_FREE rewritten to MADV_DONTNEED (the kernel frees MADV_FREE pages when it chooses, so later reads would depend on memory pressure); DONTNEED on private anonymous memory zeroes deterministically. MADV_COLLAPSE answers EINVAL (as without transparent huge pages) and is recorded: whether a collapse succeeds depends on the host's free huge pages. The runtime's region is refused."),
    Row::new(G, n(26, "msync"), Pass, A, "On tmpfs and anonymous memory the kernel call only validates its arguments (tmpfs writeback is a no-op); durability is the tracker's. The runtime's region is refused."),
    Row::new(G, n(149, "mlock"), Virt, C, LOCK),
    Row::new(G, n(150, "munlock"), Virt, C, LOCK),
    Row::new(G, n(325, "mlock2"), Virt, C, LOCK),
    Row::new(G, n(151, "mlockall"), Virt, C, LOCK),
    Row::new(G, n(152, "munlockall"), Virt, C, LOCK),
    Row::new(G, n(27, "mincore"), Deny(errno::ENOSYS), C, "Residency reveals page-cache and paging state, which the host decides."),
    Row::new(G, n(237, "mbind"), Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, n(238, "set_mempolicy"), Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, n(256, "migrate_pages"), Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, n(279, "move_pages"), Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, n(450, "set_mempolicy_home_node"), Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, n(216, "remap_file_pages"), Deny(errno::ENOSYS), C, "Deprecated; a kernel without it answers ENOSYS."),
    Row::new(G, n(440, "process_madvise"), Deny(errno::ENOSYS), C, "Acts on another process's memory by pidfd; refused."),
    Row::new(G, n(462, "mseal"), Deny(errno::ENOSYS), C, "A kernel without memory sealing answers ENOSYS; sealing would also pin runtime decisions."),
    Row::new(G, n(330, "pkey_alloc"), Deny(errno::ENOSYS), C, "Protection keys are a per-CPU hardware feature; a kernel without them answers ENOSYS."),
    Row::new(G, n(331, "pkey_free"), Deny(errno::ENOSYS), C, "Protection keys are not offered."),
    Row::new(G, n(447, "memfd_secret"), Deny(errno::ENOSYS), C, "A kernel without secret memory answers ENOSYS."),
    Row::new(G, n(453, "map_shadow_stack"), Deny(errno::ENOSYS), C, "Shadow stacks are not offered; a kernel without them answers ENOSYS."),
];
