//! Memory placement.
use super::*;

const G: Group = Group::Mem;

const RANGE: &str = "Passed for guest ranges (the effect is on mappings whose addresses the runtime chose); ranges inside the runtime's region are refused.";
const LOCK: &str = "Answered 0 without locking: memory is never paged out from the guest's point of view, and the host's RLIMIT_MEMLOCK must not show through (the guest reads it as unlimited). Ranges in the runtime's region are refused.";
const SHM: &str = "System V shared memory: one table of segments for the run, kept by the supervisor (ids as a fresh IPC namespace gives them, virtual times); a segment's memory is a memfd the supervisor holds, mapped by shmat at an address the runtime chooses (or the program's, SHM_RND and SHM_REMAP as the kernel). nattch follows fork, exit, execve, shmdt and an munmap of a whole attachment; IPC_RMID removes a segment at its last detach. A process crash keeps the segments for the next incarnation, a machine crash does not. SHM_HUGETLB and SHM_LOCK answer EPERM (unprivileged); SHM_STAT, IPC_INFO and SHM_INFO answer EINVAL; both recorded.";
const NUMA: &str = "NUMA placement has no guest-visible effect in a one-core sandbox; a kernel without NUMA support answers ENOSYS.";

pub const ROWS: &[Row] = &[
    Row::new(G, nr::MMAP, Place, C, "The runtime chooses every address without MAP_FIXED: the guest's hint when that range is free, else a top-down cursor below 0x5f00_0000_0000 that is never reused (MAP_32BIT, x86_64: ENOMEM). Fresh anonymous memory is zero. Fixed mappings into the runtime's region are refused.")
        .fd(4),
    Row::new(G, nr::BRK, Place, C, "Emulated over a 64 GiB reservation at 0x5800_0000_0000: growth makes pages accessible, shrinking replaces them with fresh ones."),
    Row::new(G, nr::MUNMAP, Place, C, RANGE),
    Row::new(G, nr::MPROTECT, Place, C, RANGE),
    Row::new(G, nr::PKEY_MPROTECT, Place, C, "As mprotect; protection keys cannot be allocated (pkey_alloc is refused), so the key is always -1."),
    Row::new(G, nr::MREMAP, Place, C, "In-place resize is passed; a move goes to an address the runtime chooses (MREMAP_FIXED at its cursor)."),
    Row::new(G, nr::MADVISE, Place, C, "Passed; DONTNEED on private anonymous memory zeroes deterministically. MADV_FREE answers EINVAL (as by a kernel without it, and natively on a file or shared mapping; the allocators that use it fall back to DONTNEED) and is recorded: the kernel frees its pages when it chooses, so later reads would depend on memory pressure, and the memory counters that tell (smaps) are not the host's here. MADV_COLLAPSE answers EINVAL (as without transparent huge pages) and is recorded: whether a collapse succeeds depends on the host's free huge pages. The runtime's region is refused."),
    Row::new(G, nr::MSYNC, Pass, A, "On tmpfs and anonymous memory the kernel call only validates its arguments (tmpfs writeback is a no-op); durability is the tracker's. The runtime's region is refused."),
    Row::new(G, nr::MLOCK, Virt, C, LOCK),
    Row::new(G, nr::MUNLOCK, Virt, C, LOCK),
    Row::new(G, nr::MLOCK2, Virt, C, LOCK),
    Row::new(G, nr::MLOCKALL, Virt, C, LOCK),
    Row::new(G, nr::MUNLOCKALL, Virt, C, LOCK),
    Row::new(G, nr::SHMGET, Virt, C, SHM),
    Row::new(G, nr::SHMAT, Place, C, SHM),
    Row::new(G, nr::SHMDT, Place, C, SHM),
    Row::new(G, nr::SHMCTL, Virt, C, SHM).refs(&[out(2, Len::Fixed(112))]),
    Row::new(G, nr::MINCORE, Deny(errno::ENOSYS), C, "Residency reveals page-cache and paging state, which the host decides."),
    Row::new(G, nr::MBIND, Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, nr::SET_MEMPOLICY, Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, nr::MIGRATE_PAGES, Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, nr::MOVE_PAGES, Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, nr::SET_MEMPOLICY_HOME_NODE, Deny(errno::ENOSYS), C, NUMA),
    Row::new(G, nr::REMAP_FILE_PAGES, Deny(errno::ENOSYS), C, "Deprecated; a kernel without it answers ENOSYS."),
    Row::new(G, nr::PROCESS_MADVISE, Deny(errno::ENOSYS), C, "Acts on another process's memory by pidfd; refused."),
    Row::new(G, nr::MSEAL, Deny(errno::ENOSYS), C, "A kernel without memory sealing answers ENOSYS; sealing would also pin runtime decisions."),
    Row::new(G, nr::MEMBARRIER, Deny(errno::ENOSYS), C, "Refused as by a kernel built without it; programs fall back to other barriers."),
    Row::new(G, nr::PKEY_ALLOC, Deny(errno::ENOSYS), C, "Protection keys are a per-CPU hardware feature; a kernel without them answers ENOSYS."),
    Row::new(G, nr::PKEY_FREE, Deny(errno::ENOSYS), C, "Protection keys are not offered."),
    Row::new(G, nr::MEMFD_SECRET, Deny(errno::ENOSYS), C, "A kernel without secret memory answers ENOSYS."),
    Row::new(G, nr::MAP_SHADOW_STACK, Deny(errno::ENOSYS), C, "Shadow stacks are not offered; a kernel without them answers ENOSYS."),
];
