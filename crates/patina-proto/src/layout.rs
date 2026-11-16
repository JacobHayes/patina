//! Fixed address map and hidden descriptor numbers.
//! Identical in every guest process.

/// Runtime image, text first. The seccomp filter lets through syscalls whose
/// instruction pointer lies in `[RT_BASE, RT_TEXT_END)`.
pub const RT_BASE: u64 = 0x6000_0000_0000;
pub const RT_TEXT_END: u64 = 0x6000_1000_0000;
/// High and low 32-bit halves the filter compares.
pub const RT_IP_HI32: u32 = 0x6000;
pub const RT_IP_LO_END: u32 = 0x1000_0000;
/// Runtime private memory: alternate stacks (aligned to their size), tables. Bump allocated.
pub const RT_PRIV: u64 = 0x6010_0000_0000;
pub const RT_PRIV_SIZE: u64 = 0x10_0000_0000;
/// Control region (shared memfd).
pub const CTL_ADDR: u64 = 0x6020_0000_0000;
/// Boundary log mapping (shared file mapping, extended in `LOG_STEP` steps).
pub const LOG_ADDR: u64 = 0x6030_0000_0000;
pub const LOG_STEP: u64 = 16 << 20;
/// Everything in `[RT_BASE, RT_REGION_END)` belongs to the runtime; the guest may not map there.
pub const RT_REGION_END: u64 = 0x6040_0000_0000;

/// Guest `ET_DYN` executable base; `ET_EXEC` images load where they were linked.
pub const EXE_BASE: u64 = 0x5555_5555_0000;
/// Guest interpreter (`PT_INTERP`) base.
pub const INTERP_BASE: u64 = 0x5700_0000_0000;
/// Guest `brk`: 64 GiB reserved, emulated.
pub const BRK_BASE: u64 = 0x5800_0000_0000;
pub const BRK_SIZE: u64 = 64 << 30;
/// Guest `mmap` without a fixed address: below this, growing down, never reused within an image.
pub const MMAP_TOP: u64 = 0x5f00_0000_0000;
/// Lowest address the top-down allocator hands out (above the brk reservation).
pub const MMAP_FLOOR: u64 = BRK_BASE + BRK_SIZE;
/// Guest initial stack.
pub const STACK_TOP: u64 = 0x7ff0_0000_0000;
pub const STACK_SIZE: u64 = 8 << 20;

/// Per-thread alternate stack of the runtime; thread state sits at its base.
pub const ALT_SIZE: u64 = 256 << 10;

pub const PAGE: u64 = 4096;

/// Hidden descriptors. The guest sees `EBADF` for any number `>= FD_HIDDEN_MIN`.
pub const FD_HIDDEN_MIN: i32 = 3000;
pub const FD_CTL: i32 = 3000;
pub const FD_LOG: i32 = 3001;
pub const FD_OPLOG_META: i32 = 3002;
pub const FD_OPLOG_DATA: i32 = 3003;
pub const FD_RT: i32 = 3004;
/// Supervisor only.
pub const FD_OUTCOME: i32 = 3005;
/// Supervisor only.
pub const FD_EXPORT: i32 = 3006;
/// Launcher to bwrap only: the `patina` executable, run inside the sandbox as `/proc/self/fd/3007 __sup`.
pub const FD_PATINA: i32 = 3007;
/// Launcher to supervisor only: the guest's stdio memfds, which the supervisor moves to
/// 0, 1 and 2 (for itself and so for every guest process) before anything else.
pub const FD_STDIN: i32 = 3020;
pub const FD_STDOUT: i32 = 3021;
pub const FD_STDERR: i32 = 3022;
/// The counter broker: a `SOCK_SEQPACKET` end whose peer is the launcher (only with `--pmu`).
pub const FD_PMU: i32 = 3008;
/// Hidden descriptors the runtime makes for itself (counters, `/proc/self/mem`) are
/// placed at the lowest free number from here.
pub const FD_RT_DYN: i32 = 3100;
/// A thread's counter page is mapped at this offset in its alternate stack (after the
/// thread state, far below where the stack grows down to).
pub const PMU_PAGE_OFF: u64 = 4096;

/// Virtual time origin of the monotonic clock, and the realtime epoch added to it
/// (2026-01-01T00:00:00Z).
pub const VCLOCK_BOOT_NS: u64 = 100_000_000_000;
pub const REALTIME_EPOCH_S: u64 = 1_767_225_600;
/// Timestamp reported for every file on a sandbox-created filesystem until the
/// virtual time table exists: the realtime epoch.
pub const FILE_EPOCH_S: u64 = REALTIME_EPOCH_S;

/// Virtual device numbers (major 0). Mounts created by the sandbox get
/// `VDEV_MOUNT_BASE + index in mountinfo order`.
pub const VDEV_MOUNT_BASE: u64 = 0x20;
