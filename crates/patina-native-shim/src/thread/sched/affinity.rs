//! The virtual machine's CPUs as a thread sees them: [`crate::cpus::count`]
//! of them. A thread's affinity is every CPU until it sets one, and the CPU it
//! runs on follows a fixed rule ([`cpu_on`]): tasks still run one at a time,
//! so the CPU is what the thread is told, not where it executes. A thread's
//! own CPU and affinity are mirrored where it reads them without the thread
//! runtime's lock or an allocation ([`CpuSlot`]): an allocator asks for its
//! CPU (per-CPU arenas) while the runtime, holding that lock, allocates
//! through it.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// The longs of a CPU mask with room for every CPU a run may have.
pub(super) const MASK_WORDS: usize = (patina_dst_abi::MAX_CPUS as usize).div_ceil(64);

/// A set of the virtual machine's CPUs: bit `n % 64` of word `n / 64` names
/// CPU `n`, the layout of the kernel's `struct cpumask` and glibc's
/// `cpu_set_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CpuMask(pub(super) [u64; MASK_WORDS]);

impl CpuMask {
    /// The first `cpus` CPUs.
    fn first(cpus: u32) -> Self {
        let mut words = [0u64; MASK_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            let below = (cpus as usize).saturating_sub(index * 64).min(64);
            *word = if below == 64 {
                u64::MAX
            } else {
                (1u64 << below) - 1
            };
        }
        CpuMask(words)
    }

    /// A mask read from the guest's bytes, native-endian longs (a short read
    /// leaves the rest clear), keeping only the machine's `cpus` CPUs.
    fn from_bytes(bytes: &[u8], cpus: u32) -> Self {
        let mut words = [0u64; MASK_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            let mut long = [0u8; 8];
            long[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_ne_bytes(long);
        }
        CpuMask(words).and(CpuMask::first(cpus))
    }

    /// The mask's byte `index`, as the guest's longs hold it.
    fn byte(&self, index: usize) -> u8 {
        self.0[index / 8].to_ne_bytes()[index % 8]
    }

    /// The mask's first `len` bytes, as the guest's longs hold them.
    #[cfg(test)]
    fn bytes(&self, len: usize) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .take(len)
            .collect()
    }

    fn and(self, other: CpuMask) -> Self {
        let mut words = self.0;
        for (word, other) in words.iter_mut().zip(other.0) {
            *word &= other;
        }
        CpuMask(words)
    }

    fn has(&self, cpu: u32) -> bool {
        let cpu = cpu as usize;
        cpu < MASK_WORDS * 64 && self.0[cpu / 64] & (1 << (cpu % 64)) != 0
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }
}

/// `cpumask_size()`: whole longs covering the machine's `cpus` CPUs
/// (`nr_cpu_ids`, on a kernel built with `CPUMASK_OFFSTACK`, as the
/// distributions build theirs).
fn cpumask_bytes(cpus: u32) -> usize {
    (cpus as usize).div_ceil(64) * std::mem::size_of::<u64>()
}

/// The CPU a thread runs on, of the machine's `cpus`. A thread starts on the
/// CPU of its creation order: task `n` on CPU `(n - 1) mod cpus`, so the main
/// thread on CPU 0 and each thread after it on the next, round robin. When its
/// affinity excludes that CPU it runs on the first one its mask allows after
/// it, wrapping round. A pure function of the task and its mask, so every
/// reader (`getcpu`, `sched_getcpu`, the rseq area, `rdtscp`) agrees, and a
/// replay answers what the recording did.
fn cpu_on(tid: i32, affinity: Option<CpuMask>, cpus: u32) -> u32 {
    let order = task_of(tid).map_or(0, |task| task.0.saturating_sub(1));
    let home = (order % u64::from(cpus)) as u32;
    let Some(mask) = affinity else {
        return home;
    };
    (0..cpus)
        .map(|step| (home + step) % cpus)
        .find(|cpu| mask.has(*cpu))
        .unwrap_or(home)
}

/// A thread's CPU and affinity, mirrored from its [`Attrs`] (which the
/// runtime's lock guards) for the thread's own lock-free reads. Written under
/// that lock: at spawn, and by a `sched_setaffinity` naming the thread, from
/// it or from another thread while it waits for the baton. A slot lives for
/// the process; a finished thread's is reused by a later one.
pub(super) struct CpuSlot {
    /// Whether the thread set an affinity; until then its CPU is its home
    /// one and its mask every CPU, both answered from the count.
    pinned: AtomicBool,
    cpu: AtomicU32,
    mask: [AtomicU64; MASK_WORDS],
}

impl CpuSlot {
    pub(super) const fn new() -> Self {
        CpuSlot {
            pinned: AtomicBool::new(false),
            cpu: AtomicU32::new(0),
            mask: [const { AtomicU64::new(0) }; MASK_WORDS],
        }
    }

    fn store(&self, cpu: u32, affinity: Option<CpuMask>) {
        if let Some(mask) = affinity {
            for (word, value) in self.mask.iter().zip(mask.0) {
                word.store(value, Ordering::Relaxed);
            }
            self.cpu.store(cpu, Ordering::Relaxed);
        }
        self.pinned.store(affinity.is_some(), Ordering::Release);
    }

    /// The thread's CPU and affinity (`None` for every CPU).
    fn load(&self, tid: i32, cpus: u32) -> (u32, Option<CpuMask>) {
        if !self.pinned.load(Ordering::Acquire) {
            return (cpu_on(tid, None, cpus), None);
        }
        let mut words = [0u64; MASK_WORDS];
        for (value, word) in words.iter_mut().zip(&self.mask) {
            *value = word.load(Ordering::Relaxed);
        }
        (self.cpu.load(Ordering::Relaxed), Some(CpuMask(words)))
    }
}

/// The main thread's slot: it exists before the thread runtime does.
static MAIN_SLOT: CpuSlot = CpuSlot::new();

thread_local! {
    /// The managed thread's slot, bound in its prelude ([`bind_cpu_slot`])
    /// and unbound as it finishes.
    static CPU_SLOT: Cell<Option<&'static CpuSlot>> = const { Cell::new(None) };
}

/// The calling thread's slot: its own once bound, the main thread's for the
/// main (or a not yet managed) thread. `None` for a managed thread outside
/// its prelude-to-finish lifetime, whose affinity is every CPU there.
fn own_slot() -> Option<&'static CpuSlot> {
    CPU_SLOT.with(Cell::get).or_else(|| {
        let task = current_task();
        (task == MAIN_TASK || task == UNMANAGED_TASK).then_some(&MAIN_SLOT)
    })
}

/// Bind the calling managed thread to `task`'s slot, made at its spawn.
pub(in crate::thread) fn bind_cpu_slot(task: TaskId) {
    let slot = lock_state().sched.slot(tid_of(task));
    CPU_SLOT.with(|cell| cell.set(slot));
}

/// Unbind the calling thread's slot as its task finishes.
pub(in crate::thread) fn unbind_cpu_slot() {
    CPU_SLOT.with(|cell| cell.set(None));
}

/// The calling thread's CPU and affinity, without the runtime's lock.
fn own_cpu(cpus: u32) -> (u32, Option<CpuMask>) {
    let tid = current_tid();
    own_slot().map_or_else(
        || (cpu_on(tid, None, cpus), None),
        |slot| slot.load(tid, cpus),
    )
}

/// The CPU the calling thread runs on ([`cpu_on`]). Takes no lock and makes
/// no allocation.
pub(crate) fn current_cpu() -> u32 {
    own_cpu(crate::cpus::count()).0
}

/// The CPU `task` runs on ([`cpu_on`]).
pub(crate) fn cpu_of_task(task: TaskId) -> u32 {
    let cpus = crate::cpus::count();
    let tid = tid_of(task);
    cpu_on(tid, lock_state().sched.get(tid).affinity, cpus)
}

impl SchedRuntime {
    /// `tid`'s slot: the main thread's, or a managed thread's from its spawn
    /// to its finish.
    pub(super) fn slot(&self, tid: i32) -> Option<&'static CpuSlot> {
        if tid == tid_of(MAIN_TASK) {
            return Some(&MAIN_SLOT);
        }
        self.slots.get(&tid).copied()
    }

    /// Mirror `tid`'s CPU and affinity into its slot.
    pub(super) fn mirror(&self, tid: i32, affinity: Option<CpuMask>) {
        if let Some(slot) = self.slot(tid) {
            let cpus = crate::cpus::count();
            slot.store(cpu_on(tid, affinity, cpus), affinity);
        }
    }
}

/// `sched_getaffinity(pid, len, mask)`: the thread's CPUs, `min(len,
/// cpumask_size())` bytes written and answered (init's are every CPU); a
/// buffer shorter than the machine's CPU count or not a whole number of longs
/// is `EINVAL`, a pid no thread has `ESRCH`.
///
/// # Safety
/// `mask` must be NULL or writable for `len` bytes.
pub(crate) unsafe fn getaffinity(pid: i32, len: u32, mask: *mut u8) -> SysResult<i64> {
    let cpus = crate::cpus::count();
    let len = len as usize;
    if len * 8 < cpus as usize || !len.is_multiple_of(CPUMASK_LONG) {
        return Err(Errno::new(EINVAL));
    }
    // The caller's own mask is read without the lock (an allocator may ask).
    let affinity = if pid == 0 || pid == current_tid() {
        own_cpu(cpus).1
    } else {
        let state = lock_state();
        let Some(tid) = find(&state, pid) else {
            return Err(Errno::new(ESRCH));
        };
        state.sched.get(tid).affinity
    };
    let written = len.min(cpumask_bytes(cpus));
    if mask.is_null() {
        return Err(Errno::new(EFAULT));
    }
    let affinity = affinity.unwrap_or(CpuMask::first(cpus));
    for index in 0..written {
        // SAFETY: per this function's contract, `index < written <= len`.
        unsafe { mask.add(index).write(affinity.byte(index)) };
    }
    Ok(written as i64)
}

/// A long, the unit a CPU mask buffer comes in.
const CPUMASK_LONG: usize = std::mem::size_of::<u64>();

/// `sched_setaffinity(pid, len, mask)`: the mask is read first (at most
/// `cpumask_size()` bytes, a short one padded with zeros), then the pid
/// (`ESRCH`), then another user's thread is `EPERM` ([`same_owner`]); a mask
/// naming none of the machine's CPUs is `EINVAL`. The thread's affinity
/// becomes the CPUs the mask names, so it runs on one of them ([`cpu_on`]),
/// and its rseq area names that CPU before the call returns.
///
/// # Safety
/// `mask` must be NULL or readable for `len` bytes.
pub(crate) unsafe fn setaffinity(pid: i32, len: u32, mask: *const u8) -> SysResult<i64> {
    let cpus = crate::cpus::count();
    let read = (len as usize).min(cpumask_bytes(cpus));
    if read > 0 && mask.is_null() {
        return Err(Errno::new(EFAULT));
    }
    let mut bytes = [0u8; MASK_WORDS * 8];
    // SAFETY: per this function's contract; `read` is at most
    // `cpumask_size()`, which the buffer covers.
    unsafe { std::ptr::copy_nonoverlapping(mask, bytes.as_mut_ptr(), read) };
    let wanted = CpuMask::from_bytes(&bytes[..read], cpus);
    let Some(tid) = find(&lock_state(), pid) else {
        return Err(Errno::new(ESRCH));
    };
    if !same_owner(tid) {
        return Err(Errno::new(EPERM));
    }
    if wanted.is_empty() {
        return Err(Errno::new(EINVAL));
    }
    let affinity = (wanted != CpuMask::first(cpus)).then_some(wanted);
    {
        let mut state = lock_state();
        let mut attrs = state.sched.get(tid);
        attrs.affinity = affinity;
        state.sched.set(tid, attrs);
        state.sched.mirror(tid, affinity);
    }
    let cpu = cpu_on(tid, affinity, cpus);
    if let Some(task) = task_of(tid) {
        super::registrations::migrated(task, cpu);
    }
    Ok(0)
}

/// `getcpu(cpu, node, cache)`: the CPU the caller runs on ([`cpu_on`]), on
/// node 0.
///
/// # Safety
/// `cpu` and `node` must be NULL or writable for a `u32`.
pub(crate) unsafe fn getcpu(cpu: *mut u32, node: *mut u32) -> SysResult<i64> {
    let current = if cpu.is_null() { 0 } else { current_cpu() };
    for (out, value) in [(cpu, current), (node, 0)] {
        if !out.is_null() {
            // SAFETY: per this function's contract.
            unsafe { out.write_unaligned(value) };
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The calling thread's affinity, through the row (`min(len,
    /// cpumask_size())` bytes into a buffer of `len`).
    fn affinity(len: usize) -> (SysResult<i64>, Vec<u8>) {
        let mut mask = vec![0u8; len];
        // SAFETY: `mask` is writable for `len` bytes.
        let r = unsafe { getaffinity(0, len as u32, mask.as_mut_ptr()) };
        (r, mask)
    }

    fn set_affinity(mask: &[u8]) -> SysResult<i64> {
        // SAFETY: `mask` is readable for its length.
        unsafe { setaffinity(0, mask.len() as u32, mask.as_ptr()) }
    }

    fn cpu() -> u32 {
        let mut cpu = u32::MAX;
        // SAFETY: `cpu` is writable; the node is not asked for.
        assert_eq!(unsafe { getcpu(&mut cpu, std::ptr::null_mut()) }, Ok(0));
        cpu
    }

    fn named(cpus: &[u32], len: usize) -> Vec<u8> {
        let mut mask = vec![0u8; len];
        for cpu in cpus {
            mask[*cpu as usize / 8] |= 1 << (cpu % 8);
        }
        mask
    }

    fn count_of(mask: &[u8]) -> u32 {
        mask.iter().map(|byte| byte.count_ones()).sum()
    }

    /// Every affinity view agrees with the machine's CPU count: the mask names
    /// exactly its CPUs, in whole longs, a buffer too small for them is
    /// `EINVAL`, and a mask naming only CPUs past them is `EINVAL`.
    #[test]
    fn the_affinity_mask_names_every_virtual_cpu() {
        crate::thread::signals::tests::isolated(|| {
            let cpus = crate::cpus::count();
            let (r, mask) = affinity(128);
            assert_eq!(r, Ok(cpumask_bytes(cpus) as i64));
            assert_eq!(count_of(&mask), cpus);
            assert!((0..cpus).all(|cpu| mask[cpu as usize / 8] & (1 << (cpu % 8)) != 0));
            let short = (cpus as usize).div_ceil(8) - 1;
            assert_eq!(affinity(short).0, Err(Errno::new(EINVAL)));
            assert_eq!(set_affinity(&named(&[cpus], 128)), Err(Errno::new(EINVAL)));
            assert_eq!(set_affinity(&named(&[], 128)), Err(Errno::new(EINVAL)));
            assert_eq!(affinity(128).1, mask, "a refused mask changes nothing");
        });
    }

    /// Pinned to another CPU, the thread runs there; a mask naming that CPU
    /// and CPUs past the machine's keeps just that CPU; the full mask
    /// restores the CPU it started on.
    #[test]
    fn a_pinned_thread_runs_on_its_cpu() {
        crate::thread::signals::tests::isolated(|| {
            let cpus = crate::cpus::count();
            assert!(cpus > 1, "the default machine has more than one CPU");
            let (_, full) = affinity(128);
            let start = cpu();
            assert!(start < cpus);
            let other = (start + 1) % cpus;
            assert_eq!(set_affinity(&named(&[other, cpus], 128)), Ok(0));
            assert_eq!(affinity(128).1, named(&[other], 128));
            assert_eq!(cpu(), other);
            assert_eq!(set_affinity(&full), Ok(0));
            assert_eq!(cpu(), start);
        });
    }

    /// A thread's own CPU and affinity answer while the runtime's lock is
    /// held, as they must for an allocator the runtime allocates through;
    /// pinned, they are the pinned CPU's.
    #[test]
    fn a_threads_own_cpu_reads_take_no_lock() {
        crate::thread::signals::tests::isolated(|| {
            let cpus = crate::cpus::count();
            let other = 1 % cpus;
            assert_eq!(set_affinity(&named(&[other], 128)), Ok(0));
            let mut mask = vec![0u8; 128];
            let held = lock_state();
            let current = current_cpu();
            let raw = cpu();
            // SAFETY: `mask` is writable for its length.
            let r = unsafe { getaffinity(0, mask.len() as u32, mask.as_mut_ptr()) };
            drop(held);
            assert_eq!((current, raw), (other, other));
            assert_eq!(r, Ok(cpumask_bytes(cpus) as i64));
            assert_eq!(mask, named(&[other], 128));
        });
    }

    /// Threads start round robin over the CPUs in creation order, main on
    /// CPU 0; a mask moves a thread to the first CPU it allows after its own,
    /// wrapping round.
    #[test]
    fn threads_start_round_robin_and_a_mask_moves_them_forward() {
        let cpus = 3;
        let on = |task, affinity| cpu_on(tid_of(TaskId(task)), affinity, cpus);
        let started: Vec<u32> = (1..=7).map(|task| on(task, None)).collect();
        assert_eq!(started, [0, 1, 2, 0, 1, 2, 0]);
        let only = |cpus_named: &[u32]| Some(CpuMask::from_bytes(&named(cpus_named, 8), cpus));
        assert_eq!(on(2, only(&[2])), 2);
        assert_eq!(on(3, only(&[0, 1])), 0);
        assert_eq!(on(2, only(&[0, 2])), 2);
    }

    #[test]
    fn a_mask_keeps_only_the_machines_cpus() {
        for cpus in [1, 63, 64, 65, patina_dst_abi::MAX_CPUS] {
            let first = CpuMask::first(cpus);
            assert_eq!(count_of(&first.bytes(128)), cpus);
            let all = CpuMask::from_bytes(&[0xff; 128], cpus);
            assert_eq!(all, first);
        }
    }
}
