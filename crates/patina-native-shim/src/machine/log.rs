//! A child's page: a memory file the hub and the child both map, which the
//! child writes what it must not lose to as it happens. A child can end
//! anywhere, mid-quantum (a host fault, an abort) or under a lock no stop
//! path may take, so nothing it holds is shipped late: the hub reads the
//! page whenever it holds the baton, and once more when the child is gone.
//!
//! The page is a header and, for a recording child, its decision log after
//! it. The header holds how many bytes of decisions are committed, whether
//! the log filled, the child's time as of its latest runtime step (so a
//! child that dies mid-quantum leaves the machine at the time it reached),
//! and the compute-bound stop it took, if it took one (so its timeline
//! keeps the boundary its replay stops at). The hub writes the time once
//! before the child starts: the machine's time, which the child's clock
//! starts at.
//!
//! The decisions are one `[operation, outcome]` JSON pair per line. A
//! decision is committed only once whole, so a child that dies writing one
//! leaves the ones before it. The log is twice the trace budget
//! ([`patina_dst_trace::MAX_TRACE_BYTES`]) and sparse: a child that fills
//! it has outgrown the budget, and the root abandons the recording.

use super::*;
use patina_dst_abi::{Operation, Outcome};
use patina_dst_trace::ComputeStop;
use std::sync::atomic::{AtomicU64, AtomicUsize};

/// The header's words, in order.
const COMMITTED: usize = 0;
const FULL: usize = 1;
const NOW: usize = 2;
/// 0: no compute stop; 1: one with no task; 2: one with the task below.
const STOP: usize = 3;
const STOP_STEPS: usize = 4;
const STOP_TASK: usize = 5;

/// The header's size.
const HEADER: usize = 64;

/// The page's size, header included.
const BYTES: usize = HEADER + 2 * patina_dst_trace::MAX_TRACE_BYTES as usize;

/// `map`ped `bytes` of `fd`, shared, or `None`.
fn map(fd: c_int, bytes: usize) -> Option<usize> {
    // SAFETY: a fresh shared mapping of a descriptor this process holds.
    let base = unsafe {
        crate::sud_host_syscall(
            libc::SYS_mmap,
            0,
            bytes as _,
            (libc::PROT_READ | libc::PROT_WRITE) as _,
            libc::MAP_SHARED as _,
            fd as _,
            0,
        )
    };
    (base > 0).then_some(base as usize)
}

/// Header word `index` of the page at `base`.
fn word(base: usize, index: usize) -> &'static AtomicU64 {
    // SAFETY: `base` is a live, page-aligned mapping of at least `HEADER`
    // bytes, which stays mapped while its owner lives; the words are only
    // ever accessed atomically.
    unsafe { &*((base + 8 * index) as *const AtomicU64) }
}

/// The hub's side of child `pid`'s page.
pub(super) struct HubPage {
    base: usize,
    bytes: usize,
    /// How many committed bytes the hub has read.
    read: usize,
}

impl HubPage {
    /// A fresh page whose time is `now`, and the descriptor (close-on-exec)
    /// the child maps it by.
    pub(super) fn create(now: u64) -> (Self, c_int) {
        Self::create_sized(now, BYTES)
    }

    fn create_sized(now: u64, bytes: usize) -> (Self, c_int) {
        // SAFETY: a static name; the flags are plain.
        let fd = unsafe {
            crate::sud_host_syscall(
                libc::SYS_memfd_create,
                c"patina-process-page".as_ptr() as _,
                libc::MFD_CLOEXEC as _,
                0,
                0,
                0,
                0,
            )
        } as c_int;
        // SAFETY: sizing the descriptor just made.
        if fd < 0
            || unsafe {
                crate::sud_host_syscall(libc::SYS_ftruncate, fd as _, bytes as _, 0, 0, 0, 0)
            } != 0
        {
            protocol_fatal_text("creating a process's page failed");
        }
        let base = map(fd, bytes)
            .unwrap_or_else(|| protocol_fatal_text("mapping a process's page failed"));
        word(base, NOW).store(now, Ordering::Release);
        (
            Self {
                base,
                bytes,
                read: 0,
            },
            fd,
        )
    }

    /// The decisions committed since the last call, and whether the log
    /// filled (decisions are missing past them). The child is frozen or
    /// gone while the hub reads.
    pub(super) fn take(&mut self) -> (Vec<u8>, bool) {
        let committed =
            (word(self.base, COMMITTED).load(Ordering::Acquire) as usize).min(self.bytes - HEADER);
        let start = self.base + HEADER + self.read;
        // SAFETY: inside the mapping, past what was read, up to what the
        // child committed.
        let decisions =
            unsafe { std::slice::from_raw_parts(start as *const u8, committed - self.read) }
                .to_vec();
        self.read = committed;
        (
            decisions,
            word(self.base, FULL).load(Ordering::Acquire) != 0,
        )
    }

    /// The child's time as of its latest runtime step.
    pub(super) fn now(&self) -> u64 {
        word(self.base, NOW).load(Ordering::Acquire)
    }

    /// The compute-bound stop the child took, if it took one.
    pub(super) fn compute_stop(&self) -> Option<ComputeStop> {
        let task = match word(self.base, STOP).load(Ordering::Acquire) {
            0 => return None,
            1 => None,
            _ => Some(TaskId(word(self.base, STOP_TASK).load(Ordering::Acquire))),
        };
        Some(ComputeStop {
            steps: word(self.base, STOP_STEPS).load(Ordering::Acquire),
            task,
        })
    }
}

impl Drop for HubPage {
    fn drop(&mut self) {
        // SAFETY: unmaps this page's own mapping.
        unsafe {
            crate::sud_host_syscall(
                libc::SYS_munmap,
                self.base as _,
                self.bytes as _,
                0,
                0,
                0,
                0,
            )
        };
    }
}

/// This child's page, mapped at startup (0 in the root).
static PAGE: AtomicUsize = AtomicUsize::new(0);

/// Map the page the hub handed this child, as descriptor `fd`: answers the
/// machine's time the hub wrote there, which this child's clock starts at.
pub(super) fn open(fd: c_int) -> Option<u64> {
    let base = map(fd, BYTES)?;
    close(fd);
    PAGE.store(base, Ordering::Release);
    Some(word(base, NOW).load(Ordering::Acquire))
}

/// This child's time is `now` as of its latest runtime step.
pub(crate) fn note_now(now: u64) {
    let base = PAGE.load(Ordering::Relaxed);
    if base != 0 {
        word(base, NOW).fetch_max(now, Ordering::Release);
    }
}

/// A recording child's trace channel: every decision goes to its page's
/// log as it is recorded, a compute-bound stop goes to the page's header,
/// and nothing is written at its end (the root writes the run's trace).
pub(crate) struct DecisionLog {
    written: usize,
}

impl DecisionLog {
    /// The log of the page this child mapped at startup.
    pub(crate) fn new() -> Result<Self, patina_dst_runtime::RuntimeError> {
        if PAGE.load(Ordering::Acquire) == 0 {
            return Err(patina_dst_runtime::RuntimeError::Config(format!(
                "a recording child process requires {}",
                patina_dst_runtime::ENV_PROCESS_PAGE_FD
            )));
        }
        Ok(Self { written: 0 })
    }

    fn base() -> usize {
        PAGE.load(Ordering::Acquire)
    }
}

impl patina_dst_runtime::TraceTransport for DecisionLog {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::other(
            "a recording child process reads no trace",
        ))
    }
    fn write_bundle(&mut self, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    /// A stop's flush: the decisions are all in the log already; a
    /// compute-bound stop's boundary goes to the header (no allocation).
    fn write_prefix(&mut self, recorder: &patina_dst_trace::Recorder) -> std::io::Result<()> {
        if let Some(stop) = recorder.metadata().compute_stop {
            let base = Self::base();
            word(base, STOP_STEPS).store(stop.steps, Ordering::Relaxed);
            word(base, STOP_TASK).store(stop.task.map_or(0, |task| task.0), Ordering::Relaxed);
            word(base, STOP).store(if stop.task.is_some() { 2 } else { 1 }, Ordering::Release);
        }
        Ok(())
    }
    fn decision(&mut self, operation: &Operation, outcome: &Outcome) {
        Self::append(Self::base(), BYTES, &mut self.written, operation, outcome);
    }
}

impl DecisionLog {
    fn append(
        base: usize,
        bytes: usize,
        written: &mut usize,
        operation: &Operation,
        outcome: &Outcome,
    ) {
        if word(base, FULL).load(Ordering::Relaxed) != 0 {
            return;
        }
        // SAFETY: the mapping's room past what is written.
        let room = unsafe {
            std::slice::from_raw_parts_mut(
                (base + HEADER + *written) as *mut u8,
                bytes - HEADER - *written,
            )
        };
        let mut cursor = std::io::Cursor::new(room);
        let fits = serde_json::to_writer(&mut cursor, &(operation, outcome)).is_ok()
            && std::io::Write::write_all(&mut cursor, b"\n").is_ok();
        if !fits {
            word(base, FULL).store(1, Ordering::Release);
            return;
        }
        *written += cursor.position() as usize;
        word(base, COMMITTED).store(*written as u64, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log that fills says so, and holds every decision committed before.
    #[test]
    fn a_full_log_reports_it_is_full() {
        let (mut hub, fd) = HubPage::create_sized(7, HEADER + 64);
        close(fd);
        let operation = Operation::SchedulerNext;
        let outcome = Outcome::Unit;
        let mut written = 0;
        for _ in 0..10 {
            DecisionLog::append(hub.base, hub.bytes, &mut written, &operation, &outcome);
        }
        let (decisions, full) = hub.take();
        assert!(full);
        let lines = decisions
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty());
        assert!(lines.count() >= 1);
        assert_eq!(hub.now(), 7);
    }
}
