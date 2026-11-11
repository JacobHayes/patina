//! A recording child's decision log: a memory file the hub and the child
//! both map, which the child appends each decision to the moment it is
//! recorded. A child can end anywhere, mid-quantum (a host fault, an abort)
//! or under a lock no stop path may take, so nothing it holds is shipped
//! late: the hub reads whatever the log holds whenever it holds the baton,
//! and once more when the child is gone.
//!
//! The file is a header (how many bytes of decisions are committed, and
//! whether the log filled) and the decisions after it, one `[operation,
//! outcome]` JSON pair per line. A decision is committed only once whole,
//! so a child that dies writing one leaves the ones before it. The log is
//! twice the trace budget ([`patina_dst_trace::MAX_TRACE_BYTES`]) and
//! sparse: a child that fills it has outgrown the budget, so the root's
//! recorder abandons the trace on the decisions before it.

use super::*;
use patina_dst_abi::{Operation, Outcome};
use std::sync::atomic::AtomicU64;

/// The header: the committed length, then the full flag.
const HEADER: usize = 16;

/// The log's size, header included.
const BYTES: usize = HEADER + 2 * patina_dst_trace::MAX_TRACE_BYTES as usize;

/// `map`ped `BYTES` of `fd`, shared, or `None`.
fn map(fd: c_int) -> Option<usize> {
    // SAFETY: a fresh shared mapping of a descriptor this process holds.
    let base = unsafe {
        crate::sud_host_syscall(
            libc::SYS_mmap,
            0,
            BYTES as _,
            (libc::PROT_READ | libc::PROT_WRITE) as _,
            libc::MAP_SHARED as _,
            fd as _,
            0,
        )
    };
    (base > 0).then_some(base as usize)
}

/// The header's two words at `base`.
fn header(base: usize) -> (&'static AtomicU64, &'static AtomicU64) {
    // SAFETY: `base` is a live mapping of `BYTES`, page-aligned, which
    // stays mapped while its owner lives; the words are only ever
    // accessed atomically.
    unsafe {
        (
            &*(base as *const AtomicU64),
            &*((base + 8) as *const AtomicU64),
        )
    }
}

/// The hub's side of child `pid`'s log.
pub(super) struct HubLog {
    base: usize,
    /// How many committed bytes the hub has read.
    read: usize,
}

impl HubLog {
    /// A fresh log, and the descriptor (close-on-exec) the child maps it by.
    pub(super) fn create() -> (Self, c_int) {
        // SAFETY: a static name; the flags are plain.
        let fd = unsafe {
            crate::sud_host_syscall(
                libc::SYS_memfd_create,
                c"patina-process-decisions".as_ptr() as _,
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
                crate::sud_host_syscall(libc::SYS_ftruncate, fd as _, BYTES as _, 0, 0, 0, 0)
            } != 0
        {
            protocol_fatal_text("creating a process's decision log failed");
        }
        let base = map(fd).unwrap_or_else(|| protocol_fatal_text("mapping a decision log failed"));
        (Self { base, read: 0 }, fd)
    }

    /// The decisions committed since the last call. The child is frozen or
    /// gone while the hub reads.
    pub(super) fn take(&mut self) -> Vec<u8> {
        let (committed, _) = header(self.base);
        let committed = (committed.load(Ordering::Acquire) as usize).min(BYTES - HEADER);
        let start = self.base + HEADER + self.read;
        // SAFETY: inside the mapping, past what was read, up to what the
        // child committed.
        let bytes =
            unsafe { std::slice::from_raw_parts(start as *const u8, committed - self.read) }
                .to_vec();
        self.read = committed;
        bytes
    }
}

impl Drop for HubLog {
    fn drop(&mut self) {
        // SAFETY: unmaps this log's own mapping.
        unsafe {
            crate::sud_host_syscall(libc::SYS_munmap, self.base as _, BYTES as _, 0, 0, 0, 0)
        };
    }
}

/// A recording child's trace channel: every decision goes to the log as it
/// is recorded, and nothing is written at its end (the root writes the
/// run's trace).
pub(crate) struct DecisionLog {
    base: usize,
    written: usize,
}

impl DecisionLog {
    /// The log the hub handed this child, as descriptor `fd`.
    pub(crate) fn open(fd: c_int) -> Result<Self, patina_dst_runtime::RuntimeError> {
        let base = map(fd).ok_or_else(|| {
            patina_dst_runtime::RuntimeError::Config(format!(
                "{} must name the process's decision log",
                patina_dst_runtime::ENV_TRACE_FD
            ))
        })?;
        close(fd);
        Ok(Self { base, written: 0 })
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
    fn write_prefix(&mut self, _recorder: &patina_dst_trace::Recorder) -> std::io::Result<()> {
        Ok(())
    }
    fn decision(&mut self, operation: &Operation, outcome: &Outcome) {
        let (committed, full) = header(self.base);
        if full.load(Ordering::Relaxed) != 0 {
            return;
        }
        // SAFETY: the mapping's room past what is written.
        let room = unsafe {
            std::slice::from_raw_parts_mut(
                (self.base + HEADER + self.written) as *mut u8,
                BYTES - HEADER - self.written,
            )
        };
        let mut cursor = std::io::Cursor::new(room);
        let fits = serde_json::to_writer(&mut cursor, &(operation, outcome)).is_ok()
            && std::io::Write::write_all(&mut cursor, b"\n").is_ok();
        if !fits {
            full.store(1, Ordering::Release);
            return;
        }
        self.written += cursor.position() as usize;
        committed.store(self.written as u64, Ordering::Release);
    }
}
