//! The event journal: every event line the probe emits, kept a second time in
//! the probe's own memory, so a harness that kills a hung run can still read
//! what it recorded.
//!
//! Under patina the guest's stdout is captured in memory and flushed only at
//! exit (the shim's `patina_stdio_write`), and its files live in the virtual
//! filesystem, so a run killed at a deadline leaves no event on the host.
//! The journal is the one channel that survives: a `#[no_mangle]` static the
//! harness (an ancestor of the guest, so allowed to read its memory) finds
//! through the binary's symbol table and reads from `/proc/<pid>/mem`. It
//! costs no system call, so it changes nothing the run records or replays.
//!
//! `started` doubles as the start marker: the probe sets it before the
//! scenario's first call, so a journal with no event and `started` set means
//! the guest got past its startup and then made no progress.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// The journal's symbol in the probe binary.
pub const SYMBOL: &str = "PATINA_CONFORMANCE_JOURNAL";
/// `started`'s value once the probe reached its scenario ("patinaJ1").
pub const STARTED: u64 = 0x7061_7469_6e61_4a31;
/// `len`'s value once an event no longer fit: the journal is incomplete.
pub const OVERFLOWED: u64 = u64::MAX;
/// The bytes the journal holds (every scenario's stream fits many times).
pub const CAPACITY: usize = 1 << 18;
/// Byte offsets of the fields, for a reader of the raw memory.
pub const STARTED_AT: u64 = 0;
pub const LEN_AT: u64 = 8;
pub const BYTES_AT: u64 = 16;

/// The journal's layout: all zero until the probe starts, so it lives in
/// `.bss` and costs the binary nothing.
#[repr(C)]
pub struct Journal {
    started: AtomicU64,
    len: AtomicU64,
    bytes: UnsafeCell<[u8; CAPACITY]>,
}

// SAFETY: `bytes` is written only by `append`, which the recorder calls
// under its lock; readers outside the process see it through `len`.
unsafe impl Sync for Journal {}

#[unsafe(no_mangle)]
#[used]
pub static PATINA_CONFORMANCE_JOURNAL: Journal = Journal {
    started: AtomicU64::new(0),
    len: AtomicU64::new(0),
    bytes: UnsafeCell::new([0; CAPACITY]),
};

/// Mark the probe as started (its scenario is about to run).
pub fn start() {
    PATINA_CONFORMANCE_JOURNAL
        .started
        .store(STARTED, Ordering::Release);
}

/// Append one event line and its newline. Called under the recorder's lock.
pub(crate) fn append(line: &[u8]) {
    let journal = &PATINA_CONFORMANCE_JOURNAL;
    let len = journal.len.load(Ordering::Acquire);
    if len == OVERFLOWED {
        return;
    }
    let at = len as usize;
    if at + line.len() + 1 > CAPACITY {
        journal.len.store(OVERFLOWED, Ordering::Release);
        return;
    }
    // SAFETY: the recorder's lock serializes appends; the range is in bounds.
    unsafe {
        let bytes = &mut *journal.bytes.get();
        bytes[at..at + line.len()].copy_from_slice(line);
        bytes[at + line.len()] = b'\n';
    }
    journal
        .len
        .store((at + line.len() + 1) as u64, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The raw layout a reader outside the process relies on: the marker at
    /// `STARTED_AT`, the length at `LEN_AT`, the lines from `BYTES_AT`.
    #[test]
    fn the_raw_layout_is_the_documented_one() {
        start();
        append(b"{\"seq\":0}");
        append(b"{\"seq\":1}");
        let base = &PATINA_CONFORMANCE_JOURNAL as *const Journal as *const u8;
        // SAFETY: reads within the static.
        let (started, len, bytes) = unsafe {
            let started = (base.add(STARTED_AT as usize) as *const u64).read();
            let len = (base.add(LEN_AT as usize) as *const u64).read();
            let bytes = std::slice::from_raw_parts(base.add(BYTES_AT as usize), len as usize);
            (started, len, bytes.to_vec())
        };
        assert_eq!(started, STARTED);
        assert_eq!(len, 20);
        assert_eq!(bytes, b"{\"seq\":0}\n{\"seq\":1}\n");
        append(&vec![b'x'; CAPACITY]);
        assert_eq!(
            PATINA_CONFORMANCE_JOURNAL.len.load(Ordering::Acquire),
            OVERFLOWED
        );
    }
}
