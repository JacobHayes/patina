//! The write-ahead log: append-only segment files, one durable record per queue
//! state transition.
//!
//! Durability contract: the server acks an Enqueue only after [`Wal::append`]
//! reports [`Durability::Durable`], so an acked job is always on stable storage.
//! A cooperative `wal-fsync-skip` does not break that — it *defers* durability
//! ([`Durability::Deferred`], group-commit style) and the ack is withheld until a
//! later flush. Recovery ([`recover`]) truncates a torn tail in the final segment
//! (a crash mid-append) and fails closed on anything a crash cannot explain.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::wire::{frame_record, scan_segment, FramedRecord, ScanEnd, WalRecord};

const SEGMENT_PREFIX: &str = "wal-";
const SEGMENT_SUFFIX: &str = ".seg";

/// Whether an append is on stable storage yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// fsync completed; this record and every earlier one is durable.
    Durable { seq: u64 },
    /// A `wal-fsync-skip` deferred durability; written but not yet fsync'd — the
    /// caller must not ack it until a later flush.
    Deferred { seq: u64 },
}

#[derive(Debug)]
pub enum WalError {
    Io(io::Error),
    /// Fail-closed recovery: a corruption a crash-truncation cannot explain
    /// (mid-log corruption, a torn non-final segment, or a non-monotonic seq).
    Corruption(String),
}

impl WalError {
    /// The verdict label this error reports under. Corruption of the durable log
    /// is a broken invariant of the queue itself; an I/O error is the storage
    /// plane failing under us, which the server refuses to run through but does
    /// not blame on the queue's own logic.
    pub fn verdict_label(&self) -> &'static str {
        match self {
            WalError::Io(_) => "storage-fault",
            WalError::Corruption(_) => "wal-integrity",
        }
    }

    /// Whether this error is a broken durable-state invariant (as opposed to the
    /// storage plane erroring out), so a caller reports it as a `Violation`
    /// rather than an `AbortIntent`.
    pub fn is_corruption(&self) -> bool {
        matches!(self, WalError::Corruption(_))
    }
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalError::Io(e) => write!(f, "wal io error: {e}"),
            WalError::Corruption(d) => write!(f, "wal corruption: {d}"),
        }
    }
}

impl From<io::Error> for WalError {
    fn from(error: io::Error) -> Self {
        WalError::Io(error)
    }
}

/// A fail-closed WAL error handed from a server thread to the driver. `WalError`
/// is not `Clone` (its `io::Error` is not), so the shape the driver reports —
/// the verdict label, whether it is a durable-state violation, and the rendered
/// message — is captured at the point of failure.
#[derive(Clone, Debug)]
pub struct FailClosed {
    pub label: &'static str,
    pub corruption: bool,
    pub message: String,
}

impl From<&WalError> for FailClosed {
    fn from(error: &WalError) -> Self {
        FailClosed {
            label: error.verdict_label(),
            corruption: error.is_corruption(),
            message: error.to_string(),
        }
    }
}

pub struct Recovered {
    pub records: Vec<FramedRecord>,
    pub next_seq: u64,
    pub last_index: u64,
    pub last_len: u64,
}

fn segment_name(index: u64) -> String {
    format!("{SEGMENT_PREFIX}{index:06}{SEGMENT_SUFFIX}")
}

/// Segments are numbered from 0 and never deleted, so recovery probes them by
/// name (a plain `stat`) rather than `read_dir`, whose syscalls are outside
/// Patina's interposed filesystem surface.
///
/// The probe must NOT use `Path::exists()`: it swallows every stat error, so a
/// transient I/O failure reads as "no such segment" and the entire intact log
/// silently vanishes — at startup that corrupts recovery, and in the final
/// audit it fabricates durability violations against a healthy WAL (found by
/// fault-injection campaign: an injected stat error at audit time reported
/// every acked job missing). Only NotFound ends the probe; anything else fails
/// closed.
fn segment_paths(dir: &Path) -> Result<Vec<PathBuf>, WalError> {
    let mut paths = Vec::new();
    for index in 0u64.. {
        let path = dir.join(segment_name(index));
        match fs::metadata(&path) {
            Ok(_) => paths.push(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(WalError::Io(e)),
        }
    }
    Ok(paths)
}

fn framed_len(records: &[FramedRecord]) -> u64 {
    records
        .iter()
        .map(|f| frame_record(f.seq, &f.record).len() as u64)
        .sum()
}

/// Reconstruct the record stream, failing closed on any corruption a crash
/// cannot explain. A torn tail in the final segment is truncated on disk so
/// later appends stay clean.
pub fn recover(dir: &Path) -> Result<Recovered, WalError> {
    let segments = segment_paths(dir)?;
    let mut records: Vec<FramedRecord> = Vec::new();
    let mut last_index = 0u64;
    let mut last_len = 0u64;

    for (position, path) in segments.iter().enumerate() {
        let is_final = position + 1 == segments.len();
        let (mut framed, end) = scan_segment(&fs::read(path)?).map_err(WalError::Corruption)?;
        let good_len = framed_len(&framed);
        if end == ScanEnd::TornTail {
            if !is_final {
                // A rotated segment was fsync'd whole; a torn tail here is real
                // damage, not an in-flight crash.
                return Err(WalError::Corruption(format!(
                    "torn tail in non-final segment {}",
                    path.display()
                )));
            }
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len(good_len)?;
            file.sync_all()?;
        }
        records.append(&mut framed);
        last_index = position as u64;
        last_len = good_len;
    }

    // Sequence numbers must strictly increase across the whole log.
    let mut previous: Option<u64> = None;
    for framed in &records {
        if matches!(previous, Some(prev) if framed.seq <= prev) {
            return Err(WalError::Corruption(format!(
                "sequence not monotonic at {}",
                framed.seq
            )));
        }
        previous = Some(framed.seq);
    }
    let next_seq = previous.map_or(0, |s| s + 1);
    Ok(Recovered {
        records,
        next_seq,
        last_index,
        last_len,
    })
}

pub struct Wal {
    dir: PathBuf,
    file: File,
    index: u64,
    len: u64,
    next_seq: u64,
    segment_bytes: u64,
    durable_seq: u64,
    /// Records written since the last successful fsync.
    dirty: bool,
    /// The `ignore-short-write` bug: append issues one raw `write()` and
    /// ignores the returned count instead of looping to completion.
    ignore_short_write: bool,
}

impl Wal {
    /// Open (recovering existing segments) and position at the end, returning the
    /// recovered records so the caller can rebuild state.
    pub fn open(
        dir: &Path,
        segment_bytes: u64,
        ignore_short_write: bool,
    ) -> Result<(Self, Vec<FramedRecord>), WalError> {
        fs::create_dir_all(dir)?;
        let recovered = recover(dir)?;
        let path = dir.join(segment_name(recovered.last_index));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // Creating the segment is a namespace op: without a parent-dir fsync a
        // crash loses the file itself — and every acked record in it.
        fsync_dir(dir)?;
        let wal = Wal {
            dir: dir.to_path_buf(),
            file,
            index: recovered.last_index,
            len: recovered.last_len,
            next_seq: recovered.next_seq,
            segment_bytes,
            durable_seq: recovered.next_seq.saturating_sub(1),
            dirty: false,
            ignore_short_write,
        };
        Ok((wal, recovered.records))
    }

    /// Append one record, rotating first if the segment is full. Honors two
    /// cooperative buggify sites at the durability boundary: a virtual-time delay
    /// and an fsync-skip that DEFERS (never falsifies) durability.
    pub fn append(&mut self, record: &WalRecord) -> Result<Durability, WalError> {
        let seq = self.next_seq;
        let frame = frame_record(seq, record);
        if self.len > 0 && self.len + frame.len() as u64 > self.segment_bytes {
            self.rotate()?;
        }
        if self.ignore_short_write {
            // Planted bug (`--bug ignore-short-write`): a single raw `write()`,
            // ignoring the returned count instead of looping until the whole
            // frame lands. Under `--fs-short-permille` this silently drops the
            // frame's tail; recovery truncates at the torn frame and the
            // durability invariant (acked-job-missing-from-wal in
            // main.rs::report) catches the vanished record.
            let _ = self.file.write(&frame)?;
        } else {
            self.file.write_all(&frame)?;
        }
        self.file.flush()?;
        self.len += frame.len() as u64;
        self.next_seq += 1;
        self.dirty = true;

        let _ = patina_dst::buggify_delay!("wal-fsync-delay");
        if patina_dst::buggify!("wal-fsync-skip") {
            return Ok(Durability::Deferred { seq }); // durability deferred, not lost
        }
        self.file.sync_all()?;
        self.durable_seq = seq;
        self.dirty = false;
        Ok(Durability::Durable { seq })
    }

    /// Flush deferred records; called each tick so a deferred ack is never
    /// withheld forever. Returns the highest durable seq.
    pub fn flush(&mut self) -> Result<u64, WalError> {
        if self.dirty {
            self.file.sync_all()?;
            self.durable_seq = self.next_seq.saturating_sub(1);
            self.dirty = false;
        }
        Ok(self.durable_seq)
    }

    fn rotate(&mut self) -> Result<(), WalError> {
        self.file.sync_all()?; // close the current segment durably before the next
        self.index += 1;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(segment_name(self.index)))?;
        fsync_dir(&self.dir)?; // the new segment's dir entry must survive a crash
        self.len = 0;
        Ok(())
    }
}

/// Make a directory's entries durable: a created file only survives a crash
/// once its parent directory is fsync'd.
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Drives the real [`recover`] over synthetic segments: a clean log recovers
/// whole, a torn final record recovers by truncation, and mid-log corruption
/// fails closed. `Err(detail)` if recovery misbehaves on any case.
pub fn recovery_fail_closed_selftest(scratch: &Path) -> Result<(), String> {
    use crate::wire::WalRecord::*;
    let write_segment = |sub: &str, bytes: &[u8]| -> Result<PathBuf, String> {
        let dir = scratch.join(sub);
        fs::create_dir_all(&dir).map_err(|e| format!("scratch: {e}"))?;
        let mut file =
            File::create(dir.join(segment_name(0))).map_err(|e| format!("scratch: {e}"))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("scratch: {e}"))?;
        Ok(dir)
    };

    // (a) A clean two-record log recovers both records.
    let mut clean = frame_record(0, &Enqueue(1, 0, 0, 0, 1));
    clean.extend_from_slice(&frame_record(1, &Complete(1)));
    let dir = write_segment("clean", &clean)?;
    if recover(&dir)
        .map_err(|e| format!("clean must recover: {e}"))?
        .records
        .len()
        != 2
    {
        return Err("clean recovery lost a record".into());
    }

    // (b) A torn final record recovers by truncation to the intact prefix.
    let mut torn = clean.clone();
    torn.truncate(torn.len() - 4);
    let dir = write_segment("torn", &torn)?;
    if recover(&dir)
        .map_err(|e| format!("torn must recover: {e}"))?
        .records
        .len()
        != 1
    {
        return Err("torn recovery did not truncate to the intact prefix".into());
    }

    // (c) Mid-log corruption (a bad record with a valid one after it) fails
    //     closed, NOT silently dropping the committed suffix.
    let mut corrupt = frame_record(0, &Complete(1));
    let flip = corrupt.len() + 10;
    corrupt.extend_from_slice(&frame_record(1, &Complete(2)));
    corrupt.extend_from_slice(&frame_record(2, &Complete(3)));
    corrupt[flip] ^= 0xFF;
    let dir = write_segment("corrupt", &corrupt)?;
    match recover(&dir) {
        Err(WalError::Corruption(_)) => Ok(()),
        Err(other) => Err(format!("mid-log corruption gave wrong error: {other}")),
        Ok(_) => Err("mid-log corruption did NOT fail closed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WalRecord;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("workq-wal-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn append_recovers_across_rotation() {
        let dir = tempdir("rot");
        let (mut wal, existing) = Wal::open(&dir, 32, false).unwrap(); // tiny: forces rotation
        assert!(existing.is_empty());
        for job in 0..20u64 {
            wal.append(&WalRecord::Complete(job)).unwrap();
        }
        drop(wal);
        assert!(
            segment_paths(&dir).expect("probe").len() > 1,
            "expected rotation"
        );
        let (_wal, records) = Wal::open(&dir, 32, false).unwrap();
        assert_eq!(records.len(), 20);
        assert_eq!(records[19].record, WalRecord::Complete(19));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn selftest_passes_on_a_correct_recoverer() {
        let scratch = tempdir("selftest");
        recovery_fail_closed_selftest(&scratch).expect("recovery selftest must pass");
        let _ = fs::remove_dir_all(&scratch);
    }
}
