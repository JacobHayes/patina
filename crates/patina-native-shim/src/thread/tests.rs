//! Managed-thread identity and pipe-channel regression tests.

use super::*;

// The `--yield-points` teardown fix must keep "task completed" a state
// distinct from "thread never registered": a completed thread's
// post-finish scheduling points are silently skipped, but a foreign or
// pre-registration thread must still fail loudly. Run on a fresh host
// thread so the thread-locals start at their defaults.
#[test]
fn completed_sentinel_is_distinct_from_never_registered() {
    std::thread::spawn(|| {
        // Never-registered defaults: no task, not completed.
        assert_eq!(current_task(), UNMANAGED_TASK);
        assert!(!task_completed());
        // sched_point on a never-registered thread does NOT take the
        // completed no-op path (it would fall through to the loud
        // reschedule when the subsystem is active).
        mark_task_completed();
        // Completing marks the sentinel WITHOUT aliasing the unregistered
        // task id, so the two states remain distinguishable.
        assert!(task_completed());
        assert_eq!(current_task(), UNMANAGED_TASK);
        // A completed thread takes no scheduling point.
        assert!(sched_point().is_ok());
    })
    .join()
    .unwrap();
}

// The main-thread teardown fix: once the process enters its post-`main`
// teardown window (the `exit` interposer calls `note_main_returned`), the
// ROOT task — which never runs `thread_finish` and so has no per-thread
// completion sentinel — takes NO scheduling point, exactly like a
// completed worker's post-teardown, so its `--yield-points` thread-local
// destructors record zero trailing yields. `MAIN_RETURNED` is process-wide
// (no other test sets it, and none relies on the global `sched_point`
// taking its reschedule path); this test restores it so the teardown state
// never leaks into sibling tests.
#[test]
fn main_returned_silences_the_root_task_scheduling_point() {
    note_main_returned();
    assert!(main_returned());
    // A scheduling point in the teardown window is a no-op, on any thread —
    // never a reschedule against a torn-down scheduler.
    std::thread::spawn(|| assert!(sched_point().is_ok()))
        .join()
        .unwrap();
    MAIN_RETURNED.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(!main_returned());
}

// Pure pipe-channel semantics (the scheduler-integrated parking is covered
// end-to-end by the pipe tests in cargo-patina/tests/native_abi.rs):
// bounded capacity, partial reads, and EOF only after drain.
#[test]
fn pipe_channel_transfers_bytes_with_bounded_capacity_and_eof() {
    let mut channel = PipeChannel::new(4);
    let mut dst = [0u8; 8];
    // Empty + writer open → WouldBlock (the reader parks).
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // Bounded capacity: a write fills it, and the next (atomic, below
    // PIPE_BUF) waits for room for all of it.
    assert_eq!(channel.try_write(b"abcd"), PipeWrite::Wrote(4));
    assert_eq!(channel.try_write(b"ef"), PipeWrite::WouldBlock);
    // A short read frees space for the writer's remaining bytes.
    assert_eq!(channel.try_read(&mut dst[..2]), PipeRead::Read(2));
    assert_eq!(&dst[..2], b"ab");
    assert_eq!(channel.try_write(b"ef"), PipeWrite::Wrote(2));
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(4));
    assert_eq!(&dst[..4], b"cdef");
    // Drained but writer still open → WouldBlock, not EOF.
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // Buffered bytes are delivered before EOF even after the writer closes.
    channel.try_write(b"hi");
    channel.write_refs = 0;
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
    assert_eq!(&dst[..2], b"hi");
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
}

// A FIFO channel is born with NO ends, and every "closed" answer is
// derived from the reference counts rather than latched — which is what
// lets a FIFO's reader or writer side come BACK when it is opened again.
// RED before FIFOs were modeled: `PipeChannel` had no such constructor
// and the two closed flags were one-way latches.
#[test]
fn fifo_channel_starts_endless_and_derives_closedness_from_its_refs() {
    let mut channel = PipeChannel::new_fifo(4, 7);
    assert_eq!(channel.fifo_ino, Some(7));
    assert_eq!((channel.read_refs, channel.write_refs), (0, 0));
    assert_eq!((channel.read_opens, channel.write_opens), (0, 0));
    // No writer: a read is end-of-file, not a park.
    let mut dst = [0u8; 8];
    assert!(channel.read_closed() && channel.write_closed());
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
    // No reader: a write is a broken pipe.
    assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);

    // One opener of each side, as `fifo_open` registers them.
    channel.read_refs += 1;
    channel.write_refs += 1;
    assert!(!channel.read_closed() && !channel.write_closed());
    assert_eq!(channel.try_write(b"hi"), PipeWrite::Wrote(2));
    // Drained with a live writer is a park, not end-of-file.
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // The last writer leaves: end-of-file. A NEW writer revives the
    // channel, which a latched flag could not express.
    channel.write_refs -= 1;
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
    channel.write_refs += 1;
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
}

// `pipe_write`: a write of at most PIPE_BUF bytes is atomic — it waits
// for room for all of it rather than landing in part — while a longer
// one takes what fits.
#[test]
fn pipe_channel_writes_up_to_pipe_buf_atomically() {
    let mut channel = PipeChannel::new(PIPE_BUF + 8);
    let small = [7u8; 16];
    assert_eq!(
        channel.try_write(&[0; PIPE_BUF]),
        PipeWrite::Wrote(PIPE_BUF)
    );
    assert_eq!(channel.try_write(&small), PipeWrite::WouldBlock);
    assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
    let mut dst = [0u8; PIPE_BUF + 8];
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(PIPE_BUF + 8));
    assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
    assert_eq!(
        channel.try_write(&[1; PIPE_BUF + 1]),
        PipeWrite::Wrote(PIPE_BUF)
    );
}

// Writing to a channel whose reader closed is a broken pipe surfaced as an
// errno (EPIPE) — never a signal.
#[test]
fn pipe_channel_write_to_closed_reader_is_broken_pipe() {
    let mut channel = PipeChannel::new(4);
    channel.read_refs = 0;
    assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);
}
