//! A streamed trace read holds memory bounded by the trace's structure and its
//! largest decision, not by how many decisions it has.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use patina_dst_abi::{Fd, Operation, Outcome};
use patina_dst_trace::{RunMetadata, TraceBundle, TraceEvent, TraceStream};

const MAIN_TIMELINE: &str = "main";

/// Counts the heap the current thread holds, and its peak, so the measure is
/// this test's alone even when other tests run alongside it.
struct ThreadHeap;

thread_local! {
    static HELD: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn adjust(delta: isize) {
    // A thread being torn down has no counters left; its frees don't matter.
    let _ = HELD.try_with(|held| {
        let now = held.get() + delta;
        held.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

unsafe impl GlobalAlloc for ThreadHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        adjust(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        adjust(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        adjust(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: ThreadHeap = ThreadHeap;

/// The most heap, beyond what was held on entry, `read` holds at once.
fn peak_heap_of(read: impl FnOnce()) -> isize {
    let base = HELD.with(Cell::get);
    PEAK.with(|peak| peak.set(base));
    read();
    PEAK.with(Cell::get) - base
}

/// Write a trace of `decisions` reads of 256 bytes each and return its size.
fn write_trace(path: &std::path::Path, decisions: u64) -> u64 {
    let events = (0..decisions)
        .map(|index| {
            TraceEvent::new(
                index,
                Operation::FsRead {
                    fd: Fd(3),
                    max_len: 256,
                },
                Outcome::Bytes(vec![index as u8; 256]),
            )
        })
        .collect();
    TraceBundle::new(RunMetadata::new(1, "fingerprint", 0, "patina"), events)
        .write_atomic(path)
        .unwrap();
    std::fs::metadata(path).unwrap().len()
}

fn read_all(path: &std::path::Path) -> u64 {
    let mut stream = TraceStream::open(path).unwrap();
    let mut seen = 0;
    stream
        .for_each_resolved(MAIN_TIMELINE, |_| {
            seen += 1;
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    seen
}

#[test]
fn streaming_a_trace_holds_no_more_for_more_decisions() {
    let directory = tempfile::tempdir().unwrap();
    let small = directory.path().join("small.patina");
    let large = directory.path().join("large.patina");
    let small_bytes = write_trace(&small, 2_000);
    let large_bytes = write_trace(&large, 32_000);

    let small_peak = peak_heap_of(|| assert_eq!(read_all(&small), 2_000));
    let large_peak = peak_heap_of(|| assert_eq!(read_all(&large), 32_000));

    // Sixteen times the decisions (some 15 MB more trace) cost no more heap
    // than a small trace's read plus slack for allocator rounding.
    let growth = large_peak - small_peak;
    assert!(
        growth < (small_bytes as isize) / 4,
        "streaming peak grew by {growth} bytes from a {small_bytes}-byte trace to a \
         {large_bytes}-byte one ({small_peak} -> {large_peak})"
    );
    assert!(large_peak < (large_bytes as isize) / 16);
}
