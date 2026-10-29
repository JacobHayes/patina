//! Two copies of `std` in one process: the guest's, and the sealed engine's
//! private one. `tls`: guest thread-local destructors make door calls at
//! thread exit, after the engine's copy registered thread-locals of its own on
//! the same thread. `park`: guest threads park, wait on a condvar and race a
//! blocking `OnceLock` initialisation while the engine's copy takes its own
//! locks on every door. `zone`: guest threads make their first `localtime_r`
//! calls at once, while the engine's choice of zone, which reads the
//! filesystem, is still in progress. `engine-panic` (a test-panic shim): a panic inside the
//! engine is the engine's copy's, so the guest's hook and `catch_unwind` never
//! see it.
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Sends, as its thread exits, what door calls answer then.
struct AtExit {
    id: u64,
    report: Sender<String>,
}

impl Drop for AtExit {
    fn drop(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!("two-copy-{}", self.id));
        std::fs::write(&path, now.as_nanos().to_string()).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        self.report
            .send(format!("{}:{read}:{}", self.id, std::process::id()))
            .unwrap();
        EXITED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Destructors finished: a join waits for its thread's.
static EXITED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static AT_EXIT: RefCell<Option<AtExit>> = const { RefCell::new(None) };
}

fn tls() {
    let (report, reports) = channel();
    let threads: Vec<_> = (0..3)
        .map(|id| {
            let report = report.clone();
            std::thread::spawn(move || {
                // Registered first, so it runs last of the guest's, and
                // before the task completes.
                AT_EXIT.with(|slot| *slot.borrow_mut() = Some(AtExit { id, report }));
                // Doors after it, which the engine's copy serves with
                // thread-locals of its own.
                std::thread::sleep(Duration::from_millis(1 + id));
                let _ = std::fs::metadata("/");
            })
        })
        .collect();
    drop(report);
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        EXITED.load(Ordering::SeqCst),
        3,
        "a join returned before its thread's destructors ran"
    );
    let mut lines: Vec<String> = reports.iter().collect();
    lines.sort();
    assert_eq!(lines.len(), 3, "{lines:?}");
    println!("TWO_COPY_TLS={}", lines.join(","));
}

fn park() {
    static ONCE: OnceLock<u64> = OnceLock::new();
    static INITS: AtomicU64 = AtomicU64::new(0);
    static WOKEN: AtomicBool = AtomicBool::new(false);
    let arrivals = Arc::new((Mutex::new(0u32), Condvar::new()));
    let main = std::thread::current();
    let waker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(3));
        WOKEN.store(true, Ordering::SeqCst);
        main.unpark();
    });
    let threads: Vec<_> = (0..4u64)
        .map(|id| {
            let arrivals = Arc::clone(&arrivals);
            std::thread::spawn(move || {
                // Contended initialisation: the others block on the winner.
                let value = *ONCE.get_or_init(|| {
                    INITS.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(2));
                    40 + id
                });
                let (count, ready) = &*arrivals;
                *count.lock().unwrap() += 1;
                ready.notify_all();
                value
            })
        })
        .collect();
    while !WOKEN.load(Ordering::SeqCst) {
        std::thread::park();
    }
    let (count, ready) = &*arrivals;
    drop(ready.wait_while(count.lock().unwrap(), |count| *count < 4).unwrap());
    waker.join().unwrap();
    let values: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(values.iter().all(|value| Some(value) == ONCE.get()), "{values:?}");
    assert_eq!(INITS.load(Ordering::SeqCst), 1);
    println!("TWO_COPY_PARK={}", values[0]);
}

#[cfg(patina_test_clock_panic)]
fn engine_panic() {
    unsafe extern "C" {
        fn patina_clock_now(clock: u32, nanos: *mut u64) -> i32;
        fn patina_test_arm_clock_panic();
    }
    std::panic::set_hook(Box::new(|_| eprintln!("GUEST_HOOK")));
    let caught = std::panic::catch_unwind(|| {
        let mut nanos = 0;
        // SAFETY: the shim's ABI, armed to panic inside the engine.
        unsafe {
            patina_test_arm_clock_panic();
            patina_clock_now(1, &mut nanos);
        }
    });
    println!("GUEST_CAUGHT={}", caught.is_err());
}

unsafe extern "C" {
    fn localtime_r(time: *const i64, out: *mut [i64; 16]) -> *mut [i64; 16];
}

/// Eight first `localtime_r` calls released together.
fn zone() {
    let start = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                let mut out = [0i64; 16];
                // SAFETY: a live time and a buffer larger than `struct tm`.
                !unsafe { localtime_r(&0, &mut out) }.is_null()
            })
        })
        .collect();
    let converted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|converted| *converted)
        .count();
    println!("TWO_COPY_ZONE={converted}");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("tls") => tls(),
        Some("park") => park(),
        Some("zone") => zone(),
        #[cfg(patina_test_clock_panic)]
        Some("engine-panic") => engine_panic(),
        other => panic!("unknown mode {other:?}"),
    }
}
