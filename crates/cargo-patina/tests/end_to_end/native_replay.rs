//! Native replay initialization, abort finalization, and restored guest argv.

use super::*;

/// The replay probe. `argv[1]` selects one of three behaviours.
///
/// * A bootstrap-window entry point ([`BOOTSTRAP_WINDOW_ENTRY_POINTS`]):
///   exercises exactly that interposed entry point and performs no other
///   boundary operation. Any effect that reaches `ensure_runtime` aborts on a
///   stored init error by itself, so a replay leg would pass without proving
///   anything about the entry point under test. Results are checked in-process
///   and a wrong one calls `abort`, which needs no boundary, so a recording's
///   success proves the arm ran. The symbols are the shim's own C ABI (and, for
///   the lock arm, the public symbol the shim strong-defines); all are defined
///   inside the linked binary, so the audit sees no unsupported import.
/// * `abort`: a guest that aborts itself.
/// * Anything else: the guest's boundary op-stream depends on its arguments.
///   It echoes `argv[0]` and its arguments, and writes and reads back a file
///   named by `argv[1]` (default "default"), so a replay run with the wrong
///   arguments diverges mid-run. A thread gives the trace scheduling decisions,
///   and [`IDENTITY_PROBE_TAG`], kept in the image by `#[used]`, is a byte the
///   guest never reads: flipping it changes the executable and nothing the
///   guest does, so only the build identity tells the two apart.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROBE_SOURCE: &str = r#"
unsafe extern "C" {
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> i32;
    fn patina_cpu_time_nanos(nanos: *mut u64) -> i32;
    fn patina_read_link(path: *const u8, buf: *mut u8, len: usize) -> isize;
    fn patina_sleep_until(clock: u32, deadline_nanos: u64) -> i32;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut u32);
    fn os_unfair_lock_trylock(lock: *mut u32) -> bool;
    fn os_unfair_lock_unlock(lock: *mut u32);
}

#[used]
static TAG: [u8; 22] = *b"PATINA-IDENTITY-PROBE0";

const MONOTONIC: u32 = 1;

fn argv_and_identity() {
    let argv: Vec<String> = std::env::args().collect();
    println!("ARGV0={}", argv.first().map(String::as_str).unwrap_or(""));
    let guest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    println!("ARGS={guest:?}");
    let name = guest.first().copied().unwrap_or("default");
    let path = format!("/{name}");
    std::fs::write(&path, name.as_bytes()).unwrap();
    let readback = std::fs::read_to_string(&path).unwrap();
    println!("READBACK={readback}");
    let worker = std::thread::spawn(|| 20u64);
    println!("IDENTITY_PROBE {}", worker.join().unwrap() + 1);
}

fn main() {
    let entry = std::env::args().nth(1).unwrap_or_default();
    match entry.as_str() {
        "clock" => {
            let mut nanos = u64::MAX;
            if unsafe { patina_clock_now(MONOTONIC, &mut nanos) } != 0 {
                std::process::abort();
            }
        }
        // The field shape from the bug report: poll the clock until virtual time
        // moves. A healthy run converges through advance-on-spin; a swallowed
        // init error freezes the clock at zero and this spins at 100% CPU.
        "clock-until" => {
            let mut start = 0u64;
            if unsafe { patina_clock_now(MONOTONIC, &mut start) } != 0 {
                std::process::abort();
            }
            let mut nanos = start;
            while nanos - start <= 10_000_000 {
                if unsafe { patina_clock_now(MONOTONIC, &mut nanos) } != 0 {
                    std::process::abort();
                }
            }
        }
        "cpu-time" => {
            let mut nanos = u64::MAX;
            if unsafe { patina_cpu_time_nanos(&mut nanos) } != 0 {
                std::process::abort();
            }
        }
        // The allocator's init-time config probe. The deterministic filesystem
        // carries no such file either way, so a healthy run answers -1 too.
        "read-link" => {
            let mut buf = [0u8; 64];
            let read = unsafe {
                patina_read_link(
                    b"/etc/malloc.conf\0".as_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            };
            if read >= 0 {
                std::process::abort();
            }
        }
        // Not a bootstrap-window path: captured stdio accepts bytes with no
        // context installed, and `patina_shutdown` then drops the buffer.
        "stdout" => {
            println!("BOOTSTRAP_WINDOW_PROBE stdout");
        }
        // Control: an entry point that already consults the stored init error,
        // through `ensure_runtime`. Even a past deadline must still consult it.
        "sleep" => {
            if unsafe { patina_sleep_until(MONOTONIC, 5_000_000) } != 0 {
                std::process::abort();
            }
        }
        #[cfg(target_os = "macos")]
        "unfair-lock" => {
            let mut lock = 0u32;
            unsafe {
                os_unfair_lock_lock(&mut lock);
                os_unfair_lock_unlock(&mut lock);
                if os_unfair_lock_trylock(&mut lock) {
                    os_unfair_lock_unlock(&mut lock);
                }
            }
        }
        "abort" => {
            eprintln!("guest-about-to-abort");
            std::process::abort();
        }
        _ => argv_and_identity(),
    }
}
"#;

/// Every entry point known to answer WITHOUT reaching `ensure_runtime`, as an
/// argument to [`PROBE_SOURCE`]. The first five and the macOS lock arm are the
/// shim-bootstrap window; `stdout` is the captured-stdio path, which answers for
/// the same reason (no context needed) outside the window.
///
/// The window entries pair with the shim's own `bootstrap_window_lints` source
/// lint, which pins the *source* call sites of the window predicate to the same
/// list, so a new bootstrap-window path cannot be added without both the lint
/// and a leg here.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BOOTSTRAP_WINDOW_ENTRY_POINTS: &[&str] = &[
    "clock",
    "clock-until",
    "cpu-time",
    "read-link",
    "stdout",
    "sleep",
    #[cfg(target_os = "macos")]
    "unfair-lock",
];

/// The inert tag in [`PROBE_SOURCE`], found in the built executable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const IDENTITY_PROBE_TAG: &[u8] = b"PATINA-IDENTITY-PROBE0";

/// Copy `source` to `dest` with one byte of its inert tag changed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn flip_identity_probe_byte(source: &Path, dest: &Path) {
    let mut bytes = fs::read(source).unwrap();
    let at = bytes
        .windows(IDENTITY_PROBE_TAG.len())
        .position(|window| window == IDENTITY_PROBE_TAG)
        .expect("the built probe carries its tag");
    bytes[at + IDENTITY_PROBE_TAG.len() - 1] = b'1';
    fs::write(dest, bytes).unwrap();
    fs::set_permissions(dest, fs::metadata(source).unwrap().permissions()).unwrap();
}

/// Rewrite `source` into `dest` without `metadata.native`, as a trace recorded
/// before build identities, or by something other than the native supervisor,
/// reads.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn strip_native_identity(source: &Path, dest: &Path) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
    let removed = value["metadata"].as_object_mut().unwrap().remove("native");
    assert!(
        removed.is_some(),
        "the recorded trace was expected to carry a native build identity before stripping"
    );
    fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
}

/// Copy the trace at `source` to `dest` as though another `cargo-patina` build
/// with the same package version had recorded it.
fn record_as_another_supervisor_build(source: &Path, dest: &Path) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
    let native = value["metadata"]["native"].as_object_mut().unwrap();
    let another = format!("sha256:{}", "0".repeat(64));
    assert_ne!(native["supervisor_sha256"], another);
    native.insert("supervisor_sha256".into(), another.into());
    fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
}

/// The `sha256:` text digest of the file at `path`.
fn file_digest(path: &Path) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(fs::read(path).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
#[path = "native_replay/tests.rs"]
mod tests;
