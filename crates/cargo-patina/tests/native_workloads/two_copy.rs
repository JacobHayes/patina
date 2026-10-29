//! The sealed engine's `std` is a second copy beside the guest's: one thread
//! carries both copies' thread-locals, the guest's parking reaches the futex
//! model while the engine's waits on the host, and a panic belongs to the
//! copy that raised it.

use super::*;

/// Guest thread-local destructors run on the live task, after the engine's
/// copy registered thread-locals of its own on the same thread: the doors
/// they call answer, and a recording replays them.
#[test]
fn guest_thread_local_destructors_reach_the_doors_beside_the_engines_copy() {
    let g = Guest::assert_build("two_copy_probe.rs");
    let out = g.assert_run_success(1, &["--", "tls"]).stdout;
    let exits = assert_unique_line_payload(&out, "TWO_COPY_TLS=");
    assert_eq!(exits.split(',').count(), 3, "{exits}");
}

/// Guest parking, condvar waits and a contended blocking `OnceLock`
/// initialisation reach the futex model while the engine's copy takes its own
/// locks, deterministically for a seed.
#[test]
fn guest_parking_reaches_the_futex_model_beside_the_engines_copy() {
    let g = Guest::assert_build("two_copy_probe.rs");
    for seed in [1, 2, 3] {
        let out = g.assert_run_success(seed, &["--", "park"]).stdout;
        assert_unique_line_payload(&out, "TWO_COPY_PARK=");
    }
}

/// The engine's own once-cells and locks wait on the host, so one held
/// across a scheduling point would hold the guest that waits on it, and the
/// baton with it: concurrent first `localtime_r` calls, whose zone choice
/// reads the filesystem, all convert.
#[test]
fn concurrent_first_calls_into_a_yielding_engine_initialiser_complete() {
    let g = Guest::assert_build("two_copy_probe.rs");
    for seed in [1, 2, 3] {
        let out = g.assert_run_success(seed, &["--", "zone"]).stdout;
        assert_eq!(assert_unique_line_payload(&out, "TWO_COPY_ZONE="), "8");
    }
}

/// A panic inside the engine is its own copy's: the engine's hook reports it
/// and aborts, while the guest's replacement hook and the guest's
/// `catch_unwind` around the call never see it. (Linked over a shared `std`,
/// the guest's hook replaced the engine's.)
#[test]
fn an_engine_panic_escapes_the_guests_hook_and_catch_unwind() {
    use std::os::unix::process::ExitStatusExt;
    let built = common::test_panic_shim("unwind", 0);
    let sealed = common::sealed_shim("test-panic-unwind", &built.archive, &[]);
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("engine-panic");
    let mut rustc = std::process::Command::new("rustc");
    rustc
        .arg("--edition=2024")
        .args(["--cfg", "patina_test_clock_panic"])
        .arg(guest_source("two_copy_probe.rs"))
        .arg("-o")
        .arg(&binary);
    for object in &sealed {
        rustc
            .arg("-C")
            .arg(format!("link-arg={}", object.display()));
    }
    for arg in common::shim_rustc_link_args(&built.archive, dir.path()) {
        rustc.arg("-C").arg(arg);
    }
    assert_success(rustc.output().unwrap());
    let guest = Guest { dir, binary };
    let (output, _) = guest.record_standalone(&["engine-panic"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.signal(), Some(6), "{stderr}");
    assert!(
        stderr.contains("patina native shim panic") && stderr.contains("planted"),
        "the engine's hook did not report its panic: {stderr}"
    );
    assert!(!stderr.contains("GUEST_HOOK"), "{stderr}");
    assert!(!text(&output.stdout).contains("GUEST_CAUGHT"), "{stderr}");
}

/// Every host binding the engine's copy reaches the host through is bound
/// before the guest's `main`, so none resolves its target on a first call,
/// which a signal handler could make. A slot stays empty only for a name the
/// host does not define, as this process's own lookup finds it.
#[test]
fn every_host_binding_is_bound_before_main() {
    use object::{Object, ObjectSymbol};
    let g = Guest::assert_build("host_binding_probe.rs");
    let bytes = std::fs::read(&g.binary).unwrap();
    let file = object::File::parse(&*bytes).unwrap();
    let mut anchor = None;
    let mut slots = Vec::new();
    for symbol in file.symbols() {
        let Ok(name) = symbol.name() else { continue };
        let name = match name.strip_prefix('_') {
            Some(name) if cfg!(target_os = "macos") => name,
            _ => name,
        };
        if name == "PATINA_BINDING_ANCHOR" {
            anchor = Some(symbol.address());
        } else if let Some(door) = name.strip_prefix("patina_slot_") {
            slots.push((door.to_owned(), symbol.address()));
        }
    }
    let anchor = anchor.expect("the probe's anchor symbol");
    assert!(!slots.is_empty(), "the engine has no host binding slots");
    let offsets: Vec<String> = slots
        .iter()
        .map(|(_, address)| (address.wrapping_sub(anchor) as i64).to_string())
        .collect();
    let mut args = vec!["--"];
    args.extend(offsets.iter().map(String::as_str));
    let out = g.assert_run_success(1, &args).stdout;
    let empty = assert_unique_line_payload(&out, "EMPTY_SLOTS=");
    let host_defines = |name: &str| {
        let name = std::ffi::CString::new(name).unwrap();
        // SAFETY: a lookup by a NUL-terminated name.
        !unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) }.is_null()
    };
    let unbound: Vec<&str> = empty
        .split(',')
        .filter(|index| !index.is_empty())
        .map(|index| slots[index.parse::<usize>().unwrap()].0.as_str())
        .filter(|door| host_defines(door))
        .collect();
    assert!(
        unbound.is_empty(),
        "host bindings unbound at main: {unbound:?}"
    );
}
