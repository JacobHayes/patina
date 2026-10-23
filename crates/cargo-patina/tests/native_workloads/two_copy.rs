//! The sealed engine's `std` is a second copy beside the guest's: one thread
//! carries both copies' thread-locals, one futex model serves both copies'
//! parking, and a panic belongs to the copy that raised it.

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
/// initialisation reach the futex model the engine's copy parks through too,
/// deterministically for a seed.
#[test]
fn guest_parking_shares_the_futex_model_with_the_engines_copy() {
    let g = Guest::assert_build("two_copy_probe.rs");
    for seed in [1, 2, 3] {
        let out = g.assert_run_success(seed, &["--", "park"]).stdout;
        assert_unique_line_payload(&out, "TWO_COPY_PARK=");
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
