//! Tests for host state, configuration, clocks, stdio, datagrams, polling, and finalization.

use super::*;
use crate::execute_preview1;
use crate::tests::seeded_context;
use patina_dst_runtime::RuntimeConfig;
use tempfile::tempdir;

pub(super) fn exercise(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
    let mut random = vec![0; 16];
    host.random_get(&mut random)?;
    let start = host.clock_time_get(WasiClock::Monotonic)?;
    host.sleep_until(WasiClock::Monotonic, start + 25)?;
    assert_eq!(host.clock_time_get(WasiClock::Monotonic)? - start, 25);
    assert_eq!(host.fd_write(1, &[b"hello", b" wasi"])?, 10);
    Ok(random)
}

#[test]
fn host_capture_is_explicit_and_fail_closed() {
    let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let mut host = Preview1Host::new(context)
        .with_argument("app.wasm")
        .with_environment("MODE", "test");
    exercise(&mut host).unwrap();
    assert_eq!(host.arguments(), ["app.wasm"]);
    assert_eq!(host.environment()["MODE"], "test");
    assert_eq!(host.stdout(), b"hello wasi");
    assert!(matches!(
        host.fd_write(3, &[b"host"]),
        Err(WasiHostError::DeniedFd(3))
    ));
    host.finish().unwrap();
}

#[test]
fn process_and_scheduler_imports_have_deterministic_local_results() {
    let context = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
    let host = Preview1Host::new(context);
    assert_eq!(host.sched_yield(), WASI_ERRNO_SUCCESS);
    assert_eq!(host.proc_raise(9), WASI_ERRNO_NOSYS);
    assert_eq!(host.sock_accept(4, 0), WASI_ERRNO_NOSYS);
    host.finish().unwrap();
}

#[test]
fn configured_wasi_datagrams_use_the_virtual_network() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "sock_send"
                    (func $send (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "sock_recv"
                    (func $recv (param i32 i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "sock_shutdown"
                    (func $shutdown (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\20\00\00\00\05\00\00\00")
                (data (i32.const 8) "\40\00\00\00\05\00\00\00")
                (data (i32.const 32) "hello")
                (func (export "_start")
                    i32.const 4 i32.const 0 i32.const 1 i32.const 0 i32.const 100
                    call $send
                    if unreachable end
                    i32.const 5 i32.const 8 i32.const 1 i32.const 0 i32.const 104 i32.const 108
                    call $recv
                    if unreachable end
                    i32.const 64 i32.load i32.const 1819043176 i32.ne
                    if unreachable end
                    i32.const 68 i32.load8_u i32.const 111 i32.ne
                    if unreachable end
                    i32.const 4 i32.const 3 call $shutdown
                    if unreachable end))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(17)).unwrap();
    let host = Preview1Host::new(context)
        .with_datagram_socket(4, "node-a", "node-b")
        .unwrap()
        .with_datagram_socket(5, "node-b", "node-a")
        .unwrap();
    assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
}

// Class pairing: runtime boot_origin::relative_sleep_saturates_at_the_deadline_limit.
#[test]
fn relative_poll_saturates_without_hiding_an_earlier_timer() {
    for clock in [WasiClock::Monotonic, WasiClock::Realtime] {
        let mut host = Preview1Host::new(Context::from_config(RuntimeConfig::seeded(1)).unwrap());
        let start = host.clock_time_get(clock).unwrap();
        let ready = host
            .poll(&[
                WasiSubscription::Clock {
                    userdata: 1,
                    clock,
                    deadline: u64::MAX,
                    absolute: false,
                },
                WasiSubscription::Clock {
                    userdata: 2,
                    clock,
                    deadline: 10,
                    absolute: false,
                },
            ])
            .unwrap();
        assert_eq!(ready, vec![(2, 0, 0)]);
        assert_eq!(host.clock_time_get(clock).unwrap(), start + 10);
        host.finish().unwrap();
    }
}

#[test]
fn random_and_clock_calls_record_and_replay() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("wasi.patina");
    let context = Context::from_config(RuntimeConfig::record(42, &trace, "wasi-v1")).unwrap();
    let mut record = Preview1Host::new(context);
    let expected = exercise(&mut record).unwrap();
    record.finish().unwrap();

    let context = Context::from_config(RuntimeConfig::replay(&trace, "wasi-v1")).unwrap();
    let mut replay = Preview1Host::new(context);
    assert_eq!(exercise(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}

// `Preview1Host::sleep_until` applies the seeded sleep-latency jitter at the
// single guest-facing sleep entry (which also backs `poll_oneoff` timeouts):
// the same seed and range wake at the same inflated deadline, a different range
// changes it, an unjittered run is unchanged, and record/replay reproduces the
// wake time byte-for-byte.
#[test]
fn sleep_jitter_is_deterministic_and_reproduces_on_replay() {
    fn woke_at(seed: u64, range: Option<&str>) -> u64 {
        let mut config = RuntimeConfig::seeded(seed);
        if let Some(range) = range {
            config = config
                .apply_fault_env(|name| {
                    (name == patina_dst_runtime::ENV_SLEEP_JITTER).then(|| range.to_string())
                })
                .unwrap();
        }
        let mut host = Preview1Host::new(Context::from_config(config).unwrap());
        let start = host.clock_time_get(WasiClock::Monotonic).unwrap();
        host.sleep_until(WasiClock::Monotonic, start + 1_000)
            .unwrap();
        host.clock_time_get(WasiClock::Monotonic).unwrap() - start
    }

    // No jitter: the clock advances exactly to the requested deadline.
    assert_eq!(woke_at(1, None), 1_000);
    // Same seed and range: identical jittered wake, within [1100, 1200].
    let first = woke_at(7, Some("100..200"));
    assert_eq!(first, woke_at(7, Some("100..200")));
    assert!((1_100..=1_200).contains(&first));
    // A different jitter range changes the schedule.
    assert_ne!(first, woke_at(7, Some("500..600")));

    // Record with jitter, then a flag-free replay reproduces the exact wake
    // time: the draw is owned by the deterministic context and restored from
    // the trace's fault configuration.
    let directory = tempdir().unwrap();
    let trace = directory.path().join("jitter.patina");
    let recorded = {
        let config = RuntimeConfig::record(7, &trace, "jitter-v1")
            .apply_fault_env(|name| {
                (name == patina_dst_runtime::ENV_SLEEP_JITTER).then(|| "100..200".to_string())
            })
            .unwrap();
        let mut host = Preview1Host::new(Context::from_config(config).unwrap());
        let start = host.clock_time_get(WasiClock::Monotonic).unwrap();
        host.sleep_until(WasiClock::Monotonic, start + 1_000)
            .unwrap();
        let now = host.clock_time_get(WasiClock::Monotonic).unwrap();
        host.finish().unwrap();
        now
    };
    let config = RuntimeConfig::replay(&trace, "jitter-v1");
    let mut host = Preview1Host::new(Context::from_config(config).unwrap());
    let start = host.clock_time_get(WasiClock::Monotonic).unwrap();
    host.sleep_until(WasiClock::Monotonic, start + 1_000)
        .unwrap();
    assert_eq!(host.clock_time_get(WasiClock::Monotonic).unwrap(), recorded);
    host.finish().unwrap();
}

#[test]
fn nested_and_duplicate_preopens_are_rejected() {
    let nested = Preview1Host::new(seeded_context(2, &[]))
        .with_preopen("/data", MountPolicy::ReadWrite)
        .unwrap()
        .with_preopen("/data/inner", MountPolicy::ReadWrite);
    assert!(matches!(nested, Err(WasiHostError::PreopenOverlap { .. })));

    let duplicate = Preview1Host::new(seeded_context(2, &[]))
        .with_preopen("/data", MountPolicy::ReadWrite)
        .unwrap()
        .with_preopen("/data", MountPolicy::ReadOnly);
    assert!(matches!(
        duplicate,
        Err(WasiHostError::PreopenOverlap { .. })
    ));

    let bad =
        Preview1Host::new(seeded_context(2, &[])).with_preopen("relative", MountPolicy::ReadWrite);
    assert!(matches!(bad, Err(WasiHostError::InvalidPreopen(_))));
}
