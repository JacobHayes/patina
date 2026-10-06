//! Tests for audited Wasmi execution, fuel accounting, and guest outcomes.

use super::*;
use crate::ResourceLimits;
use patina_dst_runtime::{Context, RuntimeConfig};

#[test]
fn wasm_instruction_fuel_bounds_modules_without_boundary_calls() {
    let module = wat::parse_str(
        r#"(module
                (memory (export "memory") 1)
                (func (export "_start") (loop $forever (br $forever))))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let error = execute_preview1_with_fuel(&module, Preview1Host::new(context), 1_000).unwrap_err();
    assert!(matches!(error, WasiRunError::Engine(_)));
    assert!(error.to_string().to_ascii_lowercase().contains("fuel"));
}

// R20 engine-determinism knob: the `simd` cargo feature is deliberately off,
// so a module using a SIMD (v128) instruction must be REJECTED at validation.
// This keeps relaxed-SIMD — the one Wasm proposal with implementation-defined
// (nondeterministic) results — out of reach: were the feature ever enabled,
// relaxed-SIMD is enabled-by-default within it, and this module would load and
// run with results that could differ across engines/hosts. If this test ever
// starts failing because SIMD was turned on, `deterministic_wasmi_config` must
// add `config.wasm_relaxed_simd(false)` before the module is admitted.
#[test]
pub(super) fn simd_module_is_rejected() {
    let module = wat::parse_str(
        r#"(module
                (memory (export "memory") 1)
                (func (export "_start")
                    (drop (v128.const i32x4 0 0 0 0))))"#,
    )
    .unwrap();
    let engine = Engine::new(&deterministic_wasmi_config());
    let error = Module::new(&engine, &module)
        .expect_err("a SIMD module must be rejected while the wasmi `simd` feature is off");
    // A validation/decoding rejection, not a silent acceptance.
    let text = error.to_string().to_ascii_lowercase();
    assert!(
        text.contains("simd") || text.contains("v128") || text.contains("feature"),
        "SIMD rejection should name the disabled proposal, got: {error}"
    );
}

// R20 engine-determinism knob: wasmi is a pure interpreter with no NaN
// canonicalization knob, so a NaN-producing float op must yield the SAME bit
// pattern on every run. Pinning this means an upstream change that (e.g.)
// introduced canonicalization or nondeterministic NaN bits would fail loudly
// here rather than silently perturbing guest-observable float results.
#[test]
pub(super) fn nan_bits_are_deterministic() {
    // sqrt(-1) is a canonical NaN source; reinterpret to i64 to observe the
    // exact bit pattern the interpreter produced.
    let module = wat::parse_str(
        r#"(module
                (func (export "nan_bits") (result i64)
                    (i64.reinterpret_f64 (f64.sqrt (f64.const -1)))))"#,
    )
    .unwrap();
    let nan_bits = || -> i64 {
        let engine = Engine::new(&deterministic_wasmi_config());
        let module = Module::new(&engine, &module).unwrap();
        let mut store = Store::new(&engine, ());
        // Fuel metering is on in the pinned config, so the store must be
        // funded before any guest instruction runs.
        store.set_fuel(1_000_000).unwrap();
        let instance = Linker::<()>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .unwrap();
        instance
            .get_typed_func::<(), i64>(&store, "nan_bits")
            .unwrap()
            .call(&mut store, ())
            .unwrap()
    };
    let first = nan_bits();
    let second = nan_bits();
    assert_eq!(first, second, "NaN bit pattern was not reproducible");
    // It is genuinely a NaN (all exponent bits set, non-zero mantissa), so the
    // determinism is over a real NaN result rather than a trivial constant.
    let bits = first as u64;
    assert_eq!(bits & 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000);
    assert_ne!(bits & 0x000f_ffff_ffff_ffff, 0);
}

#[test]
fn memory_growth_cap_traps_deterministically_and_is_replayable() {
    let module = wat::parse_str(
        r#"(module
                (memory 1)
                (func (export "_start")
                    (drop (memory.grow (i32.const 100)))))"#,
    )
    .unwrap();

    let capped = || {
        let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        let host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
            max_memory_pages: 2,
            ..ResourceLimits::default()
        });
        execute_preview1(&module, host)
    };
    // Exceeding the cap is a deterministic trap on every run.
    assert!(matches!(capped(), Err(WasiRunError::Engine(_))));
    assert!(matches!(capped(), Err(WasiRunError::Engine(_))));

    // A generous cap admits the same growth.
    let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
    let host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
        max_memory_pages: 256,
        ..ResourceLimits::default()
    });
    assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
}

/// A guest whose hostcall mix is fixed by the module text, so the counters
/// can be asserted exactly rather than "greater than zero". Mutating any
/// wrapper's counting line drives its row to absent and fails this test.
fn depth_probe_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $write (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get"
                    (func $random (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "depth\n")
                (func (export "_start")
                    (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 8)))
                    (drop (call $clock (i32.const 1) (i64.const 0) (i32.const 8)))
                    (drop (call $clock (i32.const 1) (i64.const 0) (i32.const 8)))
                    (drop (call $random (i32.const 96) (i32.const 8)))
                    (i32.store (i32.const 0) (i32.const 64))
                    (i32.store (i32.const 4) (i32.const 6))
                    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1)
                        (i32.const 16)))))"#,
    )
    .unwrap()
}

fn run_depth_probe(seed: u64) -> WasiExecution {
    let context = Context::from_config(RuntimeConfig::seeded(seed)).unwrap();
    execute_preview1(&depth_probe_module(), Preview1Host::new(context)).unwrap()
}

#[test]
fn hostcall_counters_record_every_import_call_exactly() {
    let execution = run_depth_probe(7);
    assert_eq!(execution.hostcalls.get("clock_time_get"), Some(&3));
    assert_eq!(execution.hostcalls.get("random_get"), Some(&1));
    assert_eq!(execution.hostcalls.get("fd_write"), Some(&1));
    assert_eq!(execution.hostcalls_total(), 5);
    // An import the module never calls must be absent, not zero-valued: the
    // map reports what ran, so "no rows" and "zero depth" stay distinct.
    assert!(!execution.hostcalls.contains_key("fd_read"));
    assert!(
        execution.fuel_consumed > 0,
        "fuel accounting reported nothing for a guest that executed"
    );
}

#[test]
fn depth_is_byte_identical_across_repeat_runs_of_one_seed() {
    let first = run_depth_probe(11);
    let second = run_depth_probe(11);
    assert_eq!(first.fuel_consumed, second.fuel_consumed);
    assert_eq!(first.hostcalls, second.hostcalls);
    // The counters must not perturb the run either: the guest-observable
    // outputs stay identical alongside them.
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.exit_code, second.exit_code);
}

#[test]
fn zero_fuel_depth_is_refused_rather_than_reported_as_zero() {
    let error = check_depth_available(0).unwrap_err();
    assert!(matches!(error, WasiRunError::Depth(_)), "got {error:?}");
    assert!(
        error.to_string().contains("fuel_consumed=0"),
        "refusal must name the missing measurement, got: {error}"
    );
    check_depth_available(1).expect("a run that consumed fuel has depth data");
}
