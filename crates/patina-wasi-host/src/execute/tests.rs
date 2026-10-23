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

#[test]
fn memory_growth_beyond_the_cap_traps() {
    let module = wat::parse_str(
        r#"(module
                (memory 1)
                (func (export "_start")
                    (drop (memory.grow (i32.const 100)))))"#,
    )
    .unwrap();

    // Exceeding the cap traps.
    let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
    let host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
        max_memory_pages: 2,
        ..ResourceLimits::default()
    });
    assert!(matches!(
        execute_preview1(&module, host),
        Err(WasiRunError::Engine(_))
    ));

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
    // A run that reports no fuel has no depth data and is refused rather
    // than reported as zero.
    let error = check_depth_available(0).unwrap_err();
    assert!(matches!(error, WasiRunError::Depth(_)), "got {error:?}");
    check_depth_available(1).expect("a run that consumed fuel has depth data");
}
