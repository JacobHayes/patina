//! Native and WASI custom operations, replay, faults, and campaign discovery.

use super::*;

// ---------------------------------------------------------------------------
// Custom operations (docs/arcs/custom-ops.md, Wave A): a guest wraps an effect
// Patina does not model; Patina records the result and reproduces it on replay
// without ever running the wrapper again.
// ---------------------------------------------------------------------------

// A guest with two custom ops — one with a key and a nonempty result, one with
// neither, so the empty cases ride the same path. `perform` bumps a process-local
// counter instead of doing I/O, so the printed count is a direct, boundary-free
// answer to "did the closure run?": on record it must be 2, on replay 0.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CUSTOM_OP_SDK_MAIN: &str = r#"
use std::sync::atomic::{AtomicU32, Ordering};

static PERFORMED: AtomicU32 = AtomicU32::new(0);

fn main() {
    let object = patina_dst::custom_op_bytes("s3.get_object", b"bucket/key", || {
        PERFORMED.fetch_add(1, Ordering::SeqCst);
        b"etag-7".to_vec()
    });
    let empty = patina_dst::custom_op_bytes("host.uptime", b"", || {
        PERFORMED.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    });
    println!(
        "PATINA_RESULT performed={} object={} empty_len={}",
        PERFORMED.load(Ordering::SeqCst),
        String::from_utf8_lossy(&object),
        empty.len()
    );
}
"#;

// ---------------------------------------------------------------------------
// Seeded custom-op faults (docs/arcs/custom-ops.md, Wave B): a guest declares
// what failure means for an operation it wraps, and `--custom-op-fail-permille`
// hands back that failure instead of running the effect.
// ---------------------------------------------------------------------------

// One guest, three modes, so the whole knob is proven against a single build.
//
// `probe`  — one faultable op next to one that declares nothing, which is the
//            control: eligibility is the guest's call, so the knob must pass
//            the undeclared one by even at a certain rate.
// `bare`   — no custom operations at all, for the vacuity leg.
// default  — a read-through cache whose retry policy has an off-by-one: it
//            treats a SECOND consecutive fetch failure as "upstream unchanged"
//            and serves a placeholder as though it were real data. The bug is
//            reachable only under a specific fault PATTERN (two in a row), so
//            finding it is campaign work rather than a single run's.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CUSTOM_OP_FAULT_SDK_MAIN: &str = r#"
use std::sync::atomic::{AtomicU32, Ordering};

static PERFORMED: AtomicU32 = AtomicU32::new(0);

fn fetch(index: u32) -> Result<String, String> {
    let bytes = patina_dst::custom_op_bytes_faultable(
        "s3.get_object",
        &index.to_le_bytes(),
        || b"UNAVAILABLE".to_vec(),
        || {
            PERFORMED.fetch_add(1, Ordering::SeqCst);
            format!("obj-{index}").into_bytes()
        },
    );
    let text = String::from_utf8(bytes).unwrap();
    if text == "UNAVAILABLE" {
        Err(text)
    } else {
        Ok(text)
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("bare") => {
            println!("PATINA_RESULT mode=bare");
        }
        Some("probe") => {
            let faultable = fetch(1);
            let plain = patina_dst::custom_op_bytes("host.uptime", b"", || {
                PERFORMED.fetch_add(1, Ordering::SeqCst);
                b"7".to_vec()
            });
            println!(
                "PATINA_RESULT performed={} faultable={} plain={}",
                PERFORMED.load(Ordering::SeqCst),
                match &faultable {
                    Ok(value) => value.clone(),
                    Err(error) => error.clone(),
                },
                String::from_utf8_lossy(&plain)
            );
        }
        _ => {
            let mut consecutive = 0u32;
            let mut stale = 0u32;
            for index in 0..200u32 {
                match fetch(index) {
                    Ok(_) => consecutive = 0,
                    Err(_) => {
                        consecutive += 1;
                        if consecutive >= 2 {
                            stale += 1;
                        }
                    }
                }
            }
            patina_dst::always!(stale == 0, "no-stale-objects-served");
            println!("PATINA_RESULT stale={stale}");
        }
    }
}
"#;

// The WASI half: the three `patina_sdk` custom-op imports are backed by the same
// runtime entries, so a wasip1 guest records and replays identically to native.
// The module exits 10 on the record pass and 20+len+100 on the replay pass, so
// the exit code alone proves which path ran and that the recorded bytes actually
// landed in guest memory.
const WASI_CUSTOM_OP_MODULE: &str = r#"(module
    (import "patina_sdk" "custom_op_begin"
        (func $begin (param i32 i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "custom_op_replay_result"
        (func $fetch (param i32 i32) (result i32)))
    (import "patina_sdk" "custom_op_record"
        (func $record (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "s3.get_object")
    (data (i32.const 32) "bucket/key")
    (data (i32.const 64) "etag-7")
    (func (export "_start")
        (local $mode i32)
        (local $len i32)
        ;; the 5th argument is the fault-eligibility declaration: 0 = this call
        ;; declares no failure shape, so --custom-op-fail-permille passes it by.
        (local.set $mode (call $begin
            (i32.const 0) (i32.const 13) (i32.const 32) (i32.const 10)
            (i32.const 0) (i32.const 96)))
        (if (i32.eqz (local.get $mode))
            (then
                (drop (call $record (i32.const 64) (i32.const 6)))
                (call $proc_exit (i32.const 10)))
            (else
                (local.set $len (call $fetch (i32.const 128) (i32.const 64)))
                ;; the fetched length must match what begin reported at *96
                (if (i32.ne (local.get $len) (i32.load (i32.const 96)))
                    (then (call $proc_exit (i32.const 99))))
                ;; ... and the bytes must really be in guest memory ('e' = 101)
                (if (i32.ne (i32.load8_u (i32.const 128)) (i32.const 101))
                    (then (call $proc_exit (i32.const 98))))
                (call $proc_exit (i32.add (i32.const 120) (local.get $len)))))))"#;

// The wasip1 half of the fault knob: `custom_op_begin`'s eligibility argument
// and its third answer (2 = the declared failure) are wasm imports like any
// other, so the seeded knob reaches a WASI guest identically. The module exits
// 30 + mode, so the exit code alone says which branch the host chose.
const WASI_CUSTOM_OP_FAULT_MODULE: &str = r#"(module
    (import "patina_sdk" "custom_op_begin"
        (func $begin (param i32 i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "custom_op_record"
        (func $record (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "s3.get_object")
    (data (i32.const 64) "etag-7")
    (func (export "_start")
        (local $mode i32)
        ;; fault_eligible = 1: this call declares a failure shape.
        (local.set $mode (call $begin
            (i32.const 0) (i32.const 13) (i32.const 0) (i32.const 0)
            (i32.const 1) (i32.const 96)))
        ;; A record pass must still be closed out; a faulted one is already closed.
        (if (i32.eqz (local.get $mode))
            (then (drop (call $record (i32.const 64) (i32.const 6)))))
        (call $proc_exit (i32.add (i32.const 30) (local.get $mode)))))"#;

#[cfg(test)]
#[path = "custom_ops/tests.rs"]
mod tests;
