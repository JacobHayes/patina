//! Native custom operations, replay, faults, and campaign discovery.

use super::*;

// ---------------------------------------------------------------------------
// Custom operations (ARCHITECTURE.md, "The custom-operation ABI"): a guest wraps an effect
// Patina does not model; Patina records the result and reproduces it on replay
// without ever running the wrapper again.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Seeded custom-op faults: a guest declares
// what failure means for an operation it wraps, and `--custom-op-fail-permille`
// hands back that failure instead of running the effect.
// ---------------------------------------------------------------------------

// One guest, four modes, so record/replay, the fault knob and the campaign are
// proven against a single build. `PERFORMED` counts closure runs in-process
// instead of doing I/O, so the printed count is a boundary-free answer to "did
// the closure run?".
//
// `record` — two custom ops, one with a key and a nonempty result, one with
//            neither, so the empty cases ride the same path.
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
const CUSTOM_OP_SDK_MAIN: &str = r#"
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
        Some("record") => {
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

#[cfg(test)]
#[path = "custom_ops/tests.rs"]
mod tests;
