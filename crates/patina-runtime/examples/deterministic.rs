//! Low-level explicit-context simulator example (usage mode 3 of
//! `HARNESS-DESIGN.md`).
//!
//! This drives Patina's virtual APIs directly through an explicit [`Context`]:
//! `patina_dst_runtime::run` builds a context with deterministic default drivers
//! from `PATINA_*` and finalizes it after the closure returns. It does NOT make
//! unrelated `std::fs`/`std::net`/clock calls deterministic — that is the job of
//! the native shim / WASI host under `cargo patina build`/`run`, or of the
//! shim-backed `patina-dst-harness` crate.
//!
//! [`Context`]: patina_dst_runtime::Context

use patina_dst_abi::ClockKind;
use patina_dst_runtime::RuntimeError;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (seed, entropy, time, stored) = patina_dst_runtime::run(|context| {
        let entropy = context.entropy_bytes(12)?;
        context.write_file("/state/entropy", &entropy)?;
        context.sleep_for(250_000_000)?;
        let time = context.now(ClockKind::Monotonic)?;
        let stored = context.read_file("/state/entropy")?;
        Ok::<_, RuntimeError>((context.root_seed(), entropy, time, stored))
    })?;

    println!(
        "PATINA_RESULT seed={seed} entropy={} time_ns={time} stored={}",
        hex(&entropy),
        hex(&stored)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}
