//! Patina SDK import registration and deterministic runtime bridges.

use crate::Preview1Host;
use crate::imports::Imports;
use crate::memory::{memory, offset, read_guest_bytes, write_u32};
use patina_dst_runtime::{Context, CustomOpMode, RuntimeError, SiteOutcome, VerdictKind};
use wasmi::{Caller, Error as WasmiError};

/// Read a cooperative-SUT label/site string from guest linear memory. Labels are
/// tiny, but they still ride the standard `max_io_bytes` ceiling through
/// [`read_guest_bytes`], and non-UTF-8 is a hard error rather than lossy text so
/// a mislowered call fails closed.
fn read_patina_label(
    caller: &Caller<'_, Preview1Host>,
    pointer: i32,
    length: i32,
) -> Result<String, WasmiError> {
    let bytes = read_guest_bytes(caller, pointer, length)?;
    String::from_utf8(bytes).map_err(|_| WasmiError::new("patina_sdk label is not valid UTF-8"))
}

/// Emit a fatal cooperative-SUT marker and return a trap that terminates the
/// guest with a nonzero exit. Mirrors the native shim's
/// `abort_with_buggify_marker`: the marker is a harness diagnostic, so it goes to
/// the real process stderr (like `PATINA_SDK_REPORT`), where the campaign
/// classifier greps for it — not into the captured guest stream, whose surfacing
/// depends on the run's error path.
pub(super) fn patina_buggify_fatal(marker: &str, label: &str) -> WasmiError {
    eprintln!("{marker} label={label}");
    WasmiError::new(format!("{marker} label={label}"))
}

/// Trap out of an `always!` violation.
///
/// No marker of its own: the violation was already reported through the verdict
/// ABI and drained into the guest's captured stderr as a `PATINA_VERDICT` line
/// (which the run error carries), and that verdict is what the result envelope
/// and the campaign classifier read (`docs/arcs/outcome-channel.md`). The trap
/// message names the label so the human message still says which invariant.
fn patina_always_violation_trap(label: &str) -> WasmiError {
    WasmiError::new(format!("patina: always! invariant violated: label={label}"))
}

/// Move the runtime's queued diagnostic lines (today: `PATINA_VERDICT`) into the
/// captured guest stderr, mirroring the native shim's `drain_runtime_diagnostics`.
/// The runtime performs no process I/O of its own mid-run, so every `patina_sdk`
/// import that can produce a line drains it before returning or trapping.
fn drain_runtime_diagnostics(host: &mut Preview1Host) {
    for line in host.context.take_pending_diagnostics() {
        host.stderr.extend_from_slice(line.as_bytes());
        host.stderr.push(b'\n');
    }
}

/// Shared body for the site-evaluating `patina_sdk` imports: read the label and
/// call site from guest memory, invoke the context method, and map the outcome to
/// `1`=fire / `0`=no, trapping on a fatal always-violation or duplicate label.
/// The runtime side is the SAME [`Context`] buggify subsystem the native shim
/// drives, so activation, PRF firing, the cutoff, and the diagnostics report are
/// reused rather than reimplemented.
fn patina_sdk_site(
    mut caller: Caller<'_, Preview1Host>,
    label_ptr: i32,
    label_len: i32,
    site_ptr: i32,
    site_len: i32,
    invoke: impl FnOnce(&mut Context, &str, &str) -> Result<SiteOutcome, RuntimeError>,
) -> Result<i32, WasmiError> {
    let label = read_patina_label(&caller, label_ptr, label_len)?;
    let site = read_patina_label(&caller, site_ptr, site_len)?;
    let outcome = invoke(&mut caller.data_mut().context, &label, &site)
        .map_err(|error| WasmiError::new(error.to_string()))?;
    // Before acting on the outcome: an `always!` violation lowers to a verdict,
    // and the fatal arms below trap out of this function. The drained
    // `PATINA_VERDICT` line is the violation's ONLY announcement.
    drain_runtime_diagnostics(caller.data_mut());
    match outcome {
        SiteOutcome::Fire => Ok(1),
        SiteOutcome::Ok => Ok(0),
        SiteOutcome::AlwaysViolation => Err(patina_always_violation_trap(&label)),
        SiteOutcome::DuplicateLabel => Err(patina_buggify_fatal(
            "PATINA_BUGGIFY_DUPLICATE_LABEL",
            &label,
        )),
    }
}

/// Define the `patina_sdk` import module: the WASI-side mirror of the native
/// shim's cooperative-SUT C ABI. Every function is backed by the same
/// [`Context`] buggify subsystem, so a guest compiled with `cfg(patina)` sees
/// identical activation/firing/coverage semantics on wasip1 and native. The
/// module is defined unconditionally (like the preview1 imports): when buggify is
/// disabled the sites register lazily and stay inert, exactly as native, so a
/// `patina_sdk`-importing guest run without `--buggify` behaves as all-no-op.
pub(super) fn define_patina_sdk(linker: &mut Imports) -> Result<(), WasmiError> {
    const MODULE: &str = "patina_sdk";
    linker.func_wrap(
        MODULE,
        "is_simulated",
        // The deterministic context is always installed for a WASI run, so this is
        // authoritative `true`; a foreign runtime never resolves the import.
        |_caller: Caller<'_, Preview1Host>| -> i32 { 1 },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify",
        |caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32,
         prob_permille: i32|
         -> Result<i32, WasmiError> {
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| {
                    let prob = (prob_permille >= 0).then(|| prob_permille.clamp(0, 1000) as u16);
                    ctx.buggify_evaluate(l, s, prob)
                },
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify_delay",
        |caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            patina_sdk_site(caller, label, label_len, site, site_len, |ctx, l, s| {
                ctx.buggify_delay(l, s)
            })
        },
    )?;
    linker.func_wrap(
        MODULE,
        "buggify_knob",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32,
         default: i64,
         lo: i64,
         hi: i64|
         -> Result<i64, WasmiError> {
            let label = read_patina_label(&caller, label, label_len)?;
            let site = read_patina_label(&caller, site, site_len)?;
            match caller
                .data_mut()
                .context
                .buggify_knob(&label, &site, default, lo, hi)
                .map_err(|error| WasmiError::new(error.to_string()))?
            {
                Ok(value) => Ok(value),
                Err(()) => Err(patina_buggify_fatal(
                    "PATINA_BUGGIFY_DUPLICATE_LABEL",
                    &label,
                )),
            }
        },
    )?;
    linker.func_wrap(
        MODULE,
        "always",
        |caller: Caller<'_, Preview1Host>,
         condition: i32,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| ctx.always_check(l, s, condition != 0),
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "sometimes",
        |caller: Caller<'_, Preview1Host>,
         condition: i32,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            patina_sdk_site(
                caller,
                label,
                label_len,
                site,
                site_len,
                move |ctx, l, s| ctx.sometimes_check(l, s, condition != 0),
            )
        },
    )?;
    linker.func_wrap(
        MODULE,
        "reachable",
        |caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         site: i32,
         site_len: i32|
         -> Result<i32, WasmiError> {
            patina_sdk_site(caller, label, label_len, site, site_len, |ctx, l, s| {
                ctx.reachable_mark(l, s)
            })
        },
    )?;
    // The verdict ABI: one import, kinds as data — the wasm mirror of the shim's
    // `patina_verdict`. An unrecognized kind traps rather than defaulting, so a
    // guest built against a newer kind set fails closed instead of having its
    // verdict silently reclassified.
    linker.func_wrap(
        MODULE,
        "verdict",
        |mut caller: Caller<'_, Preview1Host>,
         kind: u32,
         label: i32,
         label_len: i32,
         detail: i32,
         detail_len: i32|
         -> Result<i32, WasmiError> {
            let kind = VerdictKind::from_abi(kind).ok_or_else(|| {
                WasmiError::new(format!(
                    "patina_sdk verdict: unknown verdict kind {kind}; the guest was built \
against a newer verdict ABI than this runtime provides"
                ))
            })?;
            let label = read_patina_label(&caller, label, label_len)?;
            let detail = read_patina_label(&caller, detail, detail_len)?;
            let host = caller.data_mut();
            host.context
                .verdict(kind, &label, &detail)
                .map_err(|error| WasmiError::new(error.to_string()))?;
            drain_runtime_diagnostics(host);
            Ok(0)
        },
    )?;
    // The custom-op ABI: three imports, the wasm mirror of the shim's
    // `patina_custom_op_begin` / `_replay_result` / `_record`. Phases are
    // separate imports rather than one verb with a phase argument for the same
    // reason they are separate symbols natively: three argument shapes and three
    // directions of data flow, where a folded signature would carry arguments
    // that are ignored on two of the three phases. The op *class* is still data
    // (the label), so no custom operation ever grows this surface.
    //
    // Unlike native, a refusal traps instead of returning an errno: a wasm guest
    // has no errno to consult, and every custom-op refusal is fatal by design.
    linker.func_wrap(
        MODULE,
        "custom_op_begin",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32,
         key: i32,
         key_len: i32,
         fault_eligible: i32,
         out_len: i32|
         -> Result<i32, WasmiError> {
            let label = read_patina_label(&caller, label, label_len)?;
            let key = read_guest_bytes(&caller, key, key_len)?;
            let mode = caller
                .data_mut()
                .context
                .custom_op_begin(&label, &key, fault_eligible != 0)
                .map_err(|error| WasmiError::new(error.to_string()))?;
            let (code, len) = match mode {
                CustomOpMode::Record => (0, 0),
                CustomOpMode::Replay { len } => (1, len),
                // The operation is already closed; the guest returns the failure
                // it declared and makes no phase-2 call.
                CustomOpMode::Fault => (2, 0),
            };
            let len = u32::try_from(len).map_err(|_| {
                WasmiError::new(format!(
                    "patina_sdk custom_op_begin: the recorded result for {label:?} does not fit a \
wasm32 length"
                ))
            })?;
            write_u32(&mut caller, out_len, len)?;
            Ok(code)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "custom_op_replay_result",
        |mut caller: Caller<'_, Preview1Host>, out: i32, out_cap: i32| -> Result<i32, WasmiError> {
            let out_cap = offset(out_cap)?;
            // A short buffer leaves the operation open (nothing is consumed), so
            // the guest can retry with the length `custom_op_begin` reported.
            let pending = caller.data().context.custom_op_pending_len();
            if let Some(len) = pending.filter(|len| *len > out_cap) {
                return Err(WasmiError::new(format!(
                    "patina_sdk custom_op_replay_result: the recorded result is {len} bytes but \
the guest offered a {out_cap}-byte buffer"
                )));
            }
            let bytes = caller
                .data_mut()
                .context
                .custom_op_replay_result()
                .map_err(|error| WasmiError::new(error.to_string()))?;
            let written = i32::try_from(bytes.len()).map_err(|_| {
                WasmiError::new("patina_sdk custom_op_replay_result: result exceeds wasm32 length")
            })?;
            if !bytes.is_empty() {
                memory(&caller)?.write(&mut caller, offset(out)?, &bytes)?;
            }
            Ok(written)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "custom_op_record",
        |mut caller: Caller<'_, Preview1Host>,
         result: i32,
         result_len: i32|
         -> Result<i32, WasmiError> {
            let result = read_guest_bytes(&caller, result, result_len)?;
            caller
                .data_mut()
                .context
                .custom_op_record(result)
                .map_err(|error| WasmiError::new(error.to_string()))?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        MODULE,
        "rng",
        |mut caller: Caller<'_, Preview1Host>| -> u64 { caller.data_mut().context.buggify_rng() },
    )?;
    linker.func_wrap(
        MODULE,
        "lifecycle_setup_complete",
        |mut caller: Caller<'_, Preview1Host>| -> i32 {
            let host = caller.data_mut();
            host.context.lifecycle_setup_complete();
            // Mirror the native shim: the lifecycle marker rides the captured guest
            // stderr stream, flushed to the real stderr at run end.
            host.stderr
                .extend_from_slice(b"PATINA_LIFECYCLE setup_complete\n");
            0
        },
    )?;
    linker.func_wrap(
        MODULE,
        "lifecycle_event",
        |mut caller: Caller<'_, Preview1Host>,
         label: i32,
         label_len: i32|
         -> Result<i32, WasmiError> {
            let label = read_patina_label(&caller, label, label_len)?;
            let line = format!("PATINA_LIFECYCLE_EVENT label={label}\n");
            caller.data_mut().stderr.extend_from_slice(line.as_bytes());
            Ok(0)
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preview1::define_preview1;
    use patina_dst_runtime::RuntimeConfig;
    use wasmi::{Config as WasmiConfig, Engine, Module, Store};

    // The `patina_sdk` host module is backed by the same runtime buggify
    // subsystem as the native shim: an active site fires (the guest exits with the
    // decision), `reachable!` registers a site, and the end-of-run diagnostics
    // report the firing. Instantiated directly (bypassing `WasiAudit`) so this is
    // a focused unit test of `define_patina_sdk`'s wiring.
    #[test]
    fn patina_sdk_module_fires_and_records_diagnostics() {
        let wasm = wat::parse_str(
            r#"(module
                (import "patina_sdk" "buggify"
                    (func $buggify (param i32 i32 i32 i32 i32) (result i32)))
                (import "patina_sdk" "reachable"
                    (func $reachable (param i32 i32 i32 i32) (result i32)))
                (import "patina_sdk" "lifecycle_setup_complete" (func $setup (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "unit-fault")
                (data (i32.const 16) "unit:site")
                (data (i32.const 32) "unit-reach")
                (data (i32.const 48) "unit:reach")
                (func (export "_start")
                    (drop (call $reachable (i32.const 32) (i32.const 10) (i32.const 48) (i32.const 10)))
                    (drop (call $setup))
                    (call $proc_exit
                        (call $buggify (i32.const 0) (i32.const 10)
                            (i32.const 16) (i32.const 9) (i32.const -1)))))"#,
        )
        .unwrap();

        // Enable buggify at full activation and firing so the single site fires.
        let config = RuntimeConfig::seeded(3)
            .apply_buggify_env(|name| match name {
                patina_dst_runtime::ENV_BUGGIFY => Some("1000".to_string()),
                patina_dst_runtime::ENV_BUGGIFY_ACTIVATION => Some("1000".to_string()),
                _ => None,
            })
            .unwrap();

        let mut wasm_config = WasmiConfig::default();
        wasm_config.consume_fuel(true);
        let engine = Engine::new(&wasm_config);
        let module = Module::new(&engine, &wasm).unwrap();
        let mut linker = Imports::new(&engine);
        define_preview1(&mut linker).unwrap();
        define_patina_sdk(&mut linker).unwrap();
        let mut store = Store::new(
            &engine,
            Preview1Host::new(Context::from_config(config).unwrap()),
        );
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate_and_start(&mut store, &module).unwrap();
        let start = instance.get_typed_func::<(), ()>(&store, "_start").unwrap();
        let exit = match start.call(&mut store, ()) {
            Ok(()) => 0,
            Err(error) => error.i32_exit_status().unwrap(),
        };
        assert_eq!(
            exit, 1,
            "an always-active, always-firing buggify site must fire"
        );

        let diagnostics = store.data_mut().context.buggify_diagnostics();
        assert!(diagnostics.enabled);
        assert_eq!(diagnostics.sites_registered, 2);
        assert_eq!(diagnostics.total_firings, 1);
    }
}
