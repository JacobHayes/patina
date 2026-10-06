//! Audited Wasmi execution, fuel accounting, and guest outcomes.

use crate::limits::build_store_limits;
use crate::preview1::define_preview1;
use crate::sdk::define_patina_sdk;
use crate::static_sites::declare_wasm_static_sites;
use crate::{Preview1Host, WasiRunError};
use patina_dst_target::WasiAudit;
use std::collections::BTreeMap;
use wasmi::{Config as WasmiConfig, Engine, Error as WasmiError, Linker, Module, Store, TrapCode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasiExecution {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub fuel_consumed: u64,
    /// Per-import call counts keyed by imported function name — the hostcall half
    /// of the WASI depth proxy (see `docs/arcs/coverage-depth.md` §5). Like
    /// `fuel_consumed` this is a deterministic function of the executed
    /// instruction stream and is report-only: it never enters the trace, a
    /// fingerprint, or any canonical hash.
    pub hostcalls: BTreeMap<&'static str, u64>,
}

impl WasiExecution {
    /// Total hostcalls across every imported function.
    pub fn hostcalls_total(&self) -> u64 {
        self.hostcalls
            .values()
            .fold(0u64, |total, count| total.saturating_add(*count))
    }
}

/// Execute an audited WASI Preview 1 core module through deterministic host
/// functions. Unsupported imports are rejected before instantiation.
pub fn execute_preview1(
    module_bytes: &[u8],
    host: Preview1Host,
) -> Result<WasiExecution, WasiRunError> {
    let fuel = host.limits.fuel;
    execute_preview1_with_fuel(module_bytes, host, fuel)
}

/// The wasmi engine [`Config`] with every determinism-relevant knob pinned
/// EXPLICITLY rather than inherited from `Config::default()`, so an upstream
/// change to wasmi's defaults can never silently alter guest-observable
/// behavior under a deterministic-replay product. Verified against wasmi
/// 1.1.0; wasmi is a pure interpreter (no JIT), which shapes how the two
/// classic sources of cross-engine float divergence are handled:
///
///   - NaN bit patterns: wasmi computes floats in software (`wasmi_core`), so
///     a NaN-producing op yields the same bits on every run and every host.
///     There is NO NaN-canonicalization knob to set (unlike a JIT engine,
///     which needs one); the `nan_bits_are_deterministic` test pins that this
///     stays true.
///   - relaxed-SIMD: the ONE Wasm proposal whose results are implementation-
///     defined (relaxed FMA / swizzle / lane-select may legally differ across
///     engines) and therefore a determinism hole. It is reachable only under
///     wasmi's `simd` cargo feature, which this workspace deliberately does
///     NOT enable — `Config::wasm_simd`/`wasm_relaxed_simd` are themselves
///     gated behind it, so the nondeterministic code path is compiled out of
///     the engine entirely (a stronger guarantee than a runtime `false`) and
///     SIMD modules are rejected at validation. The `simd_module_is_rejected`
///     test pins that the feature stays off; if it is ever turned on, this
///     config MUST additionally call `config.wasm_relaxed_simd(false)`.
///
/// * `consume_fuel(true)` — bounds CPU work AND makes `fuel_consumed` a
///   deterministic function of the guest's executed instruction stream. wasmi
///   1.x fixed the `fuel_for_copying_values` rounding (`(len/64)*8` ->
///   `(len*8)/64`), so absolute fuel for multi-value copies/calls is slightly
///   higher than under 0.47; that only shifts the fuel-exhaustion trap
///   boundary — `fuel_consumed` is never recorded in the trace or any
///   canonical hash (only stdout/stderr/exit_code plus the deterministic host
///   `Context` drive replay). Within one engine version fuel is fully
///   deterministic.
/// * `floats(true)` — f32/f64 stay enabled (default true in 0.47 and 1.1;
///   pinned so a default flip cannot disable float support out from under a
///   guest).
///
/// All remaining default features (mutable-global, multi-value, multi-memory,
/// sat-float-to-int, sign-extension, bulk-memory, reference-types, tail-call,
/// extended-const, memory64) are byte-for-byte identical between wasmi 0.47.2
/// and 1.1.0 and are all deterministic.
fn deterministic_wasmi_config() -> WasmiConfig {
    let mut config = WasmiConfig::default();
    config.consume_fuel(true);
    config.floats(true);
    config
}

/// Fail closed on missing depth data. Fuel metering is pinned on for every run
/// and the engine charges the executed instruction stream including the `_start`
/// call, so a guest that ran to completion consumed fuel. Zero means the
/// accounting stopped working — and a zero-valued depth report is
/// indistinguishable from a genuine "did nothing" run, exactly the silent-empty
/// report the coverage/depth arc refuses (`docs/arcs/coverage-depth.md` §10 D1).
fn check_depth_available(fuel_consumed: u64) -> Result<(), WasiRunError> {
    if fuel_consumed == 0 {
        return Err(WasiRunError::Depth(
            "WASI run completed but reported fuel_consumed=0; depth accounting is not recording \
the executed instruction stream (refusing an empty depth report that cannot be told apart from \
zero depth)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn execute_preview1_with_fuel(
    module_bytes: &[u8],
    mut host: Preview1Host,
    fuel: u64,
) -> Result<WasiExecution, WasiRunError> {
    WasiAudit::audit(module_bytes).map_err(WasiRunError::Target)?;
    declare_wasm_static_sites(&mut host.context, module_bytes)?;
    let engine = Engine::new(&deterministic_wasmi_config());
    let module = Module::new(&engine, module_bytes).map_err(WasiRunError::Engine)?;
    let mut linker = Linker::<Preview1Host>::new(&engine);
    define_preview1(&mut linker).map_err(WasiRunError::Engine)?;
    define_patina_sdk(&mut linker).map_err(WasiRunError::Engine)?;
    let mut store = Store::new(&engine, host);
    store.set_fuel(fuel).map_err(WasiRunError::Engine)?;
    let store_limits = build_store_limits(store.data().limits.max_memory_pages);
    store.data_mut().store_limits = store_limits;
    store.limiter(|host| &mut host.store_limits);
    let run_result = (|| {
        // wasmi 1.1 merged the two-step `instantiate(..).start(..)` (InstancePre
        // then run the module's `start` section) into a single call that both
        // instantiates and runs the start function. Observable behavior is
        // unchanged: the guest's `start` section still runs before `_start`.
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(WasiRunError::Engine)?;
        let start = instance
            .get_typed_func::<(), ()>(&store, "_start")
            .map_err(WasiRunError::Engine)?;
        match start.call(&mut store, ()) {
            Ok(()) => Ok(0),
            Err(error) => match error.i32_exit_status() {
                Some(status) => Ok(status),
                None => Err(classify_start_error(error)),
            },
        }
    })();
    let fuel_consumed = fuel.saturating_sub(
        store
            .get_fuel()
            .expect("fuel metering was enabled on the Wasmi engine"),
    );
    let hostcalls = store.data().hostcalls.clone();
    let output_result = store
        .into_data()
        .finish_with_output()
        .map_err(WasiRunError::Host);
    match (run_result, output_result) {
        (Ok(exit_code), Ok((stdout, stderr))) => {
            check_depth_available(fuel_consumed)?;
            Ok(WasiExecution {
                exit_code,
                stdout,
                stderr,
                fuel_consumed,
                hostcalls,
            })
        }
        (Err(run), Ok((stdout, stderr))) if stdout.is_empty() && stderr.is_empty() => Err(run),
        (Err(run), Ok((stdout, stderr))) => Err(WasiRunError::RunWithOutput {
            run: Box::new(run),
            stdout,
            stderr,
        }),
        (Ok(_), Err(finalize)) => Err(finalize),
        (Err(run), Err(finalize)) => Err(WasiRunError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

/// Attribute a non-`proc_exit` failure out of `_start`.
///
/// A wasm trap is the guest's own outcome (an `always!` violation, an
/// `unreachable`, an out-of-bounds access) EXCEPT for the two trap codes patina
/// itself causes by installing a limit: `OutOfFuel` is the `--fuel` budget
/// halting the guest and `GrowthOperationLimited` is the memory cap refusing a
/// growth. Those are patina stopping the run, not the guest failing, so they stay
/// [`WasiRunError::Engine`] and keep failing the CLI closed rather than being
/// reported as a guest outcome. The split is structural — a trap code, never the
/// trap's message text.
fn classify_start_error(error: WasmiError) -> WasiRunError {
    match error.as_trap_code() {
        Some(TrapCode::OutOfFuel) | Some(TrapCode::GrowthOperationLimited) => {
            WasiRunError::Engine(error)
        }
        _ => WasiRunError::GuestTrap(error),
    }
}

#[cfg(test)]
mod tests;
