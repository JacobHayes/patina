//! Simulation detection and deterministic SDK entropy.

#[cfg(patina_shim)]
use crate::ffi;
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
use crate::wasm_ffi;

/// Whether execution is under Patina's deterministic simulator.
///
/// Analogous to FoundationDB's `g_network->isSimulated()`. `true` inside any
/// Patina build, `false` in an ordinary build. Prefer keeping code identical in
/// and out of simulation; reserve this for the rare simulation-only affordance
/// (extra validation, a simulation-visible log line).
///
/// ```
/// // Under a plain `cargo build`/`cargo test` this is always false.
/// assert!(!patina_dst::is_simulated());
/// ```
#[inline]
pub fn is_simulated() -> bool {
    #[cfg(patina_shim)]
    {
        // Authoritative: ask the linked shim whether the runtime is installed.
        unsafe { ffi::patina_is_simulated() != 0 }
    }
    #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
    {
        // Authoritative: ask the WASI host through the `patina_sdk` import. Under
        // a foreign (non-Patina) wasip1 runtime this import is unresolved and the
        // module cannot instantiate, so a `true` here always reflects a real host.
        unsafe { wasm_ffi::is_simulated() != 0 }
    }
    #[cfg(all(patina, not(patina_shim), not(target_arch = "wasm32")))]
    {
        true
    }
    #[cfg(not(patina))]
    {
        false
    }
}

/// A deterministic 64-bit draw. Under Patina it is bridged to the run's root
/// seed (through the native shim, or the WASI `patina_sdk` host import), so the
/// stream — and everything derived from it — is a pure function of `--seed`.
/// Outside Patina it is a plainly-seeded per-thread fallback stream, so callers
/// still get reproducible values without touching OS entropy.
///
/// This is the hook `patina-dst-proptest` builds on to make property-test case
/// generation a pure function of the run seed.
///
/// ```
/// let a = patina_dst::rng();
/// let b = patina_dst::rng();
/// // Consecutive draws advance the stream.
/// assert_ne!(a, b);
/// ```
#[inline]
pub fn rng() -> u64 {
    #[cfg(patina_shim)]
    {
        unsafe { ffi::patina_rng() }
    }
    #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
    {
        unsafe { wasm_ffi::rng() }
    }
    #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
    {
        fallback::next()
    }
}

/// Plainly-seeded fallback entropy for [`rng`] outside a Patina build (and for a
/// non-wasm Patina build without the shim). A process-local SplitMix64 with a
/// fixed seed, so it is reproducible without contacting any host source.
#[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
mod fallback {
    use std::cell::Cell;

    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x9e37_79b9_7f4a_7c15) };
    }

    pub fn next() -> u64 {
        STATE.with(|state| {
            let mut value = state.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
            state.set(value);
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fallback_rng_is_deterministic_per_thread() {
        // Fresh threads share the fixed seed, so their streams agree.
        let first = std::thread::spawn(|| (0..4).map(|_| super::rng()).collect::<Vec<_>>())
            .join()
            .unwrap();
        let second = std::thread::spawn(|| (0..4).map(|_| super::rng()).collect::<Vec<_>>())
            .join()
            .unwrap();
        assert_eq!(first, second);
    }
}
