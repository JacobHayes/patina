//! Runtime bridges called by the exported SDK macros.

pub use crate::static_sites::{
    STATIC_SITE_KIND_ALWAYS, STATIC_SITE_KIND_DELAY, STATIC_SITE_KIND_FAULT, STATIC_SITE_KIND_KNOB,
    STATIC_SITE_KIND_REACHABLE, STATIC_SITE_KIND_SOMETIMES, StaticSiteDescriptor,
    WASM_STATIC_SITE_RECORD_HEADER_LEN, encode_wasm_static_site, wasm_static_site_len,
};
#[cfg(feature = "macros")]
pub use crate::test_harness::{DstTest, DstTestReturn, assert_test_return, orchestrate};

#[cfg(patina_shim)]
use crate::ffi;
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
use crate::wasm_ffi;

pub use calls::{
    always, buggify, buggify_delay, buggify_knob, lifecycle_event, lifecycle_setup_complete,
    prob_to_permille, reachable, sometimes,
};

mod calls {
    /// `buggify!` / `buggify_with_prob!`: whether the site fires. `prob_permille`
    /// is `-1` for the run default.
    #[inline]
    pub fn buggify(label: &str, site: &str, prob_permille: i32) -> bool {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    prob_permille,
                ) != 0
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    prob_permille,
                ) != 0
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site, prob_permille);
            false
        }
    }

    /// `buggify_delay!`: whether a deterministic delay was injected.
    #[inline]
    pub fn buggify_delay(label: &str, site: &str) -> bool {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify_delay(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                ) != 0
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify_delay(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                ) != 0
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site);
            false
        }
    }

    /// `buggify_knob!`: a per-run perturbed value in `[lo, hi]`, else `default`.
    #[inline]
    pub fn buggify_knob(label: &str, site: &str, default: i64, lo: i64, hi: i64) -> i64 {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify_knob(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    default,
                    lo,
                    hi,
                )
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify_knob(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    default,
                    lo,
                    hi,
                )
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site, lo, hi);
            default
        }
    }

    /// `always!`: a fatal invariant under Patina (marker + abort), a
    /// `debug_assert` outside.
    #[inline]
    #[track_caller]
    pub fn always(condition: bool, label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_always(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            // Host-authoritative: on a violation the WASI host records the
            // `violation` verdict and traps the guest, so this import does not
            // return when `condition` is false.
            unsafe {
                super::wasm_ffi::always(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), not(target_arch = "wasm32")))]
        {
            let _ = site;
            assert!(condition, "patina always! invariant violated: {label}");
        }
        #[cfg(not(patina))]
        {
            let _ = site;
            debug_assert!(condition, "always! invariant violated: {label}");
        }
    }

    /// `sometimes!`: a coverage oracle. No effect on control flow.
    #[inline]
    pub fn sometimes(condition: bool, label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_sometimes(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::sometimes(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (condition, label, site);
        }
    }

    /// `reachable!`: a coverage oracle noting the site was reached.
    #[inline]
    pub fn reachable(label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_reachable(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::reachable(label.as_ptr(), label.len(), site.as_ptr(), site.len());
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site);
        }
    }

    /// `patina_dst::lifecycle::event!`.
    #[inline]
    pub fn lifecycle_event(label: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_lifecycle_event(label.as_ptr(), label.len());
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::lifecycle_event(label.as_ptr(), label.len());
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = label;
        }
    }

    /// `patina_dst::lifecycle::setup_complete`.
    #[inline]
    pub fn lifecycle_setup_complete() {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_lifecycle_setup_complete();
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::lifecycle_setup_complete();
            }
        }
    }

    /// Convert a `0.0..=1.0` probability to a `0..=1000` per-mille integer.
    #[inline]
    pub fn prob_to_permille(probability: f64) -> i32 {
        (probability.clamp(0.0, 1.0) * 1000.0).round() as i32
    }
}
