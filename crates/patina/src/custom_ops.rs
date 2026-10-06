//! Byte and typed custom operations and their record/replay protocol.

#[cfg(patina_shim)]
use crate::ffi;
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
use crate::wasm_ffi;
#[cfg(doc)]
use crate::{buggify, sometimes, verdict};

/// Perform one **custom operation**: an effect Patina does not model, wrapped at
/// a boundary the guest controls so Patina can mediate it — raw bytes in, raw
/// bytes out.
///
/// On the record pass `perform` runs and its bytes are recorded under `label`.
/// On replay `perform` is **not** run: the recorded bytes are returned. That is
/// what makes a custom op deterministic by construction — the guest does not
/// decide which pass it is on, the runtime does.
///
/// - `label` names the operation *class* (`"s3.get_object"`), not the call. It
///   shares the site-label namespace of [`sometimes!`]/[`buggify!`] and
///   aggregates like a [`verdict`] label, but a custom op registers no fault
///   site, so the duplicate-label rule does not apply and one label naming many
///   calls in a run is exactly the point.
/// - `key` is the operation's logical input. It is recorded with the result and
///   checked on replay, so a guest that asks a *different* question under the
///   same label is refused rather than handed a stale answer.
///
/// This is the untyped surface: it lowers directly to the shim/WASI ABI with no
/// encoding of its own. With the default-off `custom-ops` feature, `custom_op`
/// adds serde-typed keys and results over exactly this call.
///
/// # Honest limits
///
/// A custom op does **not** exempt the wrapped effect from interposition. On the
/// record pass `perform` runs for real, so an un-modeled raw effect inside it
/// still refuses or audits exactly as it would outside a custom op — recording
/// is not the determinism-guaranteed mode, replay is. And `perform` must not
/// perform effects Patina *does* model: replay skips `perform`, so those
/// operations could never be reproduced, and the runtime refuses at record time
/// rather than writing a trace that cannot replay.
///
/// Outside Patina — and in the cargo family, which has no shim to call — this is
/// just `perform()`; report through `patina_dst_runtime::Context::custom_op`
/// there.
///
/// ```
/// // Outside Patina the closure simply runs and its bytes come straight back.
/// let bytes = patina_dst::custom_op_bytes("clock.host", b"utc", || vec![1, 2, 3]);
/// assert_eq!(bytes, vec![1, 2, 3]);
/// ```
pub fn custom_op_bytes(label: &str, key: &[u8], perform: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    custom_op_bytes_inner(label, key, None::<fn() -> Vec<u8>>, perform)
}

/// A [`custom_op_bytes`] that **declares a failure shape**, so the seeded
/// `--custom-op-fail-permille` knob can fail it.
///
/// `on_fault` produces the bytes the guest receives when a fault fires; it is
/// the guest's own answer to "what does this operation failing look like", and
/// the runtime never invents one, because only the guest knows a value its
/// caller can handle. When a fault fires, `perform` does **not** run and the
/// fault is recorded, so a replay reproduces it exactly — without re-consulting
/// eligibility, because the trace is the authority.
///
/// Declaring a failure shape injects nothing on its own: with the knob off (the
/// default) this behaves exactly like [`custom_op_bytes`]. What it buys is that
/// a campaign can now exercise the guest's error path for an effect Patina does
/// not model, which is the whole reason a custom op is worth wrapping.
///
/// Outside Patina this is just `perform()`; `on_fault` is never called.
///
/// ```
/// // Outside Patina the real closure runs and the declared failure is unused.
/// let bytes = patina_dst::custom_op_bytes_faultable(
///     "s3.get_object",
///     b"bucket/key",
///     || b"TIMEOUT".to_vec(),
///     || b"etag-7".to_vec(),
/// );
/// assert_eq!(bytes, b"etag-7".to_vec());
/// ```
pub fn custom_op_bytes_faultable(
    label: &str,
    key: &[u8],
    on_fault: impl FnOnce() -> Vec<u8>,
    perform: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    custom_op_bytes_inner(label, key, Some(on_fault), perform)
}

/// The one place the custom-op protocol is written down: `on_fault` present is
/// the eligibility declaration the ABI carries, so the faultable and plain
/// surfaces differ in exactly that bit and can never drift apart in any other.
fn custom_op_bytes_inner(
    label: &str,
    key: &[u8],
    on_fault: Option<impl FnOnce() -> Vec<u8>>,
    perform: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    #[cfg(any(patina_shim, all(patina, target_arch = "wasm32")))]
    {
        let mut len: usize = 0;
        let mode = unsafe {
            custom_op_ffi::begin(
                label.as_ptr(),
                label.len(),
                key.as_ptr(),
                key.len(),
                i32::from(on_fault.is_some()),
                &raw mut len,
            )
        };
        match mode {
            0 => {
                let result = perform();
                let code = unsafe { custom_op_ffi::record(result.as_ptr(), result.len()) };
                assert!(
                    code >= 0,
                    "patina custom op {label:?}: the runtime refused the recorded result"
                );
                result
            }
            1 => {
                let mut buffer = vec![0u8; len];
                let written =
                    unsafe { custom_op_ffi::replay_result(buffer.as_mut_ptr(), buffer.len()) };
                assert!(
                    written >= 0 && written as usize == len,
                    "patina custom op {label:?}: the runtime returned {written} bytes of a \
{len}-byte recorded result"
                );
                buffer
            }
            // A seeded (or recorded) fault. The runtime only answers this to a
            // call that declared a failure shape, so the `expect` is the ABI
            // contract being upheld, not a hope.
            2 => on_fault.expect("a custom-op fault needs a declared failure shape")(),
            // Only a malformed call reaches here: every runtime-level refusal is
            // fatal on the embedder side. Fail loudly rather than silently
            // performing an effect replay was supposed to reproduce.
            other => panic!(
                "patina custom op {label:?}: the runtime refused the call (code {other}); the \
label or key argument is malformed"
            ),
        }
    }
    #[cfg(not(any(patina_shim, all(patina, target_arch = "wasm32"))))]
    {
        let _ = (label, key, on_fault);
        perform()
    }
}

/// The two ABI mirrors of the custom-op verbs behind one name, so
/// [`custom_op_bytes`] states the protocol once instead of twice.
#[cfg(any(patina_shim, all(patina, target_arch = "wasm32")))]
mod custom_op_ffi {
    #[inline]
    pub unsafe fn begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32 {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes live slices.
        unsafe {
            super::ffi::patina_custom_op_begin(
                label,
                label_len,
                key,
                key_len,
                fault_eligible,
                out_len,
            )
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_begin(
                label,
                label_len,
                key,
                key_len,
                fault_eligible,
                out_len,
            )
        }
    }

    #[inline]
    pub unsafe fn replay_result(out: *mut u8, out_cap: usize) -> isize {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes a live buffer.
        unsafe {
            super::ffi::patina_custom_op_replay_result(out, out_cap)
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_replay_result(out, out_cap) as isize
        }
    }

    #[inline]
    pub unsafe fn record(result: *const u8, result_len: usize) -> i32 {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes a live slice.
        unsafe {
            super::ffi::patina_custom_op_record(result, result_len)
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_record(result, result_len)
        }
    }
}

/// A typed [`custom_op_bytes`]: the same record/replay contract with the key and
/// the result carried as ordinary Rust values.
///
/// Requires the default-off `custom-ops` feature, which is the only thing in this
/// crate that pulls in a dependency (`serde` + `serde_json`); the untyped
/// [`custom_op_bytes`] is always available and needs nothing extra.
///
/// ```ignore
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Object { etag: String, body: Vec<u8> }
///
/// let object: Object = patina_dst::custom_op("s3.get_object", &request_key, || {
///     real_s3_client.get(&request_key) // runs on record only
/// });
/// ```
///
/// # The encoding is build-owned, not ABI-owned
///
/// Values are encoded with `serde_json`. The shim ABI and the trace carry opaque
/// bytes precisely so no serialization format is pinned into the boundary
/// contract, and a recorded trace only ever replays against the guest binary
/// that produced it — which the run fingerprint already enforces. So the choice
/// lives here, in the guest's build. JSON rather than a denser binary format
/// because a custom op's value is triage: the key and result stay legible in
/// `cargo patina trace`, which a non-self-describing encoding would reduce to a
/// blob. It is also already in the workspace, so it adds no third-party crate.
///
/// # Panics
///
/// If the value cannot be encoded, or a recorded result cannot be decoded into
/// `T` — the latter means the trace was recorded by a guest whose result type no
/// longer matches this one, which is a fail-closed refusal, not a value to guess
/// at.
#[cfg(feature = "custom-ops")]
pub fn custom_op<T, K>(label: &str, key: &K, perform: impl FnOnce() -> T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    K: serde::Serialize + ?Sized,
{
    let key = serde_json::to_vec(key)
        .unwrap_or_else(|error| panic!("patina custom op {label:?}: cannot encode key: {error}"));
    // `performed` carries the record pass's value out of the closure so the
    // caller gets exactly what `perform` returned, not a re-decoded copy of it.
    let mut performed = None;
    let bytes = custom_op_bytes(label, &key, || {
        let value = perform();
        let bytes = serde_json::to_vec(&value).unwrap_or_else(|error| {
            panic!("patina custom op {label:?}: cannot encode result: {error}")
        });
        performed = Some(value);
        bytes
    });
    match performed {
        Some(value) => value,
        None => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "patina custom op {label:?}: cannot decode the recorded result: {error}; the \
recording was produced by a guest whose result type no longer matches this one"
            )
        }),
    }
}

/// A typed [`custom_op_bytes_faultable`]: [`custom_op`] plus a declared failure
/// shape, so `--custom-op-fail-permille` can fail the operation and the guest
/// exercises its own error path.
///
/// `on_fault` returns the value a failure produces — for a `Result`-shaped `T`,
/// the `Err` variant the caller already handles. It runs *instead of* `perform`
/// when a seeded fault fires, and never otherwise.
///
/// ```ignore
/// let object: Result<Object, FetchError> = patina_dst::custom_op_faultable(
///     "s3.get_object",
///     &request_key,
///     || Err(FetchError::Timeout),        // what failure means here
///     || real_s3_client.get(&request_key), // runs on record only
/// );
/// ```
///
/// # Panics
///
/// As [`custom_op`]: an unencodable value or an undecodable recorded result.
#[cfg(feature = "custom-ops")]
pub fn custom_op_faultable<T, K>(
    label: &str,
    key: &K,
    on_fault: impl FnOnce() -> T,
    perform: impl FnOnce() -> T,
) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    K: serde::Serialize + ?Sized,
{
    let key = serde_json::to_vec(key)
        .unwrap_or_else(|error| panic!("patina custom op {label:?}: cannot encode key: {error}"));
    // A `RefCell` rather than `custom_op`'s plain `&mut`: both closures are
    // handed over at once and exactly one of them runs, so they must share the
    // slot the produced value comes back through.
    let produced: core::cell::RefCell<Option<T>> = core::cell::RefCell::new(None);
    let encode = |value: T| -> Vec<u8> {
        let bytes = serde_json::to_vec(&value).unwrap_or_else(|error| {
            panic!("patina custom op {label:?}: cannot encode result: {error}")
        });
        *produced.borrow_mut() = Some(value);
        bytes
    };
    let bytes = custom_op_bytes_faultable(label, &key, || encode(on_fault()), || encode(perform()));
    match produced.into_inner() {
        Some(value) => value,
        None => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "patina custom op {label:?}: cannot decode the recorded result: {error}; the \
recording was produced by a guest whose result type no longer matches this one"
            )
        }),
    }
}
