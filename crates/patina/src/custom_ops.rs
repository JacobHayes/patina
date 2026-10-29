//! Custom operations and their record/replay protocol.

#[cfg(patina_shim)]
use crate::ffi;
#[cfg(doc)]
use crate::verdict;

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
///   shares the site-label namespace of [`crate::sometimes!`]/[`crate::buggify!`] and
///   aggregates like a [`verdict`] label, but a custom op registers no fault
///   site, so the duplicate-label rule does not apply and one label naming many
///   calls in a run is exactly the point.
/// - `key` is the operation's logical input. It is recorded with the result and
///   checked on replay, so a guest that asks a *different* question under the
///   same label is refused rather than handed a stale answer.
///
/// It lowers directly to the shim ABI with no encoding of its own.
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
    #[cfg(patina_shim)]
    {
        let mut len: usize = 0;
        let mode = unsafe {
            ffi::patina_custom_op_begin(
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
                let code = unsafe { ffi::patina_custom_op_record(result.as_ptr(), result.len()) };
                assert!(
                    code >= 0,
                    "patina custom op {label:?}: the runtime refused the recorded result"
                );
                result
            }
            1 => {
                let mut buffer = vec![0u8; len];
                let written = unsafe {
                    ffi::patina_custom_op_replay_result(buffer.as_mut_ptr(), buffer.len())
                };
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
    #[cfg(not(patina_shim))]
    {
        let _ = (label, key, on_fault);
        perform()
    }
}
