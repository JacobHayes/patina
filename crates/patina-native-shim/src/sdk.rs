//! Cooperative-SUT buggify, verdict, custom-operation, and lifecycle ABI.

use super::*;

// ---- Cooperative-SUT (buggify) C ABI -----------------------------------------
//
// The runtime side of the `patina` crate's `buggify!`, `always!`, `sometimes!`,
// `reachable!`, `buggify_knob!`, `buggify_delay!`, `rng`, and lifecycle macros.
// Labels and call-site identities arrive as `(ptr, len)` UTF-8 slices. Fatal
// signals (`always!` violation, duplicate label) flush captured output, emit a
// distinct marker line to the real stderr, and abort — never a silent escape.

/// Reborrow a `(ptr, len)` pair as a UTF-8 label. `None` (invalid UTF-8 or a null
/// non-empty pointer) is a fail-closed error at the call sites below.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null when `len == 0`.
unsafe fn buggify_label<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by this function's documented contract.
    std::str::from_utf8(unsafe { slice::from_raw_parts(ptr, len) }).ok()
}

/// Flush captured guest output, emit `<marker> label=<label>` to the real
/// stderr through the non-interposed host alias, and abort. Mirrors
/// [`abort_with_init_error`] so the marker lands after buffered guest output.
///
/// Reserved for patina's own *refusals* — a duplicate buggify label and its
/// peers, whose marker is what `cargo patina`'s envelope attributes the refusal
/// from. A system-under-test finding does NOT come through here: it is reported
/// as a verdict ([`abort_after_verdict`]).
pub(crate) fn abort_with_buggify_marker(marker: &str, label: &str) -> ! {
    let _ = flush_before_refusal();
    let line = format!("{marker} label={label}\n");
    let _ = host_write_all(2, line.as_bytes());
    crate::host_abort();
}

/// Flush captured guest output and abort, printing nothing of the shim's own.
///
/// The run's finding has already been reported through the verdict ABI and
/// drained into the captured stderr as a `PATINA_VERDICT` line, so a second
/// hand-formatted marker would be a duplicate channel — and the classifier reads
/// the verdict, never a marker (`docs/arcs/outcome-channel.md`).
fn abort_after_verdict() -> ! {
    let _ = flush_before_refusal();
    crate::host_abort();
}

/// Move the runtime's queued diagnostic lines (today: `PATINA_VERDICT`) into the
/// captured stderr stream. The runtime performs no process I/O of its own mid-run,
/// so every shim entry point that can produce one drains it here — including on
/// the fatal paths, where [`abort_with_buggify_marker`] / [`abort_after_verdict`]
/// flush the capture before aborting and the lines therefore still reach the real
/// stderr.
fn drain_runtime_diagnostics() {
    let lines = with_context_raw(|context| Ok(context.take_pending_diagnostics()));
    for line in lines.unwrap_or_default() {
        capture_stderr_line(&line);
    }
}

/// Append a diagnostic line to the captured stderr buffer so it interleaves with
/// guest output and flushes at exit (lifecycle markers). Bounded like guest I/O.
pub(crate) fn capture_stderr_line(line: &str) {
    stdio_slot().lock().put(1, &[line.as_bytes(), b"\n"]);
}

/// Shared body for the site-evaluating buggify entry points: read the label and
/// call site, invoke the context method, map the outcome to `1`=fire / `0`=no,
/// and abort on a fatal always-violation or duplicate label.
fn buggify_site_call(
    label_ptr: *const u8,
    label_len: usize,
    site_ptr: *const u8,
    site_len: usize,
    invoke: impl FnOnce(&mut Context, &str, &str) -> Result<SiteOutcome, RuntimeError>,
) -> c_int {
    // SAFETY: the caller (the `patina` crate macro expansion) passes live slices.
    let label = match unsafe { buggify_label(label_ptr, label_len) } {
        Some(label) => label,
        None => return fail(EINVAL),
    };
    let site = match unsafe { buggify_label(site_ptr, site_len) } {
        Some(site) => site,
        None => return fail(EINVAL),
    };
    let outcome = with_context(|context| invoke(context, label, site));
    // Before acting on the outcome: an `always!` violation lowers to a verdict,
    // and the fatal arm below never returns. The drained `PATINA_VERDICT` line is
    // the violation's ONLY announcement — there is no second marker.
    drain_runtime_diagnostics();
    match outcome {
        Ok(SiteOutcome::Fire) => 1,
        Ok(SiteOutcome::Ok) => 0,
        Ok(SiteOutcome::AlwaysViolation) => abort_after_verdict(),
        Ok(SiteOutcome::DuplicateLabel) => {
            abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label)
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `patina_dst::is_simulated()`: 1 whenever the deterministic runtime is installed.
pub extern "C" fn patina_is_simulated() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::from(ensure_runtime().is_ok())
}

#[unsafe(no_mangle)]
/// `buggify!` / `buggify_with_prob!`: `prob_permille < 0` uses the run default.
/// Returns 1 when the site fires, 0 otherwise.
///
/// # Safety
/// Label and site pointers must describe live UTF-8 slices of the given lengths.
pub unsafe extern "C" fn patina_buggify(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
    prob_permille: i32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        let prob = (prob_permille >= 0).then(|| prob_permille.clamp(0, 1000) as u16);
        context.buggify_evaluate(l, s, prob)
    })
}

#[unsafe(no_mangle)]
/// `buggify_delay!`: on firing, advance virtual time deterministically. Returns
/// 1 when it delayed.
///
/// # Safety
/// See [`patina_buggify`].
pub unsafe extern "C" fn patina_buggify_delay(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, |context, l, s| {
        context.buggify_delay(l, s)
    })
}

#[unsafe(no_mangle)]
/// `buggify_knob!`: a per-run perturbed value within `[lo, hi]` for an active
/// site, or `default` otherwise. A duplicate label aborts.
///
/// # Safety
/// See [`patina_buggify`].
pub unsafe extern "C" fn patina_buggify_knob(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
    default: i64,
    lo: i64,
    hi: i64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes live slices.
    let label = match unsafe { buggify_label(label, label_len) } {
        Some(label) => label,
        None => return default,
    };
    let site = match unsafe { buggify_label(site, site_len) } {
        Some(site) => site,
        None => return default,
    };
    match with_context(|context| context.buggify_knob(label, site, default, lo, hi)) {
        Ok(Ok(value)) => value,
        Ok(Err(())) => abort_with_buggify_marker("PATINA_BUGGIFY_DUPLICATE_LABEL", label),
        Err(_) => default,
    }
}

#[unsafe(no_mangle)]
/// `always!`: a false `condition` is a fatal invariant violation under the
/// simulator (independent of buggify being enabled).
///
/// # Safety
/// See [`patina_buggify`].
pub unsafe extern "C" fn patina_always(
    condition: c_int,
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        context.always_check(l, s, condition != 0)
    })
}

#[unsafe(no_mangle)]
/// `sometimes!`: coverage oracle noting the site reached and satisfied-if-true.
///
/// # Safety
/// See [`patina_buggify`].
pub unsafe extern "C" fn patina_sometimes(
    condition: c_int,
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, move |context, l, s| {
        context.sometimes_check(l, s, condition != 0)
    })
}

#[unsafe(no_mangle)]
/// `reachable!`: coverage oracle noting the site reached.
///
/// # Safety
/// See [`patina_buggify`].
pub unsafe extern "C" fn patina_reachable(
    label: *const u8,
    label_len: usize,
    site: *const u8,
    site_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    buggify_site_call(label, label_len, site, site_len, |context, l, s| {
        context.reachable_mark(l, s)
    })
}

#[unsafe(no_mangle)]
/// `patina_dst::verdict(...)`: report one structured guest verdict.
///
/// The verdict ABI is a SINGLE verb — `kind` is data, not a symbol per kind — so
/// a new [`VerdictKind`] never grows the shim's export surface. An unknown `kind`
/// is refused with `EINVAL` rather than defaulted: a guest built against a newer
/// enum than the shim understands must fail closed, not have its verdict silently
/// reclassified. The call is recorded in the trace and its `PATINA_VERDICT` line
/// enters the captured stderr stream, so it survives a subsequent guest abort.
///
/// # Safety
/// Label and detail pointers must describe live UTF-8 slices of the given
/// lengths (or be null with a zero length).
pub unsafe extern "C" fn patina_verdict(
    kind: u32,
    label: *const u8,
    label_len: usize,
    detail: *const u8,
    detail_len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(kind) = VerdictKind::from_abi(kind) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(detail) = (unsafe { buggify_label(detail, detail_len) }) else {
        return fail(EINVAL);
    };
    let result = with_context(|context| context.verdict(kind, label, detail));
    drain_runtime_diagnostics();
    match result {
        Ok(_) => 0,
        Err(errno) => fail(errno),
    }
}

// The custom-op ABI: three verbs, one per phase of a single operation.
//
// Why three symbols rather than one verb with a phase argument (the shape the
// verdict ABI uses for its kinds): a verdict's kinds are values of ONE call, so
// carrying them as data keeps the call shape fixed. A custom op's phases are
// three different calls with three different argument shapes and three different
// directions of data flow — announce (in), fetch the recorded result (out),
// report a fresh result (in). Folding them into one signature would mean
// arguments that are meaningful on one phase and ignored on the others, and
// ignored arguments are exactly where a fail-closed check goes blind. The
// property the verdict doctrine protects — no new symbol per *op class* — is
// intact: the op class is the `label`, which is data.
//
// The protocol, which the SDK's `custom_op_bytes` drives:
//
//   1. `patina_custom_op_begin(label, key, fault_eligible, &out_len)`
//        -> 0: record pass. Run `perform`, then call `patina_custom_op_record`.
//        -> 1: replay pass. Do NOT run `perform`; `out_len` is the recorded
//              result's length, fetched with `patina_custom_op_replay_result`.
//        -> 2: a seeded fault fired (or the recording holds one). Do NOT run
//              `perform`; return the failure the call declared. The operation is
//              already closed — there is no phase-2 call.
//   2a. `patina_custom_op_record(result, result_len)` closes a record pass.
//   2b. `patina_custom_op_replay_result(out, out_cap)` closes a replay pass.
//
// `fault_eligible` (nonzero) is the guest's declaration that this call has a
// failure shape it handles, which is what `--custom-op-fail-permille` acts on.
// The declared failure itself never crosses the boundary: only the guest's own
// types know a value the call site can return, so the shim decides WHETHER the
// operation fails and the guest supplies WHAT that means.
//
// Every runtime-level refusal (a replay divergence on the label or key, a nested
// or unclosed operation, a modeled effect performed inside `perform`) is fatal:
// there is no answer the guest could safely be handed, so the shim aborts loudly
// rather than returning an errno the guest could swallow and continue past. Only
// malformed arguments — a non-UTF-8 label, a null pointer with a nonzero length —
// return `EINVAL`, because those are the guest's own call being wrong.

/// Announce a custom operation; returns 0 for "record pass, run `perform`", 1
/// for "replay pass, the answer is recorded", or 2 for "seeded fault, return the
/// declared failure". See the module comment above.
///
/// # Safety
/// `label`/`key` must describe live slices of the given lengths (or be null with
/// a zero length), and `out_len` must be a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_custom_op_begin(
    label: *const u8,
    label_len: usize,
    key: *const u8,
    key_len: usize,
    fault_eligible: c_int,
    out_len: *mut usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes live slices.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    // SAFETY: the caller passes live slices.
    let Some(key) = (unsafe { custom_op_bytes(key, key_len) }) else {
        return fail(EINVAL);
    };
    if out_len.is_null() {
        return fail(EINVAL);
    }
    match with_context(|context| context.custom_op_begin(label, key, fault_eligible != 0)) {
        Ok(CustomOpMode::Record) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(0) };
            0
        }
        Ok(CustomOpMode::Replay { len }) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(len) };
            1
        }
        Ok(CustomOpMode::Fault) => {
            // SAFETY: checked non-null above; the caller guarantees writability.
            unsafe { out_len.write(0) };
            2
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Copy the recorded result of the open custom operation into `out`, closing it.
/// Returns the number of bytes written, or -1 when `out_cap` is smaller than the
/// length `patina_custom_op_begin` reported (nothing is copied and the operation
/// stays open, so the caller can retry with a large enough buffer).
///
/// # Safety
/// `out` must be writable for `out_cap` bytes, or be null when `out_cap == 0`.
pub unsafe extern "C" fn patina_custom_op_replay_result(out: *mut u8, out_cap: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `with_context_raw`, not `with_context`: one custom operation is ONE
    // boundary, and its scheduling point was already taken by
    // `patina_custom_op_begin`. Taking a second one here would let another
    // managed task record operations between the two halves, which is exactly
    // what `Context::custom_op_record`'s "no modeled effects inside `perform`"
    // check reads as a guest error.
    let taken = with_context_raw(|context| {
        // A short buffer must not consume the recorded result: report the
        // shortfall and leave the operation open so a retry can still succeed.
        if context
            .custom_op_pending_len()
            .is_some_and(|len| len > out_cap)
        {
            return Ok(None);
        }
        context.custom_op_replay_result().map(Some)
    });
    let bytes = match taken {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            set_errno(EINVAL);
            return -1;
        }
        Err(errno) => return fail(errno) as isize,
    };
    if !bytes.is_empty() {
        if out.is_null() {
            return fail(EINVAL) as isize;
        }
        // SAFETY: the caller guarantees `out` is writable for `out_cap >= len`.
        unsafe { slice::from_raw_parts_mut(out, out_cap)[..bytes.len()].copy_from_slice(&bytes) };
    }
    bytes.len() as isize
}

#[unsafe(no_mangle)]
/// Report what the guest's `perform` produced, closing the open custom operation
/// and recording its trace event.
///
/// # Safety
/// `result` must describe a live slice of `result_len` bytes (or be null with a
/// zero length).
pub unsafe extern "C" fn patina_custom_op_record(result: *const u8, result_len: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a live slice.
    let Some(result) = (unsafe { custom_op_bytes(result, result_len) }) else {
        return fail(EINVAL);
    };
    // `with_context_raw` for the same reason as `patina_custom_op_replay_result`:
    // the operation's single scheduling point was taken at `begin`.
    match with_context_raw(|context| context.custom_op_record(result.to_vec())) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// Reborrow a `(ptr, len)` pair as opaque custom-op bytes. Unlike
/// [`buggify_label`] there is no UTF-8 requirement — a custom-op key or result is
/// whatever the guest's encoding produced — but a null pointer with a nonzero
/// length is still a fail-closed error.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null when `len == 0`.
unsafe fn custom_op_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by this function's documented contract.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

#[unsafe(no_mangle)]
/// `patina_dst::rng()`: a deterministic 64-bit draw bridged to the root seed.
pub extern "C" fn patina_rng() -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    with_context(|context| Ok(context.buggify_rng())).unwrap_or(0)
}

#[unsafe(no_mangle)]
/// `patina_dst::lifecycle::setup_complete()`: mark the setup boundary and emit a marker.
pub extern "C" fn patina_lifecycle_setup_complete() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = with_context(|context| {
        context.lifecycle_setup_complete();
        Ok(())
    });
    capture_stderr_line("PATINA_LIFECYCLE setup_complete");
    0
}

#[unsafe(no_mangle)]
/// `patina_dst::lifecycle::event!("label")`: emit a lifecycle marker.
///
/// # Safety
/// Label pointer must describe a live UTF-8 slice of `label_len` bytes.
pub unsafe extern "C" fn patina_lifecycle_event(label: *const u8, label_len: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller passes a live slice.
    let Some(label) = (unsafe { buggify_label(label, label_len) }) else {
        return fail(EINVAL);
    };
    capture_stderr_line(&format!("PATINA_LIFECYCLE_EVENT label={label}"));
    0
}
