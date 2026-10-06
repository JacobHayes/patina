//! Native platform capabilities and pre-run audit gates.

use super::*;
#[cfg(unix)]
/// Does `policy` downgrade the denied import `escape` from a hard error to a
/// warning? Matches the raw import name and its underscore-stripped alias so an
/// operator can pass either `_os_unfair_lock_lock` or `os_unfair_lock_lock`.
fn policy_downgrades(policy: &UnsupportedPolicy, escape: &NativeEscape) -> bool {
    match policy {
        UnsupportedPolicy::Deny => false,
        UnsupportedPolicy::All => true,
        UnsupportedPolicy::Only(symbols) => {
            symbols.contains(&escape.symbol)
                || symbols.contains(escape.symbol.trim_start_matches('_'))
                // An instruction-class finding is named `instruction@.text+OFF`,
                // an address that moves on every relink, so it can also be
                // allowed by the CONTAINING symbol its provenance names (e.g. an
                // undecodable AVX-512 site in a SIMD kernel the guest never
                // dispatches to): stable across rebuilds, still scoped to one
                // function rather than `all`.
                || (escape.symbol.starts_with("instruction@")
                    && escape.provenance.iter().any(|provenance| {
                        provenance
                            .containing_symbol
                            .as_deref()
                            .is_some_and(|containing| symbols.contains(containing))
                    }))
        }
    }
}

/// Whether the running kernel supports syscall-user-dispatch, probed the same
/// way the shim's C layer probes it: `prctl(PR_SET_SYSCALL_USER_DISPATCH,
/// PR_SYS_DISPATCH_OFF, 0, 0, 0)` returns 0 on a SUD kernel and `-EINVAL` where
/// the feature is absent (arm64 <= 6.18, pre-5.11 x86). Runs in the supervisor
/// process, the same kernel the guest will run on. Non-Linux always returns
/// `false` (SUD is Linux-only), so the audit downgrade never fires off-Linux.
#[cfg(target_os = "linux")]
fn kernel_supports_sud() -> bool {
    // prctl SUD op numbers; 6.8 UAPI headers may predate the constants, so pin
    // the values the design verified against the v6.8 kernel source.
    const PR_SET_SYSCALL_USER_DISPATCH: std::ffi::c_int = 59;
    const PR_SYS_DISPATCH_OFF: std::ffi::c_ulong = 0;
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // SAFETY: the OFF form with all-zero args is a pure feature probe — it turns
    // dispatch off (a no-op when it was never on) and mutates no process state.
    let rc = unsafe {
        prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_OFF,
            0usize,
            0usize,
            0usize,
        )
    };
    rc == 0
}

#[cfg(not(target_os = "linux"))]
fn kernel_supports_sud() -> bool {
    false
}

/// Whether this platform can arm the shim's timestamp-counter trap, probed the
/// same way the shim's C layer probes it: `prctl(PR_GET_TSC, &mode)` returns 0
/// where `PR_SET_TSC` exists and `-EINVAL` where it does not. `PR_SET_TSC` is an
/// x86 facility, so the probe is compiled only for x86-64 Linux and every other
/// platform returns `false` — the rdtsc audit downgrade never fires off it.
/// Runs in the supervisor process, on the same kernel the guest will run on.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_supports_tsc_trap() -> bool {
    const PR_GET_TSC: std::ffi::c_int = 25;
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    let mut mode: std::ffi::c_int = 0;
    // SAFETY: PR_GET_TSC only reads the current per-thread setting into `mode`.
    let rc = unsafe {
        prctl(
            PR_GET_TSC,
            &mut mode as *mut std::ffi::c_int,
            0usize,
            0usize,
            0usize,
        )
    };
    rc == 0
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_supports_tsc_trap() -> bool {
    false
}

/// The effective symbol allow set the native gate audits against: the shim's own
/// control-plane vehicle (auto-allowed on every `cargo patina build` binary —
/// `dlsym` on both platforms) plus the operator's explicit `--allow` symbols.
///
/// Constructed in exactly ONE place and called by BOTH the standalone `audit`
/// (`execute_native_audit`) and the pre-run `run` gate (`native_prerun_gate`), so
/// the static surface `audit` reports and the static surface `run` enforces can
/// never drift: a symbol one tolerates, the other tolerates too. This closes the
/// reported disparity where `audit` reported `_dlsym (dynamic-loading)` as denied
/// while `run` silently permitted it as the shim control-plane vehicle.
pub(crate) fn effective_native_allow(user_allow: &BTreeSet<String>) -> BTreeSet<String> {
    let mut allow = shim_control_plane_symbols();
    allow.extend(user_allow.iter().cloned());
    allow
}

/// Emit the non-blocking "fails later" note for the deny-trap-armed symbols a
/// shim-linked binary references. These symbols pass the import audit and the
/// pre-run gate (the shim strong-def drops them off the import table), but a call
/// aborts the run deterministically — a guarantee the import-table audit is blind
/// to by construction. Surfacing it up front at `audit` and `run` makes the
/// "fails later" contract visible before the guest is launched. Informational
/// only: stderr, never touches the exit code, and stays off stdout so a `--format
/// json` envelope is unaffected. A read/parse hiccup here must never fail the
/// caller's real operation, so it is swallowed (the note is best-effort).
pub(crate) fn emit_native_deny_trap_note(bytes: &[u8]) {
    let armed = match native_deny_trap_armed(bytes) {
        Ok(armed) if !armed.is_empty() => armed,
        _ => return,
    };
    let list = armed
        .iter()
        .map(|trap| format!("{} ({})", trap.symbol, trap.class))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "note: {} linked symbol(s) are deny-trap armed under patina (a call aborts \
deterministically): {list}",
        armed.len()
    );
}

/// Whether a *build* target has kernel syscall-user-dispatch, so a shim-linked
/// guest's raw inline syscalls are trapped at runtime rather than needing the
/// `--cfg rustix_use_libc` interposition workaround. x86_64 Linux has SUD since
/// 5.11; arm64 Linux does not yet (it needs the generic-entry kernels), so it
/// keeps the workaround. macOS never reaches here for rustix (it uses libc), so
/// its classification is moot. This is a build-time target decision (which cfg
/// to inject), distinct from the run-time [`kernel_supports_sud`] probe (whether
/// THIS kernel can trap). SUD-DESIGN.md §9.
pub(crate) fn target_has_sud(target: &str) -> bool {
    target.starts_with("x86_64") && target.contains("linux")
}

pub(super) fn native_prerun_gate(
    binary: &Path,
    allow: &BTreeSet<String>,
    policy: &UnsupportedPolicy,
) -> Result<Vec<NativeEscape>, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read native program {} for the pre-run audit: {error}",
            binary.display()
        ))
    })?;
    let effective = effective_native_allow(allow);
    let denied = match NativeAudit::audit(&bytes, &effective) {
        Ok(_) => {
            // Clean import audit: the run proceeds. Surface the "fails later"
            // deny-trap note once, up front, before the guest is launched.
            emit_native_deny_trap_note(&bytes);
            return Ok(Vec::new());
        }
        Err(TargetError::UnsupportedNativeImports(denied)) => denied,
        // A binary we cannot even parse/format-check must never run.
        Err(other) => {
            return Err(CliError(format!(
                "refusing to run {}: {other}",
                binary.display()
            )));
        }
    };

    // syscall-user-dispatch downgrade (SUD-DESIGN.md §7.1): a `direct-syscall`
    // *instruction* finding is trapped into the deterministic runtime at run time
    // — not an escape — iff BOTH (a) the binary carries the shim's SUD dispatch
    // marker and (b) the live kernel probe says SUD is available. Both conditions
    // together: an old-shim binary (no marker) or a no-SUD kernel keeps today's
    // refusal. cpu-nondeterminism findings are never SUD-manageable (register
    // reads SUD cannot trap), so they never enter this split.
    let shim_linked =
        native_binary_is_shim_linked(&bytes).map_err(|error| CliError(error.to_string()))?;
    let sud_marker = native_binary_has_sud_marker(&bytes).unwrap_or(false);
    let sud_ok = sud_marker && kernel_supports_sud();
    // The timestamp-counter trap downgrade, on the same two conditions: the
    // binary carries the trap dispatcher AND this platform can arm PR_SET_TSC.
    // Only rdtsc/rdtscp enter this split — rdrand/rdseed/CNTVCT share the
    // category but no mechanism traps them, so they stay in `remaining`.
    let tsc_ok =
        native_binary_has_tsc_marker(&bytes).unwrap_or(false) && platform_supports_tsc_trap();
    let (sud_instructions, rest): (Vec<_>, Vec<_>) = denied
        .into_iter()
        .partition(native_escape_is_sud_manageable);
    let (tsc_instructions, rest): (Vec<_>, Vec<_>) =
        rest.into_iter().partition(native_escape_is_tsc_manageable);
    let mut sud_managed = Vec::new();
    let mut remaining = rest;
    if tsc_ok {
        if let Some(note) =
            render_tsc_managed_note(&tsc_instructions, &binary.display().to_string())
        {
            eprintln!("{note}");
        }
    } else {
        // Not trappable here: fold back so the counter reads are blocked (with
        // the cpu-nondeterminism note below naming why), or force-runnable via
        // the operator's --allow-unsupported-symbols hatch.
        remaining.extend(tsc_instructions);
    }
    if sud_ok {
        sud_managed = sud_instructions;
    } else {
        // Not downgradable here: fold back so these raw-syscall sites are blocked
        // (with a SUD-specific hint below) — or force-runnable via the operator's
        // --allow-unsupported-symbols hatch, exactly as before SUD.
        remaining.extend(sud_instructions);
    }

    if !sud_managed.is_empty() {
        eprintln!(
            "patina: {} direct-syscall instruction site(s) in {} are SUD-managed: trapped into the \
deterministic runtime via syscall-user-dispatch (kernel SUD present, shim dispatcher linked). \
These are contained, not escapes — the run stays deterministic.",
            sud_managed.len(),
            binary.display()
        );
    }

    let (downgraded, blocked): (Vec<_>, Vec<_>) = remaining
        .into_iter()
        .partition(|escape| policy_downgrades(policy, escape));

    if !blocked.is_empty() {
        let has_raw_syscall = blocked.iter().any(native_escape_is_sud_manageable);
        let mut message = format!(
            "refusing to run {}: {} symbol(s) on the blocking/time/scheduling/effect surface are \
neither interposed by the deterministic runtime nor known-safe (default-deny). Interpose them, or \
pass --allow-unsupported-symbols <all|name,name,...> to run anyway with a warning:",
            binary.display(),
            blocked.len()
        );
        for escape in &blocked {
            message.push_str(&format!("\n  {}", native_escape_summary(escape)));
            push_native_escape_provenance_lines(&mut message, escape, "    ");
        }
        if has_raw_syscall && !kernel_supports_sud() {
            // A genuine kernel capability gap; preserve today's explanation.
            message.push_str(
                "\nnote: the direct-syscall instruction site(s) above are raw inline syscalls. This \
kernel lacks syscall-user-dispatch (arm64 needs the generic-entry kernels; x86_64 has it since \
5.11), so they cannot be trapped here. Rebuild with `--cfg rustix_use_libc` (rustix's libc \
backend emits interposable imports instead), or run on an x86_64 SUD kernel where the shim traps \
them.",
            );
        }
        if has_raw_syscall && kernel_supports_sud() && !shim_linked {
            message.push_str(
                "\nnote: the direct-syscall instruction site(s) above are raw inline syscalls. This \
binary is not linked with Patina's shim (for example, it is static, stock, or built without \
Patina), so it has no SUD dispatcher marker and the syscalls cannot be trapped in-process. Build \
from source with `cargo patina build <SOURCE.rs|DIR|Cargo.toml>`, or pass the source/package to \
`cargo patina run` to build and run it with the shim.",
            );
        }
        if has_raw_syscall && kernel_supports_sud() && shim_linked && !sud_marker {
            message.push_str(
                "\nnote: this binary is linked with Patina, but its shim has no SUD dispatcher marker \
(for example, it may have been built with an older shim); raw inline syscalls cannot be trapped \
in-process. Rebuild from source with `cargo patina build <SOURCE.rs|DIR|Cargo.toml>`, or pass the \
source/package to `cargo patina run` to link the current shim.",
            );
        }
        if let Some(note) = render_cpu_nondeterminism_note(&blocked) {
            // Instruction-class findings have no symbol name, so `--allow` can
            // never clear one; and only the timestamp counter is trappable at
            // all. Say both, rather than leaving the operator to infer them.
            message.push('\n');
            message.push_str(&note);
        }
        if let Some(note) = render_thread_pointer_note(&blocked) {
            // A moved thread pointer corrupts the shim itself, so the note names
            // the instruction and says why no downgrade exists for it.
            message.push('\n');
            message.push_str(&note);
        }
        if let Some(note) = render_compat_mode_note(&blocked) {
            // int 0x80/sysenter are direct syscalls SUD cannot manage, so the
            // SUD hint above does not cover them; say why they stay refused.
            message.push('\n');
            message.push_str(&note);
        }
        if blocked
            .iter()
            .any(|escape| escape.category == "macos-framework")
        {
            // CoreFoundation/Security framework calls: name the determinism problem
            // and the explicit allow path with its qualified-determinism caveat.
            message.push_str(
                "\nnote: the macos-framework symbol(s) above are macOS CoreFoundation/Security \
framework calls that the deterministic runtime does not interpose. The common dormant \
native-trust-root surface (rustls-native-certs: SecTrustSettingsCopy*, SecCertificateCopyData, the \
CF* helpers, kCFAllocator*) is now deny-trap interposed — a binary that merely LINKS it runs, and a \
genuine call aborts deterministically, so it never reaches this refusal. A macos-framework symbol \
reaching HERE is one the shim does not deny-trap (a non-enumerated framework symbol, or a prebuilt \
non-shim binary): the Security-framework subset reads the host keychain and system trust store — \
mutable host state that varies by machine and over time — so a run that reaches it is NOT \
reproducible. Compile the framework path out, or pass --allow-unsupported-symbols \
<all|name,name,...> to run anyway with a warning; determinism is then only qualified — the trust \
store the guest reads is whatever the host holds at run time.",
            );
        }
        if blocked
            .iter()
            .any(|escape| escape.category == "host-introspection")
        {
            // Mach/BSD/IOKit host-state reads: name the determinism problem and
            // the interpose-or-refuse posture (these must never be allowlisted).
            message.push_str(
                "\nnote: the host-introspection symbol(s) above read host CPU/memory/hardware/process \
state — nondeterministic across hosts and runs; interpose-or-refuse, never allowlist. The dormant \
hardware-inventory surface (sysinfo: host_statistics64/host_processor_info, the IOKit registry \
walk, mach_host_self, proc_*, vm_deallocate) is now deny-trap interposed — a binary that merely \
LINKS it runs, and a genuine call aborts deterministically. A host-introspection symbol reaching \
HERE is a live-path member a normal startup actually reaches (sysctl/sysctlbyname, getrusage, \
task_info) that stays refused pending a deterministic interposer, or a prebuilt non-shim binary. A \
run that reaches one is not reproducible, so it is refused; pass --allow-unsupported-symbols \
<all|name,name,...> to run anyway with a warning, but determinism is then only qualified.",
            );
        }
        return Err(CliError(message));
    }

    if !downgraded.is_empty() {
        eprintln!(
            "patina: WARNING: running {} with {} UNSUPPORTED symbol(s) downgraded from error by \
--allow-unsupported-symbols:",
            binary.display(),
            downgraded.len()
        );
        for escape in &downgraded {
            eprintln!("patina:   {}", native_escape_summary(escape));
            for provenance in &escape.provenance {
                eprintln!("patina:     {}", provenance.label());
            }
        }
        eprintln!(
            "patina: these host symbols are NOT interposed by the deterministic runtime; if the \
guest reaches them at run time it can block, read host time, or otherwise escape the scheduler. \
This run's determinism is NOT guaranteed and any \"deterministic\" claim on it is qualified."
        );
    }

    // The run proceeds (clean, or with downgraded symbols). Surface the "fails
    // later" deny-trap note once, up front, before the guest is launched.
    emit_native_deny_trap_note(&bytes);
    Ok(downgraded)
}

#[cfg(test)]
mod tests;
