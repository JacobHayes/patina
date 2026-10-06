//! Native pre-run gates, trace channels, and child execution.

use crate::audit::{native_escape_summary, push_native_escape_provenance_lines};
#[cfg(unix)]
use crate::crash_restart::{
    IncarnationLaunch, append_native_infra_marker, crash_restart_plan, supervise_crash_restart,
};
use crate::native_build::{
    SchedulePolicyFingerprint, binary_instrumentation, native_policy_from_trace,
    native_run_fingerprint, resolve_artifact, trace_has_buggify,
};
use crate::output;
use crate::parse::{knob_env_pairs, knob_env_vars, liveness_env_pairs, schedule_env_pairs};
use crate::{
    CliError, NATIVE_GUEST_ARGV0, NativeRunInvocation, NativeRunMode, UnsupportedPolicy, coverage,
};
#[cfg(unix)]
use crate::{F_GETFD, F_SETFD, FD_CLOEXEC, fcntl};
use patina_dst_fs_mem::{FsImage, FsImageEntry};
use patina_dst_runtime::{
    ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF,
    ENV_COVERAGE_FD, ENV_DEFER_INIT, ENV_FINGERPRINT, ENV_FS_IMAGE_FD, ENV_GUEST_ARGV,
    ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_GUEST_HOSTNAME, ENV_INITIAL_STACK, ENV_MODE,
    ENV_REALTIME_EPOCH_NANOS, ENV_SEED, ENV_STEP_BUDGET, ENV_TRACE_FD,
    NATIVE_INITIAL_STACK_TRAILER_SLOTS,
};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, native_binary_has_sud_marker,
    native_binary_has_tsc_marker, native_binary_is_shim_linked, native_deny_trap_armed,
    native_escape_is_sud_manageable, native_escape_is_tsc_manageable, render_compat_mode_note,
    render_cpu_nondeterminism_note, render_thread_pointer_note, render_tsc_managed_note,
    shim_control_plane_symbols,
};
use patina_dst_trace::{
    TraceBundle, TraceError, create_scratch, parse_abandoned_trace_marker, remove_dead_scratch,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::{env, fs, io};

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

/// An encoded filesystem image held open in a temporary file, ready to be
/// duplicated onto the guest's inherited image descriptor, plus its content
/// hash for the run fingerprint.
struct FsImageCapture {
    file: fs::File,
    hash: String,
}

/// Capture `host_dir` into a deterministic [`FsImage`], encode it, and write the
/// bytes to a rewound anonymous temporary file the child reads over its
/// inherited image descriptor. The supervisor runs uninterposed, so reading the
/// host tree here is sound; the guest only ever sees the rebuilt image.
fn build_fs_image_file(host_dir: &Path) -> Result<FsImageCapture, CliError> {
    use std::io::{Seek, SeekFrom, Write};

    let root = fs::canonicalize(host_dir).map_err(|error| {
        CliError(format!(
            "failed to resolve --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(CliError(format!(
            "--mount target is not a directory: {}",
            root.display()
        )));
    }
    let mut entries = Vec::new();
    collect_fs_entries(&root, "", &mut entries)?;
    let image = FsImage::new(entries);
    let bytes = image.encode();

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let mut file = tempfile::tempfile().map_err(|error| {
        CliError(format!(
            "failed to create filesystem image scratch file: {error}"
        ))
    })?;
    file.write_all(&bytes)
        .map_err(|error| CliError(format!("failed to write filesystem image: {error}")))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| CliError(format!("failed to rewind filesystem image: {error}")))?;
    Ok(FsImageCapture { file, hash })
}

/// Recursively collect `host_dir`'s contents as [`FsImageEntry`] values, mapping
/// the mount root to the guest root `/`. Symlinks are captured verbatim (their
/// target string, never followed), directories are recorded and descended, and
/// regular files carry their bytes. `FsImage::new` sorts the result, so the host
/// `readdir` order never leaks into the deterministic image.
fn collect_fs_entries(
    host_dir: &Path,
    guest_prefix: &str,
    entries: &mut Vec<FsImageEntry>,
) -> Result<(), CliError> {
    let listing = fs::read_dir(host_dir).map_err(|error| {
        CliError(format!(
            "failed to read --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    for entry in listing {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read entry under {}: {error}",
                host_dir.display()
            ))
        })?;
        let host_path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            CliError(format!(
                "--mount directory contains a non-UTF-8 name under {}",
                host_dir.display()
            ))
        })?;
        let guest_path = format!("{guest_prefix}/{name}");
        // Classify without following symlinks so a symlink stays a symlink in
        // the image, matching how a default recursive file-walk lstat's and skips it.
        let metadata = fs::symlink_metadata(&host_path).map_err(|error| {
            CliError(format!("failed to stat {}: {error}", host_path.display()))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&host_path)
                .map_err(|error| {
                    CliError(format!(
                        "failed to read symlink {}: {error}",
                        host_path.display()
                    ))
                })?
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    CliError(format!(
                        "symlink {} has a non-UTF-8 target",
                        host_path.display()
                    ))
                })?;
            entries.push(FsImageEntry::Symlink {
                path: guest_path,
                target,
            });
        } else if file_type.is_dir() {
            entries.push(FsImageEntry::Directory {
                path: guest_path.clone(),
            });
            collect_fs_entries(&host_path, &guest_path, entries)?;
        } else if file_type.is_file() {
            let contents = fs::read(&host_path).map_err(|error| {
                CliError(format!("failed to read {}: {error}", host_path.display()))
            })?;
            entries.push(FsImageEntry::File {
                path: guest_path,
                contents,
            });
        }
        // Anything else (sockets, devices, fifos) is skipped: a search corpus
        // has none, and the in-memory filesystem cannot model them.
    }
    Ok(())
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
pub(super) fn effective_native_allow(user_allow: &BTreeSet<String>) -> BTreeSet<String> {
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
pub(super) fn emit_native_deny_trap_note(bytes: &[u8]) {
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
pub(super) fn target_has_sud(target: &str) -> bool {
    target.starts_with("x86_64") && target.contains("linux")
}

fn native_prerun_gate(
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

/// The one sentence a run prints when its trace CHANNEL failed — the scratch
/// file could not be opened, read, or renamed. It is a fixed prefix on purpose:
/// the envelope's refusal table keys on it, so every generation that loses its
/// trace channel carries the same class and collapses onto ONE signature,
/// instead of one novel finding per scratch path. The `guest_exit_code=` that
/// follows is the status the guest itself reached, which stays the run's answer.
pub(crate) const TRACE_CHANNEL_UNAVAILABLE: &str = "patina: recorded trace channel unavailable";

/// Why a recorded trace never reached its final path.
enum TraceCommitFailure {
    /// The recorder deliberately abandoned the trace and left an
    /// abandoned-trace marker naming why (today: the run outgrew
    /// `MAX_TRACE_BYTES`). It writes that marker only from finalization, which
    /// runs after the guest has already exited, so the run's verdict is final
    /// and stands on its own — only the replay artifact is lost. The run is
    /// reported, not failed.
    Abandoned(String),
    /// The trace CHANNEL failed: the recorder's own scratch file could not be
    /// opened, read, or renamed — it vanished under the run, its directory did,
    /// or the filesystem refused. That is an operational condition of the host,
    /// exactly like a wall-clock timeout or an OOM kill, and it says nothing
    /// about the system under test: the guest ran, and its verdict is whatever
    /// it reached. Kept apart from [`Self::Broken`] because a truncated bundle
    /// left behind by a guest that DIED mid-record is a consequence of the run
    /// and must keep failing it.
    Unavailable(String),
    /// Anything else: an empty, truncated, or corrupt trace. Nothing said why
    /// the bundle is missing, so the run cannot be trusted and fails.
    Broken(String),
}

impl TraceCommitFailure {
    fn reason(&self) -> &str {
        match self {
            Self::Abandoned(reason) | Self::Broken(reason) | Self::Unavailable(reason) => reason,
        }
    }
}

struct NativeTraceSink {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<fs::File>,
}

impl NativeTraceSink {
    fn create(final_path: &Path) -> Result<Self, CliError> {
        if final_path.exists() && TraceBundle::load(final_path).is_err() {
            fs::remove_file(final_path).map_err(|error| {
                CliError(format!(
                    "failed to remove incomplete existing trace {} before recording: {error}",
                    final_path.display()
                ))
            })?;
        }
        if let Some(parent) = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                CliError(format!(
                    "failed to create trace directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        remove_dead_scratch(final_path);
        let (temp_path, file) = create_scratch(final_path).map_err(|error| {
            CliError(format!(
                "failed to create temporary trace beside {}: {error}",
                final_path.display()
            ))
        })?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            temp_path,
            file: Some(file),
        })
    }

    #[cfg(unix)]
    fn file(&self) -> &fs::File {
        self.file.as_ref().expect("trace sink is live until commit")
    }

    /// Write a trace the supervisor assembled itself (a crash-restart run's
    /// joined incarnations) into the channel a guest otherwise writes.
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        use std::io::Write;

        self.file
            .as_mut()
            .expect("trace sink is live until commit")
            .write_all(bytes)
            .map_err(|error| {
                CliError(format!(
                    "failed to write temporary trace {}: {error}",
                    self.temp_path.display()
                ))
            })
    }

    fn commit(mut self) -> Result<PathBuf, TraceCommitFailure> {
        // Held, and with it the scratch file's lock, until the rename is done.
        let _file = self.file.take();
        if let Err(error) = TraceBundle::load(&self.temp_path) {
            // Tell "the recorder gave up, and said so" apart from "the trace
            // is simply not there". Both leave no bundle at the temp path, but
            // only the first is accompanied by an abandoned-trace marker the
            // recorder wrote deliberately AFTER the guest had already finished.
            // A guest that died mid-run leaves an empty or truncated file and
            // no marker, and that must keep failing the run.
            let abandoned = fs::read(&self.temp_path)
                .ok()
                .and_then(|bytes| parse_abandoned_trace_marker(&bytes));
            let _ = fs::remove_file(&self.temp_path);
            return Err(match abandoned {
                Some(_) => TraceCommitFailure::Abandoned(error.to_string()),
                // The scratch file could not be OPENED at all — it is gone, or
                // its directory is. The guest still ran, so this is the channel
                // failing under the run rather than the run failing.
                None if matches!(error, TraceError::Io { .. }) => {
                    TraceCommitFailure::Unavailable(error.to_string())
                }
                None => TraceCommitFailure::Broken(error.to_string()),
            });
        }
        fs::rename(&self.temp_path, &self.final_path).map_err(|error| {
            let _ = fs::remove_file(&self.temp_path);
            TraceCommitFailure::Unavailable(format!(
                "failed to atomically rename temporary trace {} to {}: {error}",
                self.temp_path.display(),
                self.final_path.display()
            ))
        })?;
        Ok(self.final_path.clone())
    }
}

impl Drop for NativeTraceSink {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Record the downgraded-symbol caveat next to a recorded trace so a later
/// reader of the artifact sees that the run was not an unconditional
/// determinism claim.
fn write_unsupported_sidecar(trace: &Path, downgraded: &[NativeEscape]) -> Result<(), CliError> {
    if downgraded.is_empty() {
        return Ok(());
    }
    let sidecar = {
        let mut name = trace.as_os_str().to_owned();
        name.push(".unsupported-symbols");
        PathBuf::from(name)
    };
    let mut contents = String::from(
        "# This trace was recorded with --allow-unsupported-symbols. The symbols\n\
# below are NOT interposed by the deterministic runtime; the run's determinism\n\
# is qualified. Symbol (category), followed by provenance when recoverable:\n",
    );
    for escape in downgraded {
        contents.push_str(&format!("{}\n", native_escape_summary(escape)));
        push_native_escape_provenance_lines(&mut contents, escape, "  ");
    }
    fs::write(&sidecar, contents).map_err(|error| {
        CliError(format!(
            "failed to write unsupported-symbols sidecar {}: {error}",
            sidecar.display()
        ))
    })
}

/// Encode the guest program arguments (`argv[1..]`) as the JSON string array the
/// runtime records into the trace metadata. Recording requires UTF-8 arguments
/// (the trace bundle is UTF-8 JSON); a non-UTF-8 argument fails closed here,
/// before the guest runs, rather than corrupting the trace.
fn encode_guest_argv(program_args: &[OsString]) -> Result<String, CliError> {
    let mut argv = Vec::with_capacity(program_args.len());
    for argument in program_args {
        let text = argument.to_str().ok_or_else(|| {
            CliError(format!(
                "cannot record the guest argument {argument:?}: --record requires UTF-8 guest \
arguments so they round-trip through the trace metadata"
            ))
        })?;
        argv.push(text.to_owned());
    }
    serde_json::to_string(&argv)
        .map_err(|error| CliError(format!("failed to encode guest arguments: {error}")))
}

/// Reconcile the guest arguments for a replay against the trace's recorded argv.
///
/// The trace records the `argv[1..]` it ran with, so a bare replay (no `--`
/// section) reproduces them and the operator need not re-pass the arguments —
/// fixing the incident where a divergent default argv caused a confusing mid-run
/// operation mismatch. If a `--` section IS supplied it must match the recording
/// byte-for-byte, otherwise the replay is refused UPFRONT naming both the
/// recorded and the passed arguments (a parse-time error, never a mid-run
/// divergence). A trace recorded before argv capture carries no recorded argv, so
/// the arguments are taken from the command line exactly as before — no new error
/// for old traces.
fn reconcile_replay_argv(
    trace: &Path,
    bundle: &TraceBundle,
    passed: &[OsString],
) -> Result<Vec<OsString>, CliError> {
    let Some(recorded) = &bundle.metadata.guest_argv else {
        // Pre-argv trace: honor the historical contract (arguments from the
        // command line, and their absence behaves exactly as today).
        return Ok(passed.to_vec());
    };
    let recorded_os: Vec<OsString> = recorded.iter().map(OsString::from).collect();
    if passed.is_empty() || passed == recorded_os.as_slice() {
        Ok(recorded_os)
    } else {
        Err(CliError(format!(
            "replay guest-argument mismatch for {}: the trace recorded {recorded:?}, but the \
command line passed {passed:?} after `--`. Omit the `--` section to replay the recorded arguments, \
or pass them byte-for-byte identically.",
            trace.display()
        )))
    }
}

#[cfg(unix)]
struct InheritedFdGuard {
    saved: Vec<(i32, i32)>,
}

#[cfg(unix)]
impl InheritedFdGuard {
    fn clear_cloexec(fds: &[i32]) -> Result<Self, CliError> {
        let mut saved = Vec::with_capacity(fds.len());
        for &fd in fds {
            // SAFETY: `fd` is an open descriptor owned by the supervisor.
            let flags = unsafe { fcntl(fd, F_GETFD, 0) };
            if flags < 0 {
                return Err(CliError(format!(
                    "failed to inspect inherited descriptor {fd}: {}",
                    io::Error::last_os_error()
                )));
            }
            saved.push((fd, flags));
            if flags & FD_CLOEXEC != 0 {
                // SAFETY: `F_SETFD` only updates descriptor flags on this fd.
                if unsafe { fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
                    return Err(CliError(format!(
                        "failed to make descriptor {fd} inheritable: {}",
                        io::Error::last_os_error()
                    )));
                }
                let cleared = unsafe { fcntl(fd, F_GETFD, 0) };
                if cleared < 0 || cleared & FD_CLOEXEC != 0 {
                    return Err(CliError(format!(
                        "failed to clear close-on-exec for descriptor {fd}: {}",
                        if cleared < 0 {
                            io::Error::last_os_error().to_string()
                        } else {
                            format!("descriptor flags are still {cleared}")
                        }
                    )));
                }
            }
        }
        Ok(Self { saved })
    }

    fn restore(mut self) -> Result<(), CliError> {
        for (fd, flags) in self.saved.drain(..) {
            // SAFETY: Restore the exact descriptor flags saved before spawn.
            if unsafe { fcntl(fd, F_SETFD, flags) } < 0 {
                return Err(CliError(format!(
                    "failed to restore descriptor {fd} flags: {}",
                    io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for InheritedFdGuard {
    fn drop(&mut self) {
        for (fd, flags) in self.saved.drain(..) {
            // Best-effort cleanup for early returns. Callers use `restore()` on
            // the normal path so restore errors can be reported explicitly.
            let _ = unsafe { fcntl(fd, F_SETFD, flags) };
        }
    }
}

#[cfg(unix)]
fn spawn_native_child(
    command: &mut Command,
    binary: &Path,
    inherited_fds: &[i32],
) -> Result<(std::process::Child, InheritedFdGuard), CliError> {
    // Return the guard to the caller instead of restoring immediately: the
    // descriptor-inheritance contract is simple and conservative if the fds stay
    // inheritable for the whole child lifetime, and this supervisor process does
    // not spawn unrelated children while waiting for the guest.
    let guard = InheritedFdGuard::clear_cloexec(inherited_fds)?;
    let child = command.spawn().map_err(|error| {
        CliError(format!(
            "failed to run native program {}: {error}",
            binary.display()
        ))
    })?;
    Ok((child, guard))
}

#[cfg(unix)]
pub(super) struct NativeChildStatus {
    pub(super) exit_code: i32,
    pub(super) signal: Option<i32>,
    pub(super) core: bool,
}

#[cfg(unix)]
pub(super) fn native_child_status(status: ExitStatus) -> NativeChildStatus {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        NativeChildStatus {
            exit_code: code,
            signal: None,
            core: false,
        }
    } else if let Some(signal) = status.signal() {
        NativeChildStatus {
            exit_code: 128 + signal,
            signal: Some(signal),
            core: status.core_dumped(),
        }
    } else {
        NativeChildStatus {
            exit_code: 2,
            signal: None,
            core: false,
        }
    }
}

pub(super) const NATIVE_FS_CRASH_RESTART_EXIT: i32 = 112;

#[cfg(unix)]
fn wait_native_child_once(
    command: &mut Command,
    binary: &Path,
    inherited_fds: &[i32],
) -> Result<(output::Captured, u32), CliError> {
    if output::capture_active() {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let (child, inherited_guard) = spawn_native_child(command, binary, inherited_fds)?;
        let host_pid = child.id();
        let output = child.wait_with_output().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let NativeChildStatus {
            exit_code,
            signal,
            core,
        } = native_child_status(output.status);
        Ok((
            output::Captured {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
                captured: true,
                signal,
                core,
            },
            host_pid,
        ))
    } else {
        let (mut child, inherited_guard) = spawn_native_child(command, binary, inherited_fds)?;
        let host_pid = child.id();
        let status = child.wait().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let NativeChildStatus {
            exit_code,
            signal,
            core,
        } = native_child_status(status);
        Ok((
            output::Captured {
                exit_code,
                stdout: Vec::new(),
                stderr: Vec::new(),
                captured: false,
                signal,
                core,
            },
            host_pid,
        ))
    }
}

#[cfg(unix)]
pub(super) fn execute_native_run(invocation: NativeRunInvocation) -> Result<i32, CliError> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    // Source-first: an artifact runs as-is; a source/package is built on the fly
    // first (`resolved` holds the build workspace alive for the whole run). For
    // replay, the rebuilt binary is judged against the trace by the fingerprint
    // and operation-mismatch machinery below — no special-casing.
    let resolved = resolve_artifact(invocation.binary.clone())?;
    let binary = fs::canonicalize(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to resolve native program {}: {error}",
            resolved.path.display()
        ))
    })?;

    // Pre-run default-deny gate. Before the guest executes, enumerate every
    // externally-resolved symbol it can reach and hard-error, listing names, if
    // any on the blocking/time/scheduling/effect surface is neither interposed
    // nor known-safe. This is what makes a missed interposer (the class the
    // macOS dispatch-semaphore Parker escape belonged to) structurally
    // impossible to run silently: an unmodeled blocking symbol is an import the
    // shim does not define, so it surfaces here as a denial rather than blocking
    // a host thread outside the scheduler. `--allow-unsupported-symbols`
    // downgrades matching denials to a loud warning for programs that carry
    // unsupported surface the scenario never reaches.
    let downgraded =
        match native_prerun_gate(&binary, &invocation.allow, &invocation.allow_unsupported) {
            Ok(downgraded) => downgraded,
            Err(error) if output::facts_active() => {
                output::emit_native_prerun_refusal(&binary, error.to_string());
                return Ok(2);
            }
            Err(error) => return Err(error),
        };

    // A binary built with `--yield-points` schedules under a different (denser)
    // policy, so its recorded traces must not cross-replay with a plain binary.
    // Detect the linked hook's marker and fold it into the compatibility
    // fingerprint; the same binary is inspected on record and replay, so the
    // suffix is applied consistently and a policy mismatch is rejected.
    let instrumentation = binary_instrumentation(&binary)?;
    if invocation.coverage_out.is_some() && !instrumentation.has_coverage() {
        return Err(CliError::usage(
            "--coverage-out requires a native binary built with `cargo patina build --yield-points` or `--coverage-points`; coverage rides the SanitizerCoverage edge counters",
        ));
    }

    // Starvation intervals reorder real thread execution adversarially. A guest
    // whose synchronization is INTERPOSED (mutex/condvar/futex) is always safe —
    // every wait is a scheduling boundary the aging guarantee can act on. But a
    // guest with an *invisible atomic spinlock* (e.g. std's queue `RwLock`/`Parker`
    // fast path) held across an interposed boundary can wedge: the adversarial
    // deferral schedules the spinner while the lock holder is starved, and the
    // spinner's atomics-only loop offers no boundary for aging to force the holder
    // — the exact cooperative-scheduling limitation the vacuous-schedule warning
    // flags. `--yield-points` closes it (loop backedges become boundaries), so
    // starvation there is always liveness-safe; `--coverage-points=N` closes it
    // too, one boundary every N basic blocks, which bounds the aging delay by N
    // blocks rather than eliminating it. Warn loudly when starvation is enabled
    // on a binary with neither rather than risk a silent hang.
    if invocation.schedule.starve.is_some() && !instrumentation.preempts_inside_atomics() {
        eprintln!(
            "PATINA WARNING: starvation intervals (--starve) are enabled on a binary built \
WITHOUT a mode that makes an atomics-only window schedulable (`--yield-points`, or \
`--coverage-points=N`). Starvation is liveness-safe for guests whose synchronization is \
interposed (mutex/condvar/futex), but a guest with an invisible atomic spinlock (e.g. std's queue \
RwLock/Parker fast path) held across a boundary can WEDGE under adversarial deferral — the same \
atomics-only window the vacuous-schedule diagnostic flags as unreachable. Rebuild with \
`cargo patina build --yield-points` (a boundary at every basic block) or `--coverage-points=N` \
(one every N basic blocks, far cheaper) to make those windows schedulable so starvation stays \
liveness-safe."
        );
    }

    // Capture the mounted host directory into a deterministic filesystem image.
    // The supervisor is not interposed, so it may read the host tree freely; the
    // encoded image travels to the guest over an inherited descriptor and the
    // shim rebuilds it, so the fully interposed guest never touches the host
    // filesystem. The image hash folds into the fingerprint below so a replay
    // against a different corpus is rejected exactly like any incompatibility.
    let image_file = match &invocation.mount {
        Some(host_dir) => Some(build_fs_image_file(host_dir)?),
        None => None,
    };
    let image_hash = image_file.as_ref().map(|image| image.hash.clone());
    let coverage_file = match &invocation.coverage_out {
        Some(path) => Some(fs::File::create(path).map_err(|error| {
            CliError(format!(
                "failed to create coverage map {}: {error}",
                path.display()
            ))
        })?),
        None => None,
    };
    // The structured run-facts channel. A native guest is FULLY interposed, so
    // the document cannot travel over a path — it rides an inherited host
    // descriptor the shim writes through its private host aliases, exactly like
    // the trace bundle and the coverage map.
    let facts_file = if output::facts_active() {
        Some(tempfile::tempfile().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };

    // A replay reads its trace once: the guest arguments, the fingerprint
    // components and the crash-restart plan all come from this one load.
    let replay_trace = match &invocation.mode {
        NativeRunMode::Replay { path, .. } => Some(TraceBundle::load(path).map_err(|error| {
            CliError(format!("failed to read trace {}: {error}", path.display()))
        })?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => None,
    };

    // Restore the guest arguments for a replay from the trace's recorded argv, so
    // a bare replay reproduces them without the `--` section being re-passed; a
    // mismatched `--` section is refused upfront (see `reconcile_replay_argv`).
    // For seeded/record runs the arguments are the ones supplied on the command
    // line, unchanged.
    let program_args = match (&invocation.mode, &replay_trace) {
        (NativeRunMode::Replay { path, .. }, Some(bundle)) => {
            reconcile_replay_argv(path, bundle, &invocation.program_args)?
        }
        _ => invocation.program_args.clone(),
    };

    // What a record or replay tells the guest about its mode, identical for
    // every incarnation of the run.
    let mode_env: Vec<(&str, String)> = match &invocation.mode {
        NativeRunMode::Seeded { seed } => {
            vec![(ENV_MODE, "seeded".into()), (ENV_SEED, seed.to_string())]
        }
        NativeRunMode::Record {
            seed, fingerprint, ..
        } => vec![
            (ENV_MODE, "record".into()),
            (ENV_SEED, seed.to_string()),
            (
                ENV_FINGERPRINT,
                native_run_fingerprint(
                    fingerprint,
                    instrumentation,
                    image_hash.as_deref(),
                    invocation.buggify.is_some(),
                    &SchedulePolicyFingerprint::from_schedule(&invocation.schedule),
                ),
            ),
            // Record the guest arguments into the trace metadata so a later
            // `replay` restores them without the `--` section being re-passed.
            // Always forwarded (even when empty) so a zero-argument run records
            // `[]` — distinct from an old trace's absent field, so replaying it
            // reproduces zero arguments rather than inheriting whatever the
            // command line supplies.
            (ENV_GUEST_ARGV, encode_guest_argv(&program_args)?),
        ],
        NativeRunMode::Replay { fingerprint, .. } => {
            // Reconstruct the `+buggify` and `+pct`/`+starve`/`+swarm`
            // fingerprint components from the trace so replay is self-contained;
            // a policy trace replayed against a plain build still fails closed on
            // the fingerprint.
            let bundle = replay_trace
                .as_ref()
                .expect("a native replay loads its trace first");
            let buggify = invocation.buggify.is_some() || trace_has_buggify(bundle);
            let policy = native_policy_from_trace(bundle);
            vec![
                (ENV_MODE, "replay".into()),
                // Startup effects (notably AT_RANDOM) happen before the shim
                // can read the trace. They need the same seed as the runtime.
                (ENV_SEED, bundle.metadata.root_seed.to_string()),
                (
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        instrumentation,
                        image_hash.as_deref(),
                        buggify,
                        &policy,
                    ),
                ),
            ]
        }
    };

    // The shim publishes the deterministic map into the ORIGINAL stack envp.
    // Reserve room for its entries plus a disjoint copy of the platform trailer
    // (ELF auxv / Darwin apple vector); libc/dyld keep the original trailer.
    // Replay restores its map from metadata, not the normally empty CLI map.
    // A deferred harness starts empty and later replaces environ at installation.
    let startup_env_entries = if invocation.harness {
        0
    } else if let Some(bundle) = &replay_trace {
        bundle.metadata.guest_env.as_ref().map_or(0, BTreeMap::len)
    } else {
        invocation.environment.len()
    };

    let crash_restart_plan = crash_restart_plan(&invocation, replay_trace)?;
    if crash_restart_plan.is_some() && invocation.schedule.starve.is_some() {
        return Err(CliError::usage(
            "native --fs-crash-at crash-restart with --starve is not implemented; refusing rather than mixing the restart supervisor with the starvation stall backstop",
        ));
    }

    // Every incarnation of the run is launched from this one description; only
    // its descriptors (trace channel, base filesystem, crash handoff) differ. A
    // run without a crash selector is the single incarnation 0. Returns the
    // command and the descriptors it inherits: the shim reads only the ones the
    // control plane names, and they stay inheritable for the child's lifetime.
    let incarnation_command = |launch: IncarnationLaunch<'_>| -> Result<
        (Command, Vec<std::os::unix::io::RawFd>),
        CliError,
    > {
        let mut command = Command::new(&binary);
        let mut fds = Vec::new();
        // Stamp a fixed, machine-independent `argv[0]`: the guest is exec'd from
        // an absolute host path, but that path must not leak into the guest's
        // `std::env::args()` as a non-portable string. The guest's own arguments
        // live in `argv[1..]`.
        command
            .args(&program_args)
            .arg0(NATIVE_GUEST_ARGV0)
            .env_clear();
        // These inert entries cannot configure the loader (unlike baking the
        // guest's real names, e.g. LD_PRELOAD, into exec's environment). The
        // shim checks actual trailer size before writing, failing closed if a
        // future platform needs more than this reservation. Padding is not
        // control-plane state and is never snapshotted or exposed to the guest.
        command.env(ENV_INITIAL_STACK, "1");
        for slot in 0..startup_env_entries + NATIVE_INITIAL_STACK_TRAILER_SLOTS {
            command.env(format!("_PATINA_ENVP_SLOT_{slot}"), "");
        }
        // A `patina-dst-harness` binary (usage mode 2) defers runtime
        // installation to its `run`/`run_with` call: tell the packaged
        // constructor to capture/scrub the control plane and register
        // finalization but NOT install the runtime. Applies uniformly to
        // seeded/record and replay so the harness owns installation on every
        // path. An interposed effect before the harness installs fails closed.
        if invocation.harness {
            command.env(ENV_DEFER_INIT, "1");
        }
        if let Some(file) = &coverage_file {
            command.env(ENV_COVERAGE_FD, file.as_raw_fd().to_string());
            fds.push(file.as_raw_fd());
        }
        if let Some(file) = &facts_file {
            command.env(
                patina_dst_runtime::ENV_FACTS_FD,
                file.as_raw_fd().to_string(),
            );
            fds.push(file.as_raw_fd());
        }
        // The guest's environment is cleared above, so every end-of-run report
        // knob the operator set has to be forwarded explicitly or it never
        // reaches the guest at all. Driven by `Report::ALL` rather than a
        // hand-kept list, so a report added to the runtime is silenceable on
        // native the day it exists.
        if let Some(value) = env::var_os("PATINA_COMPUTE_WATCHDOG_MS") {
            command.env("PATINA_COMPUTE_WATCHDOG_MS", value);
        }
        for report in patina_dst_runtime::Report::ALL {
            if let Some(value) = env::var_os(report.env()) {
                command.env(report.env(), value);
            }
        }
        if !invocation.environment.is_empty() {
            let encoded = serde_json::to_string(&invocation.environment).map_err(|error| {
                CliError(format!(
                    "failed to encode native guest environment: {error}"
                ))
            })?;
            command.env(ENV_GUEST_ENV, encoded);
        }
        if let Some(cwd) = &invocation.cwd {
            command.env(ENV_GUEST_CWD, cwd);
        }
        if let Some(nanos) = invocation.realtime_epoch_nanos {
            command.env(ENV_REALTIME_EPOCH_NANOS, nanos.to_string());
        }
        if let Some(hostname) = &invocation.hostname {
            command.env(ENV_GUEST_HOSTNAME, hostname);
        }
        // The boundary-operation budget is a supervisor-side bound, not recorded
        // run semantics, so it is supplied per invocation on every family alike.
        if let Some(budget) = invocation.step_budget {
            command.env(ENV_STEP_BUDGET, budget.to_string());
        }
        // Forward whatever fault knobs the operator supplied to the guest,
        // scrubbing every knob's variable first so an ambient value cannot leak
        // into a run that set none. On record and seeded runs these configure
        // the faults and are recorded into the trace metadata. Native replay
        // does not accept semantic re-supply; the trace's recorded configuration
        // is authoritative and restored by the runtime.
        for variable in knob_env_vars() {
            command.env_remove(variable);
        }
        for (name, value) in knob_env_pairs(&invocation.knobs)? {
            command.env(name, value);
        }
        // Forward the cooperative-SUT (buggify) knobs. Presence of
        // `PATINA_BUGGIFY` enables buggify; its value (if any) is the firing
        // per-mille. Like the fault knobs, these are recorded into trace metadata
        // and restored from the trace on native replay, rather than re-supplied
        // as semantic flags.
        if let Some(buggify) = &invocation.buggify {
            command.env(ENV_BUGGIFY, buggify.fire_permille.as_deref().unwrap_or(""));
            if let Some(value) = &buggify.activation_permille {
                command.env(ENV_BUGGIFY_ACTIVATION, value);
            }
            if let Some(value) = &buggify.cutoff_nanos {
                command.env(ENV_BUGGIFY_CUTOFF, value);
            }
            if buggify.after_setup {
                command.env(ENV_BUGGIFY_AFTER_SETUP, "1");
            }
        }
        // Forward the exploration scheduling-policy (PCT / starvation) and swarm
        // knobs through the same control plane. Recorded into the trace metadata
        // and restored from the trace on native replay; the fingerprint suffix
        // rejects a cross-policy replay.
        for (name, value) in schedule_env_pairs(&invocation.schedule) {
            command.env(name, value);
        }
        // Forward the liveness-watchdog knobs through the same control plane. The
        // watchdog is schedule-invariant: recorded (informational) but not
        // fingerprinted, so a watchdog trace replays against any build.
        for (name, value) in liveness_env_pairs(&invocation.liveness) {
            command.env(name, value);
        }
        for (name, value) in &mode_env {
            command.env(name, value);
        }
        command.env(
            patina_dst_runtime::ENV_INCARNATION,
            launch.incarnation.to_string(),
        );
        if let Some(file) = launch.trace {
            command.env(ENV_TRACE_FD, file.as_raw_fd().to_string());
            fds.push(file.as_raw_fd());
        }
        if let Some((file, key)) = launch.handoff {
            command
                .env(
                    patina_dst_runtime::ENV_HANDOFF_FD,
                    file.as_raw_fd().to_string(),
                )
                .env(patina_dst_runtime::ENV_HANDOFF_KEY, key);
            fds.push(file.as_raw_fd());
        }
        // A restarted incarnation boots from the recovered filesystem instead of
        // the run's base image.
        match (launch.restart_snapshot, &image_file) {
            (Some(file), _) => {
                command.env(
                    patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD,
                    file.as_raw_fd().to_string(),
                );
                fds.push(file.as_raw_fd());
            }
            (None, Some(image)) => {
                command.env(ENV_FS_IMAGE_FD, image.file.as_raw_fd().to_string());
                fds.push(image.file.as_raw_fd());
            }
            (None, None) => {}
        }
        Ok((command, fds))
    };

    // Record mode writes to a sibling temporary file first; the supervisor
    // validates and renames it to the requested path only after the run ends.
    let mut trace_sink = match &invocation.mode {
        NativeRunMode::Record { path, .. } => Some(NativeTraceSink::create(path)?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => None,
    };

    let mut crash_restart = None;
    let mut captured = if let Some(plan) = &crash_restart_plan {
        let run = supervise_crash_restart(plan, |launch| {
            let (mut command, fds) = incarnation_command(launch)?;
            wait_native_child_once(&mut command, &binary, &fds)
        })?;
        if let (Some(sink), Some(bytes)) = (trace_sink.as_mut(), &run.trace) {
            sink.write_all(bytes)?;
        }
        crash_restart = Some(run.report);
        run.captured
    } else {
        // Hold the trace channel open until the child exits so the inherited
        // descriptor named by `PATINA_TRACE_FD` stays valid.
        let replay_trace_file = match &invocation.mode {
            NativeRunMode::Replay { path, .. } => Some(fs::File::open(path).map_err(|error| {
                CliError(format!("failed to open trace {}: {error}", path.display()))
            })?),
            NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => None,
        };
        let trace = trace_sink
            .as_ref()
            .map(NativeTraceSink::file)
            .or(replay_trace_file.as_ref());
        let (mut command, inherited_fds) = incarnation_command(IncarnationLaunch {
            incarnation: 0,
            trace,
            handoff: None,
            restart_snapshot: None,
        })?;
        // Starvation stall backstop (diagnostic, NOT a liveness guarantee; armed only
        // when starvation is enabled, so it has zero effect on any other mode). The
        // scheduler's aging bounds starvation for interposed synchronization, but a
        // guest spinning inside a std-internal atomic critical section — which is NOT
        // yield-point instrumented, so cooperative scheduling has no edge to preempt
        // it while the lock holder is starved — can livelock. A hung generation
        // silently eats a sweep slot, so the supervisor (uninterposed, real
        // wall-clock) converts an already-hung run into a LOUD named fatal with a
        // distinct nonzero exit so sweeps classify STARVATION_STALL instead of
        // hanging. The threshold is deliberately generous (default 60 real seconds,
        // `PATINA_STARVATION_STALL_SECS` override) so a healthy run normally finishes
        // far inside it — a 10,000-iteration `turso_stress` generation takes about
        // 30 s — though a busy enough host can still cross it; it never touches the
        // recorded operation stream of a run that completes.
        // It is an ELAPSED-TIME deadline, not a progress detector: the supervisor
        // cannot see the scheduler's decision counter, so it cannot separate a wedge
        // from a run that is merely slower than the deadline. That is exactly why a
        // campaign files exit 111 under a class that is NOT counted as a bug found
        // (`CampaignClass::is_finding`), and why the counter is the signal to publish
        // if the two ever need telling apart from the outside.
        if invocation.schedule.starve.is_some() {
            let stall_secs: u64 = std::env::var("PATINA_STARVATION_STALL_SECS")
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(60);
            let capture = output::capture_active();
            if capture {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            let (mut child, inherited_guard) =
                spawn_native_child(&mut command, &binary, &inherited_fds)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(stall_secs);
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => break,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            eprintln!(
                                "patina: starvation stall — the run did not finish within {stall_secs}s \
    under --starve. What this backstop measures is elapsed wall clock, not scheduler progress: the \
    supervisor cannot see the decision counter, so it cannot tell a guest spinning inside an \
    uninstrumented atomic critical section (std carries no yield point, so cooperative scheduling \
    cannot preempt a spinner while the lock holder is starved — the documented starvation limitation, \
    and the likely cause) from a run that is merely slower than this deadline. Not a liveness \
    guarantee, and not a verdict on the guest — see IMPLEMENTATION.md \"Slice 7: exploration tier\". \
    Killed with a nonzero exit."
                            );
                            inherited_guard.restore()?;
                            drop(trace_sink);
                            drop(replay_trace_file);
                            drop(image_file);
                            drop(coverage_file);
                            drop(facts_file);
                            return Ok(STARVATION_STALL_EXIT);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(error) => {
                        return Err(CliError(format!(
                            "failed while waiting on native program {}: {error}",
                            binary.display()
                        )));
                    }
                }
            }
            let output = child.wait_with_output().map_err(|error| {
                CliError(format!(
                    "failed while waiting on native program {}: {error}",
                    binary.display()
                ))
            })?;
            inherited_guard.restore()?;
            let NativeChildStatus {
                exit_code,
                signal,
                core,
            } = native_child_status(output.status);
            output::Captured {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
                captured: capture,
                signal,
                core,
            }
        } else {
            wait_native_child_once(&mut command, &binary, &inherited_fds)?.0
        }
    };
    let mut committed_record_trace = None;
    let mut trace_finalization_error: Option<(PathBuf, String)> = None;
    let mut channel_unavailable: Option<i32> = None;
    if let Some(sink) = trace_sink {
        match sink.commit() {
            Ok(path) => {
                if let Err(error) = write_unsupported_sidecar(&path, &downgraded) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                committed_record_trace = Some(path);
            }
            Err(failure) => {
                let path = match &invocation.mode {
                    NativeRunMode::Record { path, .. } => path.clone(),
                    NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => PathBuf::new(),
                };
                // A trace that is missing for an unexplained reason fails the
                // run: a clean exit code alongside no bundle would report a
                // recording that does not exist. A trace the recorder
                // deliberately abandoned after the guest finished is different
                // in kind — the guest's own status is the run's answer, and
                // overriding it here would manufacture a failure out of a
                // completed run (and bury the real status of one that failed
                // for a genuine reason). Either way the `PATINA_INFRA
                // trace=incomplete` marker below says the artifact is missing
                // and why, so nothing is silent.
                if matches!(
                    failure,
                    TraceCommitFailure::Broken(_) | TraceCommitFailure::Unavailable(_)
                ) && captured.exit_code == 0
                {
                    // The guest's own status is preserved for the classifier on
                    // the `guest_exit_code=` of the channel line below; this
                    // status is patina's, and says the artifact is missing.
                    channel_unavailable =
                        matches!(failure, TraceCommitFailure::Unavailable(_)).then_some(0);
                    captured.exit_code = 2;
                } else if matches!(failure, TraceCommitFailure::Unavailable(_)) {
                    channel_unavailable = Some(captured.exit_code);
                }
                trace_finalization_error = Some((path, failure.reason().to_string()));
            }
        }
    }
    let native_signal = captured.signal;
    append_native_infra_marker(
        &mut captured,
        native_signal,
        trace_finalization_error
            .as_ref()
            .map(|(path, reason)| (path.as_path(), reason.as_str())),
        channel_unavailable,
    );
    drop(image_file);
    drop(coverage_file);
    // Read the facts document back off the inherited descriptor. The child wrote
    // through the same open file description, so the offset is at the end —
    // rewind before reading.
    let facts = match facts_file {
        Some(mut file) => {
            use std::io::{Read, Seek};
            file.rewind().map_err(|error| {
                CliError(format!("failed to rewind the run-facts channel: {error}"))
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                CliError(format!("failed to read the run-facts channel: {error}"))
            })?;
            output::parse_facts(&bytes)?
        }
        None => None,
    };
    let coverage = if let Some(path) = &invocation.coverage_out {
        let len = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if captured.exit_code == 0 || len > 0 {
            Some(coverage::coverage_summary_from_map(path)?)
        } else {
            None
        }
    } else {
        None
    };
    let (trace_path, seed) = match &invocation.mode {
        NativeRunMode::Seeded { seed } => (None, Some(*seed)),
        NativeRunMode::Record { seed, .. } => (committed_record_trace.clone(), Some(*seed)),
        NativeRunMode::Replay { path, .. } => (Some(path.clone()), None),
    };
    let fingerprint = match &invocation.mode {
        NativeRunMode::Seeded { .. } => None,
        NativeRunMode::Record { fingerprint, .. } | NativeRunMode::Replay { fingerprint, .. } => {
            Some(fingerprint.clone())
        }
    };
    let artifact = resolved.display.display().to_string();
    let exit = output::finalize_run(
        output::RunReport {
            verb: "run",
            family: "native",
            artifact: &artifact,
            trace_path,
            timeline: "main",
            fingerprint,
            seed,
            coverage: coverage.clone(),
            depth: None,
            crash_restart,
            facts,
        },
        captured,
    )?;
    if let Some(coverage) = coverage {
        if !output::options().is_json() {
            if let Some(path) = coverage.map_path {
                eprintln!(
                    "PATINA_COVERAGE map={} edges={}/{} covered_permille={}",
                    path.display(),
                    coverage.edges_covered,
                    coverage.edges_total,
                    coverage.covered_permille,
                );
            }
        }
    }
    Ok(exit)
}

/// Distinct exit code the supervisor returns when the starvation stall backstop
/// kills a hung `--starve` run, so a sweep can classify `STARVATION_STALL` rather
/// than treat the run as an ordinary crash.
pub(super) const STARVATION_STALL_EXIT: i32 = 111;

#[cfg(not(unix))]
pub(super) fn execute_native_run(_invocation: NativeRunInvocation) -> Result<i32, CliError> {
    Err(CliError(
        "native-run requires a Unix host for the PATINA_TRACE_FD supervisor channel".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnsupportedPolicy;
    use patina_dst_target::NativeEscape;

    use std::fs;

    use patina_dst_trace::remove_dead_scratch;

    /// A trace whose scratch file is GONE at commit — it was swept out from
    /// under the run, or its directory was — is the artifact channel failing,
    /// not the run failing. It is reported as its own kind so the campaign can
    /// file it as INFRA under one shared shape, while a trace that is present
    /// but empty (what a guest that died mid-record leaves) stays Broken and
    /// keeps failing the run.
    #[cfg(unix)]
    #[test]
    fn a_vanished_scratch_file_is_a_channel_failure_not_a_broken_trace() {
        let directory = tempfile::tempdir().unwrap();

        let final_path = directory.path().join("vanished.patina");
        let sink = NativeTraceSink::create(&final_path).unwrap();
        fs::remove_file(&sink.temp_path).unwrap();
        let failure = sink.commit().unwrap_err();
        assert!(
            matches!(failure, TraceCommitFailure::Unavailable(_)),
            "a vanished scratch file is a channel failure; got {}",
            failure.reason()
        );

        // RED twin: the file is there and simply holds no bundle. That is the
        // run's own doing and must stay a failure.
        let final_path = directory.path().join("empty.patina");
        let sink = NativeTraceSink::create(&final_path).unwrap();
        assert!(matches!(
            sink.commit().unwrap_err(),
            TraceCommitFailure::Broken(_)
        ));
    }

    /// The scratch sweep clears what a DEAD recorder left behind and nothing
    /// else. A file a recorder still holds belongs to a live run — two
    /// campaigns sharing an out-dir is how that happens — and deleting it
    /// destroys that run's trace, surfacing much later as an unexplained
    /// missing artifact. Liveness is the recorder's lock on its file, never its
    /// pid: a pid is reused, and one in another pid namespace or owned by
    /// another user reads as dead to `kill(pid, 0)`.
    #[cfg(unix)]
    #[test]
    fn the_scratch_sweep_spares_a_live_recorders_file() {
        let directory = tempfile::tempdir().unwrap();
        let trace_path = directory.path().join("generation-7.patina");

        let live = NativeTraceSink::create(&trace_path).unwrap();
        let stale = directory.path().join(".generation-7.patina.tmp.1.0");
        let other_generation = directory.path().join(".generation-70.patina.tmp.1.0");
        for path in [&stale, &other_generation] {
            fs::write(path, b"x").unwrap();
        }

        remove_dead_scratch(&trace_path);
        assert!(
            live.temp_path.exists(),
            "a live recorder's scratch must be spared"
        );
        assert!(!stale.exists(), "a dead recorder's scratch must be swept");
        assert!(
            other_generation.exists(),
            "another generation's scratch is not this one's to sweep"
        );
    }

    /// The supervisor's half of the recorder-budget fix. A trace that never
    /// landed fails the run — EXCEPT when the recorder left an abandoned-trace
    /// marker saying it gave up after the guest had already finished, in which
    /// case the guest's own status is the run's answer. Both cases still remove
    /// the scratch file, so nothing unreplayable is left behind for a later
    /// `replay` to trip over.
    #[cfg(unix)]
    #[test]
    fn an_abandoned_trace_is_reported_while_a_missing_one_fails() {
        use patina_dst_trace::abandoned_trace_marker;
        use std::io::Write;

        let directory = tempfile::tempdir().unwrap();

        let final_path = directory.path().join("abandoned.patina");
        let mut sink = NativeTraceSink::create(&final_path).unwrap();
        let temp_path = sink.temp_path.clone();
        sink.file
            .as_mut()
            .unwrap()
            .write_all(&abandoned_trace_marker(
                "resource-limit",
                "serialized trace is 999 bytes; limit is 100",
            ))
            .unwrap();
        let failure = sink.commit().unwrap_err();
        assert!(
            matches!(failure, TraceCommitFailure::Abandoned(_)),
            "a marker must classify as abandoned; got {}",
            failure.reason()
        );
        assert!(
            failure.reason().contains("abandoned this trace")
                && failure.reason().contains("resource-limit"),
            "the reported reason must name what happened; got {}",
            failure.reason()
        );
        assert!(!temp_path.exists() && !final_path.exists());

        // An empty trace is what a guest that died mid-run leaves: nothing said
        // why, so it stays a failure.
        let final_path = directory.path().join("empty.patina");
        let sink = NativeTraceSink::create(&final_path).unwrap();
        let temp_path = sink.temp_path.clone();
        let failure = sink.commit().unwrap_err();
        assert!(
            matches!(failure, TraceCommitFailure::Broken(_)),
            "an unexplained empty trace must stay a failure; got {}",
            failure.reason()
        );
        assert!(!temp_path.exists() && !final_path.exists());
    }

    /// `--allow-unsupported-symbols NAME` against an instruction-class finding:
    /// its own name (`instruction@.text+OFF`) moves on every relink, so the
    /// CONTAINING symbol its provenance names matches too — scoped to that one
    /// function, never `all`. A symbol finding keeps matching only by its own
    /// (stable) name; a crate name is not a symbol.
    #[cfg(unix)]
    #[test]
    fn unsupported_only_matches_an_instruction_finding_by_its_containing_symbol() {
        use patina_dst_target::NativeProvenance;

        let provenance = |containing: Option<&str>| NativeProvenance {
            object: "unknown".into(),
            crate_name: Some("simd".into()),
            containing_symbol: containing.map(str::to_string),
            section: Some(".text".into()),
        };
        let instruction = NativeEscape {
            symbol: "instruction@.text+0x1f40".into(),
            category: "cpu-nondeterminism",
            provenance: vec![provenance(Some("simd::kernel::avx512_sum"))],
            mnemonic: None,
        };
        let only = |names: &[&str]| {
            UnsupportedPolicy::Only(names.iter().map(|name| name.to_string()).collect())
        };
        assert!(policy_downgrades(
            &only(&["simd::kernel::avx512_sum"]),
            &instruction
        ));
        assert!(policy_downgrades(
            &only(&["instruction@.text+0x1f40"]),
            &instruction
        ));
        assert!(!policy_downgrades(
            &only(&["simd::kernel::other"]),
            &instruction
        ));
        assert!(!policy_downgrades(&only(&["simd"]), &instruction));
        let unattributed = NativeEscape {
            provenance: vec![provenance(None)],
            ..instruction.clone()
        };
        assert!(!policy_downgrades(
            &only(&["simd::kernel::avx512_sum"]),
            &unattributed
        ));
        let symbol = NativeEscape {
            symbol: "rdtsc_helper".into(),
            ..instruction.clone()
        };
        assert!(!policy_downgrades(
            &only(&["simd::kernel::avx512_sum"]),
            &symbol
        ));
        assert!(policy_downgrades(&only(&["rdtsc_helper"]), &symbol));
        assert!(policy_downgrades(&UnsupportedPolicy::All, &instruction));
        assert!(!policy_downgrades(&UnsupportedPolicy::Deny, &instruction));
    }
}
