//! Native audits and escape diagnostics.

use crate::native_build::resolve_artifact;
use crate::native_run::{effective_native_allow, emit_native_deny_trap_note};
use crate::{ArtifactRef, CliError, NativeAuditInvocation, output};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, native_binary_has_sud_marker,
    native_binary_has_tsc_marker, native_binary_is_shim_linked, native_escape_is_sud_manageable,
    native_escape_is_tsc_manageable, native_host_identity_sites, render_compat_mode_note,
    render_host_identity_note, render_inert_weak_imports, render_native_escapes_grouped,
    render_thread_pointer_note,
};
use std::fs;
use std::path::Path;

pub(super) fn execute_native_audit(invocation: NativeAuditInvocation) -> Result<i32, CliError> {
    // A build-on-the-fly artifact is always shim-linked (it comes through the
    // same pipeline `build` uses), so the shim-linked gate only concerns a
    // prebuilt binary the caller handed us.
    let was_prebuilt = matches!(invocation.binary, ArtifactRef::Prebuilt(_));
    let resolved = resolve_artifact(invocation.binary)?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read native binary {}: {error}",
            resolved.path.display()
        ))
    })?;
    // Fail closed on a prebuilt binary that was not built with `cargo patina
    // build`: its import table lists the unsatisfied libc calls the shim would
    // interpose once linked (`open`, `clock_gettime`, `pthread_mutex_*`, ...),
    // not the true post-interposition residual. Auditing it raw reports ~the
    // whole libc surface as "unsupported", the exact opposite of the truth. The
    // audit is only meaningful against a shim-linked artifact, so steer to
    // source-first (which links the shim before auditing) or a Patina-built
    // binary — with `--raw` as the explicit escape hatch.
    let shim_linked = if was_prebuilt {
        native_binary_is_shim_linked(&bytes).map_err(|error| CliError(error.to_string()))?
    } else {
        true
    };
    if !shim_linked && !invocation.raw {
        return Err(CliError(format!(
            "refusing to audit {}: this binary was not built with `cargo patina build`, so its \
             imports are unsatisfied libc calls (open, clock_gettime, pthread_mutex_*, ...) — the \
             surface the shim *interposes* once linked — not the post-interposition residual. The \
             audit would be the opposite of the truth. Audit source-first so the shim is linked \
             first:\n    cargo patina audit ./Cargo.toml --bin <NAME>\nor pass a Patina-built \
             artifact (`cargo patina build ... --output <PATH>`). To list the raw imports of this \
             exact binary anyway, re-run with --raw.",
            resolved.path.display()
        )));
    }
    // `--raw` on a NON-shim-linked binary: run the full audit anyway — the
    // instruction scan and escape categorization stay meaningful — but under a
    // loud banner, because the *import* findings are the pre-interposition libc
    // surface, not the post-interposition residual a shim-linked audit reports.
    if !shim_linked && invocation.raw {
        eprintln!(
            "PATINA_RAW_AUDIT: auditing a NON-shim-linked binary. Import findings reflect \
             unsatisfied libc imports — most are symbols the shim interposes once `cargo patina \
             build` links it in — NOT the post-interposition residual. Audit source-first \
             (`cargo patina audit ./Cargo.toml --bin <NAME>`) for the true residual."
        );
    }
    // Shim-linked (or built on the fly, or --raw): render the real audit — for a
    // shim-linked artifact this is the true post-interposition residual, and it
    // fails closed on any genuine escape.
    //
    // The allow set is the shared `effective_native_allow` (shim control-plane +
    // the operator's `--allow`), the SAME set the pre-run `run` gate audits
    // against, so the static surface `audit` reports equals the surface `run`
    // enforces — closing the reported `_dlsym` disparity.
    //
    // syscall-user-dispatch (SUD-DESIGN.md §7.1): a `direct-syscall` *instruction*
    // finding in a SUD-dispatch-capable binary is not a hard escape — at run time
    // it is trapped and routed by SUD (on a kernel that has it). `audit` is
    // static (no live kernel probe), so it reports BOTH outcomes: runnable under
    // SUD, refused on kernels without it. Any OTHER denial (or the same finding
    // without the SUD marker) still fails closed.
    let effective = effective_native_allow(&invocation.allow);
    // Host-identity reads (`cpuid`) are informational, so they are reported on
    // EVERY outcome of the three-way split below — clean, trap-managed, and
    // refused. Scan for them once here rather than in each arm. The scan can only
    // fail the ways `NativeAudit::audit` fails on the same bytes (parse, format,
    // undecodable architecture), so propagating is fail-closed and changes no
    // message an operator sees.
    let host_identity =
        native_host_identity_sites(&bytes).map_err(|error| CliError(error.to_string()))?;
    let audit = match NativeAudit::audit(&bytes, &effective) {
        Ok(audit) => audit,
        Err(TargetError::UnsupportedNativeImports(denied)) => {
            let sud_marker = native_binary_has_sud_marker(&bytes)
                .map_err(|error| CliError(error.to_string()))?;
            // The timestamp-counter trap is the same shape as the SUD downgrade,
            // one instruction class over: an `rdtsc`/`rdtscp` finding in a
            // trap-capable binary is answered from the virtual clock at run time
            // on x86-64 Linux. `audit` stays static, so it reports both outcomes.
            let tsc_marker = native_binary_has_tsc_marker(&bytes)
                .map_err(|error| CliError(error.to_string()))?;
            let (managed, hard): (Vec<_>, Vec<_>) = denied.iter().cloned().partition(|escape| {
                (sud_marker && native_escape_is_sud_manageable(escape))
                    || (tsc_marker && native_escape_is_tsc_manageable(escape))
            });
            let (sud_instructions, tsc_instructions): (Vec<_>, Vec<_>) = managed
                .into_iter()
                .partition(native_escape_is_sud_manageable);
            if !hard.is_empty() || (sud_instructions.is_empty() && tsc_instructions.is_empty()) {
                // A genuine escape remains (or there was nothing SUD could manage):
                // fail closed and render the provenance-rich audit result.
                emit_native_audit_violation(&resolved.path, &denied, &host_identity);
                emit_host_identity_note(&host_identity);
                return Ok(2);
            }
            // Only trap-manageable instruction findings, and the matching
            // dispatcher is linked: report them as managed (both outcomes) and
            // succeed.
            let sites = sud_instructions.len();
            let tsc_sites = tsc_instructions.len();
            if output::options().is_json() {
                let mut findings: Vec<String> = sud_instructions
                    .iter()
                    .map(|escape| format!("{} (direct-syscall, SUD-managed)", escape.symbol))
                    .collect();
                findings.extend(tsc_instructions.iter().map(|escape| {
                    format!("{} (cpu-nondeterminism, TSC-trap-managed)", escape.symbol)
                }));
                let mut details = native_escape_details(&sud_instructions, Some("SUD-managed"));
                details.extend(native_escape_details(
                    &tsc_instructions,
                    Some("TSC-trap-managed"),
                ));
                details.extend(host_identity_details(&host_identity));
                output::emit_audit_with_details(
                    "audit",
                    "native",
                    &resolved.path.display().to_string(),
                    findings,
                    details,
                    0,
                );
            } else {
                if sites > 0 {
                    println!(
                        "direct-syscall (SUD-managed, {sites} site{}): raw inline syscall instruction(s) \
trapped into the deterministic runtime via syscall-user-dispatch. Runnable on a SUD kernel \
(x86_64 >= 5.11); refused on kernels without it (notably arm64 today) — rebuild with \
`--cfg rustix_use_libc` for those.",
                        if sites == 1 { "" } else { "s" }
                    );
                }
                if tsc_sites > 0 {
                    println!(
                        "cpu-nondeterminism (TSC-trap-managed, {tsc_sites} site{}): inline rdtsc/rdtscp \
answered deterministically from the run's virtual clock via prctl(PR_SET_TSC) on x86-64 Linux; \
refused everywhere else (macOS, arm64) — rebuild the guest without the inline counter read for \
those. Manageable is not runnable: this says the counter reads are answered, not that the guest \
progresses. A guest that calibrates the counter by busy-waiting on clock deltas is carried by the \
runtime's advance-on-spin rescue; one that spins without ever consulting the value stops with a \
named frozen-clock-churn abort.",
                        if tsc_sites == 1 { "" } else { "s" }
                    );
                }
                for escape in sud_instructions.iter().chain(tsc_instructions.iter()) {
                    println!("  {} ({})", escape.symbol, escape.category);
                    for provenance in &escape.provenance {
                        if let Some(site) = provenance.site_label() {
                            println!("    {} [{site}]", provenance.label());
                        } else {
                            println!("    {}", provenance.label());
                        }
                    }
                }
            }
            emit_host_identity_note(&host_identity);
            return Ok(0);
        }
        Err(error) => return Err(CliError(error.to_string())),
    };
    let findings: Vec<String> = audit.imports.iter().map(ToString::to_string).collect();
    if output::options().is_json() {
        output::emit_audit_with_details(
            "audit",
            "native",
            &resolved.path.display().to_string(),
            findings,
            host_identity_details(&host_identity),
            0,
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    // The audit above reports the import-table residual. Deny-trap-armed symbols
    // are absent from it by construction (the shim strong-def drops them off the
    // import table), so add the non-blocking "fails later" note naming any this
    // binary references — visible up front rather than only when a call aborts.
    emit_native_deny_trap_note(&bytes);
    // Same visibility rule for imports the undefined-weak rule cleared: the
    // audit outcome ignores them, but the surface stays named, on stderr in
    // both output modes so the JSON envelope stays schema-stable.
    if let Some(note) = render_inert_weak_imports(&audit.inert_weak_imports) {
        eprintln!("{note}");
    }
    // And for host-identity reads: a clean audit is exactly where their silence
    // used to be total — the binary passes, and nothing said its code paths can
    // vary across hosts.
    emit_host_identity_note(&host_identity);
    Ok(0)
}

/// The disposition label host-identity findings carry in the JSON envelope's
/// `finding_details`, alongside `SUD-managed` / `TSC-trap-managed`. Both halves
/// are the point: *unmanaged* (no trap, no model — unlike the timestamp counter)
/// and *visible* (reported anyway, unlike the silence this replaced).
const HOST_IDENTITY_DISPOSITION: &str = "unmanaged-visible";

fn host_identity_details(sites: &[NativeEscape]) -> Vec<serde_json::Value> {
    native_escape_details(sites, Some(HOST_IDENTITY_DISPOSITION))
}

/// Print the host-identity heading, on stderr in BOTH output modes — the
/// inert-weak-imports rule. The sites are informational and never change the exit
/// code, so keeping them off stdout leaves the human import list and the JSON
/// envelope byte-stable for callers that parse them; JSON consumers get the same
/// sites as `finding_details` rows carrying [`HOST_IDENTITY_DISPOSITION`].
fn emit_host_identity_note(sites: &[NativeEscape]) {
    if let Some(note) = render_host_identity_note(sites) {
        eprintln!("{note}");
    }
}

fn emit_native_audit_violation(
    path: &Path,
    denied: &[NativeEscape],
    host_identity: &[NativeEscape],
) {
    let findings = denied.iter().map(native_escape_summary).collect::<Vec<_>>();
    if output::options().is_json() {
        let mut details = native_escape_details(denied, None);
        // A refusal reports the host-identity sites too: they are not why the
        // binary was refused, and dropping them here would make the class visible
        // on some outcomes and silent on others.
        details.extend(host_identity_details(host_identity));
        output::emit_audit_with_details(
            "audit",
            "native",
            &path.display().to_string(),
            findings,
            details,
            2,
        );
    } else {
        eprintln!("{}", render_native_escapes_grouped(denied));
        if let Some(note) = render_thread_pointer_note(denied) {
            eprintln!("{note}");
        }
        if let Some(note) = render_compat_mode_note(denied) {
            eprintln!("{note}");
        }
    }
}

pub(super) fn native_escape_summary(escape: &NativeEscape) -> String {
    format!("{} ({})", escape.symbol, escape.category)
}

pub(super) fn push_native_escape_provenance_lines(
    output: &mut String,
    escape: &NativeEscape,
    indent: &str,
) {
    for provenance in &escape.provenance {
        output.push('\n');
        output.push_str(indent);
        output.push_str(&provenance.label());
        if let Some(site) = provenance.site_label() {
            output.push_str(&format!(" [{site}]"));
        }
    }
}

fn native_escape_details(
    escapes: &[NativeEscape],
    disposition: Option<&str>,
) -> Vec<serde_json::Value> {
    escapes
        .iter()
        .map(|escape| {
            let provenance = escape
                .provenance
                .iter()
                .map(|origin| {
                    serde_json::json!({
                        "object": origin.object.clone(),
                        "crate": origin.crate_name.clone(),
                        "containing_symbol": origin.containing_symbol.clone(),
                        "section": origin.section.clone(),
                    })
                })
                .collect::<Vec<_>>();
            let mut detail = serde_json::json!({
                "symbol": escape.symbol.clone(),
                "category": escape.category,
                "provenance": provenance,
            });
            if let Some(disposition) = disposition {
                detail["disposition"] = serde_json::Value::String(disposition.to_string());
            }
            if let Some(mnemonic) = escape.mnemonic {
                detail["mnemonic"] = serde_json::Value::String(mnemonic.to_string());
            }
            detail
        })
        .collect()
}
