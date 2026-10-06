//! Native audit findings and containment-note rendering.

use crate::NativeEscape;
use crate::instruction_scan::{FAR_TRANSFER_CATEGORY, THREAD_POINTER_CATEGORY};
use crate::provenance::NativeProvenance;
use crate::shim::{native_escape_is_sud_manageable, native_escape_is_tsc_manageable};
use std::collections::{BTreeMap, BTreeSet};

/// Render the "host-identity reads" heading for the sites
/// [`native_host_identity_sites`] found, or `None` when there are none.
///
/// The wording keeps the distinctions the timestamp-counter note draws.
/// *Manageable* (rdtsc: trapped and answered from the virtual clock) and
/// *runnable* (the guest actually progresses) are both stronger than what holds
/// here: a host-identity read is **unmanaged** — patina neither traps nor models
/// it, and the guest sees the real host's feature bits. What that costs is
/// stated exactly: determinism ON a host is unaffected (the bits do not change
/// between runs), while reproducibility ACROSS hosts is not guaranteed wherever
/// those bits guard behavior. That is not hypothetical — `fastant` selects its
/// TSC path from the invariant-TSC bit, so the same guest at the same seed takes
/// a different code path on a host whose bit is clear.
pub fn render_host_identity_note(sites: &[NativeEscape]) -> Option<String> {
    if sites.is_empty() {
        return None;
    }
    let mnemonics: BTreeSet<&str> = sites.iter().filter_map(|site| site.mnemonic).collect();
    let keys = mnemonics.iter().any(|mnemonic| mnemonic.ends_with("pkru"));
    let mut note = format!(
        "host-identity reads ({}, {} site{}): unmanaged — patina neither traps nor models the host \
         CPU's identity, so the guest reads the real feature bits. This is NOT a refusal and NOT an \
         escape from a single run's determinism: the bits are constant on a host, so repeats and \
         record/replay are unaffected. What it costs is cross-host reproducibility — the guest's \
         code paths may vary across hosts with different CPU feature bits wherever these reads \
         guard behavior (a fast-clock crate selecting its timestamp-counter path from the \
         invariant-TSC bit is the live example). Pin the host to reproduce a run exactly.",
        mnemonics.into_iter().collect::<Vec<_>>().join("/"),
        sites.len(),
        if sites.len() == 1 { "" } else { "s" }
    );
    if keys {
        note.push_str(
            " rdpkru/wrpkru reach the host CPU's protection-key register, which contradicts the \
             declared virtual CPU (no protection keys): a host with keys answers its default \
             rights, one without raises SIGILL.",
        );
    }
    for site in sites {
        note.push_str(&format!("\n  {} ({})", site.symbol, site.category));
        for provenance in &site.provenance {
            note.push_str(&format!("\n    {}", provenance.label()));
            if let Some(label) = provenance.site_label() {
                note.push_str(&format!(" [{label}]"));
            }
        }
    }
    Some(note)
}

/// Render the "inert weak imports" heading for an audit's
/// [`NativeAudit::inert_weak_imports`], or `None` when there are none.
///
/// These are not allowed imports; they are references that cannot reach the host
/// at all, and the audit reports them so the surface stays visible rather than
/// disappearing into the clean-audit case.
pub fn render_inert_weak_imports(imports: &[String]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut output = String::from(
        "inert weak imports (undefined weak: resolve to NULL, the referencing code takes its \
         guarded fallback — not a host door):",
    );
    for import in imports {
        output.push_str("\n  ");
        output.push_str(import);
    }
    Some(output)
}

/// The refusal note for `cpu-nondeterminism` *instruction* findings that are
/// blocked, or `None` when the blocked set has none.
///
/// Two things were previously left unsaid at a refusal, and both misled:
///
/// 1. an instruction finding has no symbol name, so `--allow <symbol>` can never
///    clear one — the finding's "symbol" is a `.text` offset;
/// 2. `rdtsc`/`rdtscp` ARE trap-managed on x86-64 Linux, so the same binary that
///    is refused here runs contained there, while `rdrand`/`rdseed`/`mrs CNTVCT`
///    are refused everywhere because no mechanism traps them.
///
/// The note names which of the two the blocked findings are, by mnemonic, so the
/// operator is told whether a different platform (or a rebuild) is the fix.
pub fn render_cpu_nondeterminism_note(blocked: &[NativeEscape]) -> Option<String> {
    let instructions: Vec<&NativeEscape> = blocked
        .iter()
        .filter(|escape| {
            escape.category == "cpu-nondeterminism" && escape.symbol.starts_with("instruction@")
        })
        .collect();
    if instructions.is_empty() {
        return None;
    }
    let trappable: BTreeSet<&str> = instructions
        .iter()
        .filter(|escape| native_escape_is_tsc_manageable(escape))
        .filter_map(|escape| escape.mnemonic)
        .collect();
    let untrappable: BTreeSet<&str> = instructions
        .iter()
        .filter(|escape| !native_escape_is_tsc_manageable(escape))
        .filter_map(|escape| escape.mnemonic)
        .collect();

    let mut note = String::from(
        "note: the cpu-nondeterminism finding(s) above are INSTRUCTIONS, not imports: each names a \
         .text offset, so --allow <symbol> cannot clear one (there is no symbol to allow).",
    );
    if !trappable.is_empty() {
        note.push_str(&format!(
            " The {} site(s) read the timestamp counter, which the shim traps into the virtual \
             clock via prctl(PR_SET_TSC) — but only on x86-64 Linux with a trap-capable shim \
             linked. Here the trap is unavailable, so they are refused: run on x86-64 Linux, or \
             rebuild the guest without the inline timestamp read.",
            trappable.into_iter().collect::<Vec<_>>().join("/")
        ));
    }
    if !untrappable.is_empty() {
        note.push_str(&format!(
            " The {} site(s) are unallowable AND untrappable anywhere: no mechanism intercepts a \
             hardware entropy read or the arm64 system counter, so the deterministic runtime can \
             neither model nor contain them. The only fix is to remove the instruction — use the \
             interposed entropy/clock entry points (getrandom/clock_gettime) instead.",
            untrappable.into_iter().collect::<Vec<_>>().join("/")
        ));
    }
    Some(note)
}

/// The refusal note for blocked thread-pointer instruction findings, naming the
/// instructions, or `None` when the blocked set has none. Like the
/// cpu-nondeterminism note it says what the finding is and what fixes it, since
/// an instruction offset has no symbol for `--allow` to clear.
pub fn render_thread_pointer_note(blocked: &[NativeEscape]) -> Option<String> {
    let sites: Vec<&NativeEscape> = blocked
        .iter()
        .filter(|escape| {
            escape.category == THREAD_POINTER_CATEGORY && escape.symbol.starts_with("instruction@")
        })
        .collect();
    if sites.is_empty() {
        return None;
    }
    let mnemonics: BTreeSet<&str> = sites.iter().filter_map(|escape| escape.mnemonic).collect();
    Some(format!(
        "note: the thread-pointer finding(s) above are {} instruction(s) that move the thread \
         pointer. The shim linked into the guest finds its own per-thread state through that \
         pointer, so a guest that moves it corrupts the runtime (x86-64's syscall door, \
         arch_prctl(ARCH_SET_FS), is refused for the same reason). No trap intercepts the \
         write, and an instruction offset has no symbol for --allow to clear. Remove the \
         instruction: keep glibc's thread-local storage (the pointer glibc installs) rather \
         than installing your own.",
        mnemonics.into_iter().collect::<Vec<_>>().join("/")
    ))
}

/// The refusal note for blocked findings that reach the x86-64 kernel's 32-bit
/// syscall ABI or the CPU's 32-bit compatibility mode, naming them, or `None`
/// when the blocked set has none:
/// the i386 syscall entries (`int 0x80`, `sysenter`) and the far transfers
/// ([`FAR_TRANSFER_CATEGORY`]). Neither has a downgrade on any kernel, which the
/// generic direct-syscall hint would otherwise contradict.
pub fn render_compat_mode_note(blocked: &[NativeEscape]) -> Option<String> {
    let mnemonics: BTreeSet<&str> = blocked
        .iter()
        .filter(|escape| {
            escape.symbol.starts_with("instruction@")
                && (escape.category == FAR_TRANSFER_CATEGORY
                    || (escape.category == "direct-syscall"
                        && !native_escape_is_sud_manageable(escape)))
        })
        .filter_map(|escape| escape.mnemonic)
        .collect();
    if mnemonics.is_empty() {
        return None;
    }
    Some(format!(
        "note: the {} site(s) above leave the native 64-bit ABI. int 0x80 and sysenter enter \
         the kernel's i386 syscall ABI, which the shim never services (where the kernel traps \
         them into syscall-user-dispatch, its handler accepts only native syscalls; elsewhere \
         they fault), and a far call, jump or return can switch the CPU to a 32-bit code segment \
         whose instructions this 64-bit scan does not decode. No kernel runs either contained. \
         Remove the instruction.",
        mnemonics.into_iter().collect::<Vec<_>>().join("/")
    ))
}

/// The note naming the `rdtsc`/`rdtscp` sites the TSC trap manages for a run that
/// proceeds — the counterpart of the SUD-managed note, emitted by both the audit
/// and the pre-run gate so a contained escape is visible rather than silent.
pub fn render_tsc_managed_note(managed: &[NativeEscape], subject: &str) -> Option<String> {
    if managed.is_empty() {
        return None;
    }
    Some(format!(
        "patina: {} timestamp-counter instruction site(s) in {subject} are trap-managed: \
         rdtsc/rdtscp raise SIGSEGV via prctl(PR_SET_TSC) and are answered from the run's virtual \
         clock (1 GHz nominal, so a tick is a virtual nanosecond). These are contained, not \
         escapes — the run stays deterministic. Determinism is not progress: a guest that \
         calibrates the counter by busy-waiting on clock deltas is carried by the advance-on-spin \
         rescue, and one that spins without consulting the value stops with a named \
         frozen-clock-churn abort rather than hanging.",
        managed.len()
    ))
}

pub fn render_native_escapes_grouped(escapes: &[NativeEscape]) -> String {
    let mut groups: BTreeMap<String, Vec<(&NativeEscape, NativeProvenance)>> = BTreeMap::new();
    for escape in escapes {
        let provenance = if escape.provenance.is_empty() {
            vec![NativeProvenance::unknown()]
        } else {
            escape.provenance.clone()
        };
        for origin in provenance {
            groups
                .entry(origin.label())
                .or_default()
                .push((escape, origin));
        }
    }

    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_by(|(left_label, left), (right_label, right)| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left_label.cmp(right_label))
    });

    let mut output = String::from("unsupported native imports:");
    if groups.is_empty() {
        return output;
    }
    for (label, findings) in groups {
        output.push('\n');
        output.push_str(&format!(
            "  {label} ({} finding{})",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        ));
        for (finding, origin) in findings {
            output.push('\n');
            output.push_str(&format!("    {} ({})", finding.symbol, finding.category));
            if let Some(site) = origin.site_label() {
                output.push_str(&format!(" [{site}]"));
            }
        }
    }
    output
}

#[cfg(test)]
mod tests;
