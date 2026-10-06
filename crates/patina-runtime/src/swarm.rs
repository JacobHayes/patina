//! Seeded fault-class selection and fingerprint component retraction.

use crate::{Masks, SWARM_CLASSES};

use crate::config::{BuggifyConfig, RuntimeConfig};
use patina_dst_rng_seeded::{SplitMix64, domain_seed};

/// Apply swarm fault-class selection to a record/seeded run's configuration: for
/// each enabled fault class, a domain-separated seed-derived coin decides whether
/// it stays active this generation. The masked configuration is what every driver
/// and the recorded `FaultConfigRecord` then consume, so replay reproduces the
/// selected subset verbatim; the returned `SwarmConfigRecord` documents the
/// candidate set and the seed's selection so the trace is self-describing. Each
/// class draws independently, so subsets vary across generations (seeds).
///
/// **Deselection is retracted from the fingerprint too.** A class whose
/// capability the supervisor declared as a compatibility-fingerprint component
/// (today only [`FINGERPRINT_BUGGIFY`]) has that component stripped from
/// `config.fingerprint` when the seed deselects it, because the fingerprint
/// describes the run that actually happened, not the run that was requested.
/// Without this the run would declare `+buggify` while carrying a disarmed
/// buggify config — exactly the incoherence
/// [`validate_buggify_fingerprint_contract`] refuses — so a legitimate
/// swarm-masked generation aborted. The trace metadata stays coherent by the same
/// rule: the recorded fault/buggify records are derived from the masked config,
/// and the swarm record names the class as a candidate that was not selected.
pub(super) fn apply_swarm_mask(config: &mut RuntimeConfig) -> patina_dst_trace::SwarmConfigRecord {
    let mut draw = SwarmDraw::default();
    let seed = config.seed;

    // [`SWARM_CLASSES`] is the draw order, and what each class masks decides both
    // its candidacy and its dropper — so a knob joins swarm by naming a class in
    // the knob table, never by growing this function.
    for class in SWARM_CLASSES {
        let candidate = match class.masks {
            Masks::Knobs(knobs) => knobs.iter().any(|knob| knob.is_set(&config.faults)),
            Masks::Buggify => config.buggify.enabled,
        };
        if !candidate {
            continue;
        }
        apply_swarm_class(
            seed,
            class.token,
            class.domain,
            class.fingerprint_component,
            &mut draw,
            || match class.masks {
                Masks::Knobs(knobs) => {
                    for knob in knobs {
                        knob.clear(&mut config.faults);
                    }
                }
                // The WHOLE buggify config is reset, not just `enabled`. Clearing
                // only the flag left the requested permilles behind, so the run
                // reported `enabled=0 fire_permille=372` — a half-masked state
                // that reads like "buggify was asked for and silently ignored".
                // That line is what the original investigation drew its (wrong)
                // conclusion from. A dropped class now leaves no residue at all;
                // the fact that it was requested and dropped is carried
                // explicitly by the swarm record, the `PATINA_SWARM_REPORT` line,
                // and `swarm_deselected=1`. Resetting also makes record and
                // replay agree: the trace records no buggify config for a dropped
                // class, so a replay that rebuilt one from residue could not
                // reproduce the recording's diagnostics.
                Masks::Buggify => config.buggify = BuggifyConfig::default(),
            },
        );
    }

    for component in draw.retract {
        config.fingerprint = remove_fingerprint_component(&config.fingerprint, component);
    }

    patina_dst_trace::SwarmConfigRecord {
        candidate_classes: draw.candidates.into_iter().map(String::from).collect(),
        selected_classes: draw.selected,
    }
}

/// What one run's swarm draw accumulated: the classes it considered, the ones it
/// kept, and the fingerprint components of the ones it dropped. Collected in a
/// struct rather than three out-parameters so the per-class droppers — which each
/// borrow the config mutably — stay independent of the accumulation.
#[derive(Default)]
struct SwarmDraw {
    candidates: Vec<&'static str>,
    selected: Vec<String>,
    /// Retracted from the fingerprint only after every dropper has run, so the
    /// config borrow the droppers hold is released first.
    retract: Vec<&'static str>,
}

fn apply_swarm_class(
    seed: u64,
    token: &'static str,
    domain: &'static str,
    fingerprint_component: Option<&'static str>,
    draw: &mut SwarmDraw,
    drop: impl FnOnce(),
) {
    draw.candidates.push(token);
    let mut rng = SplitMix64::new(domain_seed(seed, domain));
    if rng.next_u64() & 1 == 1 {
        draw.selected.push(token.into());
    } else {
        drop();
        if let Some(component) = fingerprint_component {
            draw.retract.push(component);
        }
    }
}

/// Remove every `+component` occurrence from a compatibility fingerprint,
/// preserving the base label and the order of the remaining components. The
/// result is exactly the string a supervisor composes for a run that never
/// declared the component, so a flag-free replay — which reconstructs the
/// component set from the trace metadata — recomputes an identical fingerprint.
fn remove_fingerprint_component(fingerprint: &str, component: &str) -> String {
    let mut parts = fingerprint.split('+');
    let mut out = String::from(parts.next().unwrap_or_default());
    for part in parts {
        if part == component {
            continue;
        }
        out.push('+');
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests;
