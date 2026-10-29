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
/// The recorded fault/buggify records are derived from the masked config, and
/// the swarm record names a dropped class as a candidate that was not selected.
/// The run's fingerprint is computed from the masked config afterwards, so a
/// deselected `buggify` leaves no `+buggify` behind.
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
        apply_swarm_class(seed, class.token, class.domain, &mut draw, || {
            match class.masks {
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
            }
        });
    }

    patina_dst_trace::SwarmConfigRecord {
        candidate_classes: draw.candidates.into_iter().map(String::from).collect(),
        selected_classes: draw.selected,
    }
}

/// What one run's swarm draw accumulated: the classes it considered, the ones it
/// kept. Collected in a
/// struct rather than two out-parameters so the per-class droppers — which each
/// borrow the config mutably — stay independent of the accumulation.
#[derive(Default)]
struct SwarmDraw {
    candidates: Vec<&'static str>,
    selected: Vec<String>,
}

fn apply_swarm_class(
    seed: u64,
    token: &'static str,
    domain: &'static str,
    draw: &mut SwarmDraw,
    drop: impl FnOnce(),
) {
    draw.candidates.push(token);
    let mut rng = SplitMix64::new(domain_seed(seed, domain));
    if rng.next_u64() & 1 == 1 {
        draw.selected.push(token.into());
    } else {
        drop();
    }
}

#[cfg(test)]
mod tests;
