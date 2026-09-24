//! Every scenario, what it covers, and how patina is known to fail it.
//!
//! A [`Scenario`] declares the registry rows it exercises (`covers`), the rows
//! it asserts `ENOSYS` for because they are newer than the virtual ABI level
//! (`asserts_absent`), and the libc symbols its `libc` vehicle goes through.
//! The host must implement every covered row and lack every asserted-absent
//! one for its native run to be an oracle (see [`crate::host`]). A [`Gap`] is
//! a strict expected failure: the patina run must fail exactly as declared,
//! and a gap that stops matching fails its test until it is removed.
//! [`EXCLUSIONS`] are registry entries deliberately left without a scenario,
//! each with its reason; [`crate::coverage`] reports the rest.

use crate::compare::{Expected, Failure};
use crate::probe::Probe;
use crate::scenarios::{abi, entropy, fd, fs, net, proc, readiness, signal, thread, time};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// A scenario body.
pub type Run = fn(&Probe);

pub struct Scenario {
    /// `family/name`, the probe binary's first argument.
    pub name: &'static str,
    pub run: Run,
    /// The vehicles the scenario has a shape through.
    pub vehicles: &'static [Vehicle],
    /// Rows the scenario exercises and host-checks.
    pub covers: &'static [Syscall],
    /// Rows past the virtual ABI level the scenario asserts `ENOSYS` for.
    pub asserts_absent: &'static [Syscall],
    /// libc symbols the `libc` vehicle goes through.
    pub symbols: &'static [&'static str],
    pub gaps: &'static [Gap],
    /// Facts the patina run's recorded trace must show.
    pub trace: Option<TraceFacts>,
}

impl Scenario {
    /// The gaps that apply to `vehicle`.
    pub fn gaps_for(&self, vehicle: Vehicle) -> impl Iterator<Item = &Gap> {
        self.gaps
            .iter()
            .filter(move |gap| gap.vehicles.contains(&vehicle))
    }
}

/// The defaults a scenario declaration spreads (`..DEFAULTS`).
pub const DEFAULTS: Scenario = Scenario {
    name: "",
    run: |_| {},
    vehicles: Vehicle::ALL,
    covers: &[],
    asserts_absent: &[],
    symbols: &[],
    gaps: &[],
    trace: None,
};

/// The family arc (docs/arcs/syscall-conformance.md §6) that models a
/// pending gap away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arc {
    Fs,
    MemoryIpc,
    TimeTimersSchedIdentity,
    SignalsThreadsProcess,
    NetworkReadiness,
}

impl Arc {
    /// The arc's name as §6 spells it.
    pub fn name(self) -> &'static str {
        match self {
            Arc::Fs => "fs",
            Arc::MemoryIpc => "memory+ipc",
            Arc::TimeTimersSchedIdentity => "time+timers+sched+identity",
            Arc::SignalsThreadsProcess => "signals+threads+process",
            Arc::NetworkReadiness => "network+readiness",
        }
    }
}

/// Why a gap exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not modeled yet; the arc closes it.
    Pending(Arc),
    /// A permanent difference the design makes: the scenario's native oracle
    /// needs something patina refuses by design.
    ByDesign,
}

/// A strict expected failure of the patina run through `vehicles`.
pub struct Gap {
    pub status: Status,
    pub vehicles: &'static [Vehicle],
    /// What differs and the responsible code.
    pub what: &'static str,
    pub failure: Failure,
}

impl Gap {
    pub fn reason(&self) -> String {
        match self.status {
            Status::Pending(arc) => format!("pending: {} — {}", arc.name(), self.what),
            Status::ByDesign => format!("by design: {}", self.what),
        }
    }

    /// The gap as [`crate::compare::judge`] takes it, with `reason` from
    /// [`Gap::reason`].
    pub fn expected<'a>(&'a self, reason: &'a str) -> Expected<'a> {
        Expected {
            reason,
            failure: &self.failure,
        }
    }
}

/// A signal generation a recorded trace carries (`signal_generated`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    pub signal: i32,
    pub target: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Process,
    Thread,
}

impl Generation {
    /// A process-directed generation of `signal`.
    pub const fn process(signal: i32) -> Self {
        Generation {
            signal,
            target: Target::Process,
        }
    }

    /// A thread-directed generation of `signal`.
    pub const fn thread(signal: i32) -> Self {
        Generation {
            signal,
            target: Target::Thread,
        }
    }
}

/// What a scenario's recorded patina trace must show beyond its event stream:
/// a shallow model (a process-global signal state that fires a host signal at
/// generation time) can pass every behavioural check without these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceFacts {
    /// Exactly the scenario's generations, in order.
    pub generations: &'static [Generation],
    /// At most this many `task_wake` ops directly after one generation: only
    /// the chosen target is woken.
    pub max_wakes_per_generation: Option<usize>,
}

impl TraceFacts {
    /// Check `trace events --format json` records (one JSON value per op).
    pub fn check(&self, ops: &[Value]) -> Result<(), Vec<String>> {
        let mut unmet = Vec::new();
        let recorded: Vec<Generation> = ops.iter().filter_map(generation_of).collect();
        if recorded != self.generations {
            unmet.push(format!(
                "signal_generated ops recorded {recorded:?}, the scenario generates {:?}",
                self.generations
            ));
        }
        if let Some(max) = self.max_wakes_per_generation {
            for (index, op) in ops.iter().enumerate() {
                let wakes = ops[index + 1..]
                    .iter()
                    .take_while(|next| next["kind"] == "task_wake")
                    .count();
                if op["kind"] == "signal_generated" && wakes > max {
                    unmet.push(format!(
                        "a generation woke {wakes} tasks (at most {max}: only the chosen target is woken)"
                    ));
                }
            }
        }
        if unmet.is_empty() { Ok(()) } else { Err(unmet) }
    }
}

/// A `signal_generated` op: process-directed when its `target` is the string
/// `process`, thread-directed otherwise (`{"task": N}`).
fn generation_of(op: &Value) -> Option<Generation> {
    if op["kind"] != "signal_generated" {
        return None;
    }
    let signal = i32::try_from(op["operation"]["sig"].as_u64()?).ok()?;
    let process = op["operation"]["target"]
        .as_str()
        .is_some_and(|target| target.eq_ignore_ascii_case("process"));
    Some(Generation {
        signal,
        target: if process {
            Target::Process
        } else {
            Target::Thread
        },
    })
}

/// A registry entry with no scenario, deliberately.
pub struct Exclusion {
    pub entry: Entry,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Syscall(Syscall),
    Symbol(&'static str),
}

/// Registry entries excluded from conformance coverage, with their reasons.
pub const EXCLUSIONS: &[Exclusion] = &[];

pub const SCENARIOS: &[&Scenario] = &[
    &abi::newer_than_virtual::SCENARIO,
    &entropy::getrandom::SCENARIO,
    &fd::pipes::SCENARIO,
    &fd::table::SCENARIO,
    &fs::dirs::SCENARIO,
    &fs::getdents::SCENARIO,
    &fs::links::SCENARIO,
    &fs::metadata::SCENARIO,
    &fs::open_rw::SCENARIO,
    &fs::owner::SCENARIO,
    &fs::paths::SCENARIO,
    &fs::size::SCENARIO,
    &fs::times::SCENARIO,
    &net::tcp::SCENARIO,
    &net::udp::SCENARIO,
    &proc::absent::SCENARIO,
    &proc::ids::SCENARIO,
    &proc::prctl::SCENARIO,
    &proc::traps::SCENARIO,
    &proc::wait::SCENARIO,
    &readiness::epoll::SCENARIO,
    &readiness::ppoll::SCENARIO,
    &signal::altstack::SCENARIO,
    &signal::basic::SCENARIO,
    &signal::block::SCENARIO,
    &signal::core_term::SCENARIO,
    &signal::default::SCENARIO,
    &signal::default_term::SCENARIO,
    &signal::eintr::SCENARIO,
    &signal::mask::SCENARIO,
    &signal::nested::SCENARIO,
    &signal::one_wake::SCENARIO,
    &signal::per_thread::SCENARIO,
    &signal::pipe::SCENARIO,
    &signal::pipe_term::SCENARIO,
    &signal::queue::SCENARIO,
    &signal::raw_action::SCENARIO,
    &signal::resethand_term::SCENARIO,
    &signal::rt_order::SCENARIO,
    &signal::unmask::SCENARIO,
    &signal::wait::SCENARIO,
    &thread::futex::SCENARIO,
    &thread::kill::SCENARIO,
    &thread::lifecycle::SCENARIO,
    &thread::main_exit::SCENARIO,
    &thread::masks::SCENARIO,
    &thread::pthread_kill::SCENARIO,
    &thread::tid_clear::SCENARIO,
    &time::clocks::SCENARIO,
];

/// The scenario named `name`.
pub fn scenario(name: &str) -> Option<&'static Scenario> {
    SCENARIOS
        .iter()
        .copied()
        .find(|scenario| scenario.name == name)
}

/// Scenarios that exist to prove a harness check can fail, never compared
/// with patina: `planted/escape` opens a host file through `syscall(2)` for the
/// leak filter to flag.
pub fn planted(name: &str) -> Option<(&'static str, Run)> {
    match name {
        "planted/escape" => Some(("planted/escape", planted_escape)),
        _ => None,
    }
}

fn planted_escape(p: &Probe) {
    let fd = p.openat(crate::probe::AT_FDCWD, "/etc/hostname", libc::O_RDONLY, 0);
    if fd >= 0 {
        p.close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_syscalls::{Disposition, Os, SYMBOLS, SYSCALLS};
    use std::collections::BTreeSet;

    fn disposition(row: Syscall) -> Disposition {
        SYSCALLS
            .iter()
            .find(|entry| entry.id == row)
            .map(|entry| entry.disposition)
            .unwrap_or_else(|| panic!("{} has no registry row", row.name()))
    }

    #[test]
    fn scenario_names_are_unique_family_slash_name() {
        let mut seen = BTreeSet::new();
        for scenario in SCENARIOS {
            assert!(seen.insert(scenario.name), "duplicate {}", scenario.name);
            let (family, name) = scenario.name.split_once('/').expect("family/name");
            assert!(!family.is_empty() && !name.is_empty(), "{}", scenario.name);
        }
    }

    #[test]
    fn every_scenario_exercises_a_row() {
        for scenario in SCENARIOS {
            assert!(
                !scenario.covers.is_empty() || !scenario.asserts_absent.is_empty(),
                "{} covers nothing",
                scenario.name
            );
        }
    }

    #[test]
    fn covered_rows_are_in_the_virtual_abi() {
        for scenario in SCENARIOS {
            for row in scenario.covers {
                assert_ne!(
                    disposition(*row),
                    Disposition::Absent,
                    "{} covers {}, which is past the virtual ABI level (assert it absent)",
                    scenario.name,
                    row.name()
                );
            }
        }
    }

    #[test]
    fn asserted_absent_rows_are_past_the_virtual_abi() {
        for scenario in SCENARIOS {
            for row in scenario.asserts_absent {
                assert_eq!(
                    disposition(*row),
                    Disposition::Absent,
                    "{} asserts {} absent",
                    scenario.name,
                    row.name()
                );
            }
        }
    }

    #[test]
    fn named_symbols_are_registry_rows_of_this_os() {
        for scenario in SCENARIOS {
            for symbol in scenario.symbols {
                assert!(
                    SYMBOLS
                        .iter()
                        .any(|row| row.name == *symbol && row.platform.defines_on(Os::host())),
                    "{} names symbol {symbol}, which has no registry row",
                    scenario.name
                );
            }
        }
    }

    #[test]
    fn gaps_name_vehicles_the_scenario_has() {
        for scenario in SCENARIOS {
            for gap in scenario.gaps {
                assert!(
                    !gap.vehicles.is_empty(),
                    "{}: a gap with no vehicle",
                    scenario.name
                );
                for vehicle in gap.vehicles {
                    assert!(
                        scenario.vehicles.contains(vehicle),
                        "{}: gap for {} it has no shape through",
                        scenario.name,
                        vehicle.name()
                    );
                }
            }
        }
    }

    #[test]
    fn a_vehicle_has_at_most_one_stopping_gap() {
        for scenario in SCENARIOS {
            for vehicle in scenario.vehicles {
                let stops = scenario
                    .gaps_for(*vehicle)
                    .filter(|gap| matches!(gap.failure, Failure::Stops { .. }))
                    .count();
                assert!(
                    stops <= 1,
                    "{}[{}]: {stops} stopping gaps",
                    scenario.name,
                    vehicle.name()
                );
            }
        }
    }

    /// A stopped run records no complete trace, so trace facts beside a stop
    /// would go unchecked.
    #[test]
    fn trace_facts_never_share_a_vehicle_with_a_stop() {
        for scenario in SCENARIOS.iter().filter(|scenario| scenario.trace.is_some()) {
            for vehicle in scenario.vehicles {
                assert!(
                    !scenario
                        .gaps_for(*vehicle)
                        .any(|gap| matches!(gap.failure, Failure::Stops { .. })),
                    "{}[{}]: trace facts and a stopping gap",
                    scenario.name,
                    vehicle.name()
                );
            }
        }
    }

    #[test]
    fn a_differing_gap_names_its_differences() {
        for scenario in SCENARIOS {
            for gap in scenario.gaps {
                if let Failure::Differs(differences) = gap.failure {
                    assert!(!differences.is_empty(), "{}: {}", scenario.name, gap.what);
                }
            }
        }
    }

    #[test]
    fn exclusions_are_unique_and_uncovered() {
        let mut seen = Vec::new();
        for exclusion in EXCLUSIONS {
            assert!(!exclusion.reason.is_empty());
            assert!(!seen.contains(&exclusion.entry), "{:?}", exclusion.entry);
            seen.push(exclusion.entry);
            for scenario in SCENARIOS {
                let covered = match exclusion.entry {
                    Entry::Syscall(row) => {
                        scenario.covers.contains(&row) || scenario.asserts_absent.contains(&row)
                    }
                    Entry::Symbol(name) => scenario.symbols.contains(&name),
                };
                assert!(
                    !covered,
                    "{:?} is excluded and covered by {}",
                    exclusion.entry, scenario.name
                );
            }
        }
    }

    fn op(kind: &str, operation: Value) -> Value {
        serde_json::json!({ "kind": kind, "operation": operation })
    }

    const ONE_PROCESS_SIGUSR1: TraceFacts = TraceFacts {
        generations: &[Generation {
            signal: libc::SIGUSR1,
            target: Target::Process,
        }],
        max_wakes_per_generation: Some(1),
    };

    #[test]
    fn trace_facts_accept_the_declared_generations() {
        let ops = [
            op(
                "signal_generated",
                serde_json::json!({ "sig": 10, "target": "process" }),
            ),
            op("task_wake", serde_json::json!({})),
        ];
        assert_eq!(ONE_PROCESS_SIGUSR1.check(&ops), Ok(()));
    }

    #[test]
    fn trace_facts_refuse_a_missing_generation() {
        assert!(ONE_PROCESS_SIGUSR1.check(&[]).is_err());
    }

    #[test]
    fn trace_facts_refuse_a_thread_directed_generation_for_a_process_one() {
        let ops = [op(
            "signal_generated",
            serde_json::json!({ "sig": 10, "target": { "task": 1 } }),
        )];
        assert!(ONE_PROCESS_SIGUSR1.check(&ops).is_err());
    }

    #[test]
    fn trace_facts_with_no_generations_refuse_a_generation() {
        const NONE: TraceFacts = TraceFacts {
            generations: &[],
            max_wakes_per_generation: None,
        };
        let ops = [op(
            "signal_generated",
            serde_json::json!({ "sig": 10, "target": "process" }),
        )];
        assert_eq!(NONE.check(&[]), Ok(()));
        assert!(NONE.check(&ops).is_err());
    }

    #[test]
    fn trace_facts_refuse_a_wake_all() {
        let ops = [
            op(
                "signal_generated",
                serde_json::json!({ "sig": 10, "target": "process" }),
            ),
            op("task_wake", serde_json::json!({})),
            op("task_wake", serde_json::json!({})),
        ];
        assert!(ONE_PROCESS_SIGUSR1.check(&ops).is_err());
    }
}
