//! In-house model-based (stateful) testing over [`patina-dst-proptest`](crate).
//!
//! # What this adds over a plain property
//!
//! A single property checks one generated value. A *stateful* property checks a
//! whole *sequence* of operations against a reference model: it generates a list
//! of abstract [commands](StateMachine::Command), runs each one against both a
//! cheap in-memory **model** and the real **system under test** (SUT), and after
//! every step asserts the SUT still agrees with the model. When they diverge,
//! the failing command sequence is the counterexample — and, because generation
//! rides on [`patina-dst-proptest`](crate)'s ChaCha-seeded runner, the whole search
//! (and the shrunk sequence) is a pure function of the Patina run seed.
//!
//! This is the same idea as `proptest-state-machine`, kept deliberately small
//! and Patina-native: one trait, three entry points, no bespoke RNG, and the
//! command-sequence shrinking is proptest's own `Vec` shrinker.
//!
//! # Generation is state-independent; validity is a precondition
//!
//! Commands are drawn from a single fixed [`command_strategy`] — generation does
//! *not* consult the model. Whether a generated command is *legal in the current
//! model state* is decided by [`precondition`]. The runner skips any command
//! whose precondition is false at the point it would run. This is the load-
//! bearing choice that makes shrinking work: because validity is re-decided on
//! every execution, a shrunk sequence (with commands dropped or simplified) stays
//! valid by construction — an operation that becomes illegal after an earlier one
//! is removed is simply skipped rather than corrupting the run. Preconditions are
//! therefore re-checked during shrinking exactly as during the first run; the
//! documented policy is *skip*, never *regenerate*.
//!
//! [`command_strategy`]: StateMachine::command_strategy
//! [`precondition`]: StateMachine::precondition
//!
//! # Shrinking
//!
//! A failing run produces a `Vec<Command>` counterexample. proptest's built-in
//! `Vec` shrinker both **drops commands** and **simplifies individual commands**
//! (via each command strategy's own shrink tree), re-running the sequence after
//! each candidate edit. A dropped command that was only ever skipped changes
//! nothing and is accepted, so redundant commands fall away; a load-bearing one
//! is kept. The result is a locally minimal sequence, and it is
//! deterministic — the same runner seed yields the same shrunk sequence every
//! time (see the crate-level determinism note).
//!
//! # Worked example: a key/value store against a `BTreeMap`
//!
//! The SUT here is a `HashMap` and the model a `BTreeMap`; both are correct, so
//! the property holds. Swap in a real store (see the redb dogfood) or plant a
//! bug and [`check`] returns the minimal failing command sequence.
//!
//! ```
//! use std::collections::{BTreeMap, HashMap};
//!
//! use patina_dst_proptest::prelude::*;
//! use patina_dst_proptest::state::{check, StateMachine};
//!
//! #[derive(Clone, Debug)]
//! enum Cmd {
//!     Put(u8, u8),
//!     Delete(u8),
//!     Get(u8),
//! }
//!
//! struct KvStore;
//!
//! impl StateMachine for KvStore {
//!     type Command = Cmd;
//!     type Model = BTreeMap<u8, u8>;
//!     type System = HashMap<u8, u8>;
//!
//!     fn init_model() -> Self::Model {
//!         BTreeMap::new()
//!     }
//!
//!     fn init_system() -> Self::System {
//!         HashMap::new()
//!     }
//!
//!     fn command_strategy() -> BoxedStrategy<Self::Command> {
//!         prop_oneof![
//!             (0u8..4, 0u8..8).prop_map(|(k, v)| Cmd::Put(k, v)),
//!             (0u8..4).prop_map(Cmd::Delete),
//!             (0u8..4).prop_map(Cmd::Get),
//!         ]
//!         .boxed()
//!     }
//!
//!     fn precondition(_model: &Self::Model, _command: &Self::Command) -> bool {
//!         true
//!     }
//!
//!     fn next(model: &mut Self::Model, command: &Self::Command) {
//!         match command {
//!             Cmd::Put(k, v) => {
//!                 model.insert(*k, *v);
//!             }
//!             Cmd::Delete(k) => {
//!                 model.remove(k);
//!             }
//!             Cmd::Get(_) => {}
//!         }
//!     }
//!
//!     fn apply(
//!         system: &mut Self::System,
//!         model: &Self::Model,
//!         command: &Self::Command,
//!     ) -> Result<(), String> {
//!         match command {
//!             Cmd::Put(k, v) => {
//!                 system.insert(*k, *v);
//!             }
//!             Cmd::Delete(k) => {
//!                 system.remove(k);
//!             }
//!             Cmd::Get(k) => {
//!                 if system.get(k) != model.get(k) {
//!                     return Err(format!("get({k}) diverged"));
//!                 }
//!             }
//!         }
//!         Ok(())
//!     }
//! }
//!
//! let mut runner = patina_dst_proptest::runner();
//! check::<KvStore>(&mut runner, 0..=16).expect("the store matches its model");
//! ```

use std::fmt::Debug;

use proptest::collection::{SizeRange, vec};
use proptest::strategy::BoxedStrategy;
use proptest::test_runner::{TestCaseError, TestError, TestRunner};

/// A system under test paired with a reference model and the abstract commands
/// that drive both.
///
/// Implement this for a marker type; the associated types name the pieces and
/// the methods define one step of the model/SUT contract. The runner
/// ([`check`]/[`execute`]) generates a command sequence, then for each command
/// in turn: checks [`precondition`](Self::precondition) (skipping the command if
/// it does not hold), advances the model with [`next`](Self::next), applies it
/// to the SUT with [`apply`](Self::apply), and finally runs
/// [`check_invariants`](Self::check_invariants). The first `Err` from `apply` or
/// `check_invariants` is the failure that gets shrunk.
pub trait StateMachine {
    /// An abstract operation. `Clone` so the runner can report the executed
    /// subsequence; `Debug` so a counterexample is legible.
    type Command: Clone + Debug;

    /// The reference model: a cheap, obviously-correct mirror of the SUT's
    /// observable state.
    type Model;

    /// The system under test.
    type System;

    /// The model's initial state.
    fn init_model() -> Self::Model;

    /// A fresh system under test.
    fn init_system() -> Self::System;

    /// The strategy commands are drawn from. Fixed and state-independent — bake
    /// every command variant in here (typically with [`prop_oneof!`]) and gate
    /// legality in [`precondition`](Self::precondition). proptest's shrinking of
    /// the generated `Vec` and of each command comes from this strategy.
    ///
    /// [`prop_oneof!`]: proptest::prop_oneof
    fn command_strategy() -> BoxedStrategy<Self::Command>;

    /// Whether `command` is legal in the current model state. A command whose
    /// precondition is false is skipped (never applied to the SUT), both on the
    /// first run and during shrinking, which is what keeps shrunk sequences
    /// valid. Default: everything is always legal.
    fn precondition(model: &Self::Model, command: &Self::Command) -> bool {
        let _ = (model, command);
        true
    }

    /// Advance the model by `command`. Called before [`apply`](Self::apply), so
    /// `apply` sees the post-transition model and can compare the SUT's result
    /// against the model's expectation.
    fn next(model: &mut Self::Model, command: &Self::Command);

    /// Apply `command` to the SUT and check it against the (already advanced)
    /// `model`. Return `Err(message)` on a postcondition violation — e.g. a read
    /// command whose SUT result disagrees with the model.
    fn apply(
        system: &mut Self::System,
        model: &Self::Model,
        command: &Self::Command,
    ) -> Result<(), String>;

    /// A whole-state invariant checked after every applied command. Use it to
    /// compare the SUT's full observable state against the model. Default: no
    /// extra invariant beyond each command's own [`apply`](Self::apply) check.
    fn check_invariants(system: &Self::System, model: &Self::Model) -> Result<(), String> {
        let _ = (system, model);
        Ok(())
    }
}

/// A failing command sequence and the violation it triggered.
///
/// `commands` is the *executed* subsequence — only the precondition-passing
/// commands, up to and including the one whose `apply`/`check_invariants`
/// failed — so it is directly the minimal reproduction, with skipped commands
/// already elided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMachineFailure<C> {
    /// The executed commands leading to and including the failure.
    pub commands: Vec<C>,
    /// The message returned by the failing `apply` or `check_invariants`.
    pub message: String,
}

/// Execute one concrete command sequence against a fresh model and SUT.
///
/// Skips commands whose [`precondition`](StateMachine::precondition) is false in
/// the current model state. On success returns the executed (precondition-
/// passing) subsequence; on the first violation returns the executed prefix plus
/// the failure message. This is a pure function of `commands`, so re-running a
/// counterexample reproduces it exactly — which is how [`check`] recovers the
/// executed trace from proptest's shrunk `Vec`.
pub fn execute<M: StateMachine>(
    commands: &[M::Command],
) -> Result<Vec<M::Command>, StateMachineFailure<M::Command>> {
    let mut model = M::init_model();
    let mut system = M::init_system();
    let mut executed = Vec::new();
    for command in commands {
        if !M::precondition(&model, command) {
            continue;
        }
        M::next(&mut model, command);
        executed.push(command.clone());
        if let Err(message) = M::apply(&mut system, &model, command) {
            return Err(StateMachineFailure {
                commands: executed,
                message,
            });
        }
        if let Err(message) = M::check_invariants(&system, &model) {
            return Err(StateMachineFailure {
                commands: executed,
                message,
            });
        }
    }
    Ok(executed)
}

/// Search for a failing command sequence and shrink it to a minimal one.
///
/// Generates `Vec<Command>` values of length in `sizes` from `runner` (seeded,
/// under Patina, from the run seed) and executes each with [`execute`]. On the
/// first failure proptest shrinks the sequence — dropping and simplifying
/// commands — and this returns the minimal counterexample as a
/// [`StateMachineFailure`]. Returns `Ok(())` if the property held for every
/// generated sequence.
pub fn check<M: StateMachine>(
    runner: &mut TestRunner,
    sizes: impl Into<SizeRange>,
) -> Result<(), StateMachineFailure<M::Command>> {
    let strategy = vec(M::command_strategy(), sizes);
    match runner.run(&strategy, |commands| {
        execute::<M>(&commands)
            .map(|_| ())
            .map_err(|failure| TestCaseError::fail(failure.message))
    }) {
        Ok(()) => Ok(()),
        Err(TestError::Fail(reason, minimal)) => {
            // The minimal value proptest returns is one that failed the test, so
            // re-executing it deterministically reproduces the failure and yields
            // the executed subsequence. The fallback only guards the impossible
            // case of a non-reproducing minimal, keeping this total.
            Err(execute::<M>(&minimal)
                .err()
                .unwrap_or_else(|| StateMachineFailure {
                    commands: minimal,
                    message: reason.to_string(),
                }))
        }
        Err(TestError::Abort(reason)) => {
            panic!("state-machine run aborted before finding a counterexample: {reason}")
        }
    }
}

/// Run [`check`] and panic with the minimal counterexample if the property
/// fails. The drop-in for asserting a stateful property inside a test.
pub fn assert_holds<M: StateMachine>(runner: &mut TestRunner, sizes: impl Into<SizeRange>) {
    if let Err(failure) = check::<M>(runner, sizes) {
        panic!(
            "stateful property failed: {}\nminimal command sequence ({} commands): {:#?}",
            failure.message,
            failure.commands.len(),
            failure.commands
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;
    use crate::rng_from_seed;

    /// The abstract KV command used by the planted-bug tests. Small domains
    /// (keys `0..4`, values `0..8`) so collisions are frequent and shrinking
    /// converges to tiny, canonical counterexamples.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Cmd {
        Insert(u8, u8),
        Remove(u8),
        Get(u8),
    }

    fn cmd_strategy() -> BoxedStrategy<Cmd> {
        prop_oneof![
            (0u8..4, 0u8..8).prop_map(|(k, v)| Cmd::Insert(k, v)),
            (0u8..4).prop_map(Cmd::Remove),
            (0u8..4).prop_map(Cmd::Get),
        ]
        .boxed()
    }

    /// A correct KV: SUT is a second `BTreeMap`, so the property always holds.
    struct CorrectKv;

    impl StateMachine for CorrectKv {
        type Command = Cmd;
        type Model = BTreeMap<u8, u8>;
        type System = BTreeMap<u8, u8>;

        fn init_model() -> Self::Model {
            BTreeMap::new()
        }
        fn init_system() -> Self::System {
            BTreeMap::new()
        }
        fn command_strategy() -> BoxedStrategy<Self::Command> {
            cmd_strategy()
        }
        fn next(model: &mut Self::Model, command: &Self::Command) {
            apply_to_map(model, command);
        }
        fn apply(
            system: &mut Self::System,
            model: &Self::Model,
            command: &Self::Command,
        ) -> Result<(), String> {
            apply_to_map(system, command);
            check_get(system, model, command)
        }
        fn check_invariants(system: &Self::System, model: &Self::Model) -> Result<(), String> {
            if system == model {
                Ok(())
            } else {
                Err(format!("state diverged: sut={system:?} model={model:?}"))
            }
        }
    }

    /// A KV with a planted off-by-one delete bug: `Remove(1)` also deletes key
    /// `0` in the SUT, while the model removes only key `1`. Both keys are pinned
    /// by the bug (the clobbered key `0` and the triggering key `1`) and the
    /// surviving field — the value inserted at key `0` — is free of any coupling,
    /// so it shrinks cleanly to `0`. The counterexample therefore converges to a
    /// single canonical two-command sequence across every seed:
    /// `[Insert(0, 0), Remove(1)]`.
    struct PlantedBugKv;

    impl StateMachine for PlantedBugKv {
        type Command = Cmd;
        type Model = BTreeMap<u8, u8>;
        type System = BTreeMap<u8, u8>;

        fn init_model() -> Self::Model {
            BTreeMap::new()
        }
        fn init_system() -> Self::System {
            BTreeMap::new()
        }
        fn command_strategy() -> BoxedStrategy<Self::Command> {
            cmd_strategy()
        }
        fn next(model: &mut Self::Model, command: &Self::Command) {
            apply_to_map(model, command);
        }
        fn apply(
            system: &mut Self::System,
            model: &Self::Model,
            command: &Self::Command,
        ) -> Result<(), String> {
            match command {
                Cmd::Insert(k, v) => {
                    system.insert(*k, *v);
                }
                Cmd::Remove(k) => {
                    system.remove(k);
                    // The bug: removing key 1 also evicts key 0.
                    if *k == 1 {
                        system.remove(&0);
                    }
                }
                Cmd::Get(_) => {}
            }
            check_get(system, model, command)?;
            if system == model {
                Ok(())
            } else {
                Err(format!("state diverged: sut={system:?} model={model:?}"))
            }
        }
    }

    fn apply_to_map(map: &mut BTreeMap<u8, u8>, command: &Cmd) {
        match command {
            Cmd::Insert(k, v) => {
                map.insert(*k, *v);
            }
            Cmd::Remove(k) => {
                map.remove(k);
            }
            Cmd::Get(_) => {}
        }
    }

    fn check_get(
        system: &BTreeMap<u8, u8>,
        model: &BTreeMap<u8, u8>,
        command: &Cmd,
    ) -> Result<(), String> {
        if let Cmd::Get(k) = command {
            if system.get(k) != model.get(k) {
                return Err(format!(
                    "get({k}) diverged: sut={:?} model={:?}",
                    system.get(k),
                    model.get(k)
                ));
            }
        }
        Ok(())
    }

    fn runner(seed: u8) -> TestRunner {
        TestRunner::new_with_rng(crate::config(), rng_from_seed([seed; 32]))
    }

    #[test]
    fn correct_store_satisfies_its_model() {
        let mut runner = runner(1);
        check::<CorrectKv>(&mut runner, 0..=24).expect("a correct store must hold");
    }

    // The planted bug is found and shrunk to the tightest possible sequence: an
    // insert of key 0 followed by the remove of key 1 that clobbers it. The
    // whole-state comparison in `apply` catches the divergence with no Get.
    #[test]
    fn planted_bug_shrinks_to_a_minimal_sequence() {
        let mut runner = runner(1);
        let failure = check::<PlantedBugKv>(&mut runner, 0..=24)
            .expect_err("the off-by-one delete bug must be caught");
        assert_eq!(
            failure.commands.len(),
            2,
            "expected a two-command counterexample, got {:?}",
            failure.commands
        );
        match (&failure.commands[0], &failure.commands[1]) {
            (Cmd::Insert(0, _), Cmd::Remove(1)) => {}
            other => panic!("unexpected minimal sequence: {other:?}"),
        }
    }

    // Shrinking is deterministic: the same seed yields a byte-identical minimal
    // sequence across repeats, and independent seeds converge to the same
    // canonical counterexample.
    #[test]
    fn shrinking_is_stable_across_repeats_and_seeds() {
        let shrink = |seed: u8| {
            let mut runner = runner(seed);
            check::<PlantedBugKv>(&mut runner, 0..=24)
                .unwrap_err()
                .commands
        };
        let baseline = shrink(1);
        assert_eq!(baseline, shrink(1), "same seed must reproduce the shrink");
        assert_eq!(
            baseline,
            shrink(7),
            "seed 7 must converge to the same minimum"
        );
        assert_eq!(
            baseline,
            shrink(42),
            "seed 42 must converge to the same minimum"
        );
        assert_eq!(
            baseline,
            vec![Cmd::Insert(0, 0), Cmd::Remove(1)],
            "the canonical minimum inserts key 0 then removes key 1, clobbering key 0"
        );
    }

    // A precondition that forbids a command class causes those commands to be
    // skipped, never applied — proven by a machine whose SUT would panic if a
    // forbidden command ever reached `apply`.
    #[test]
    fn precondition_skips_forbidden_commands() {
        struct NoRemovesKv;
        impl StateMachine for NoRemovesKv {
            type Command = Cmd;
            type Model = BTreeMap<u8, u8>;
            type System = BTreeMap<u8, u8>;

            fn init_model() -> Self::Model {
                BTreeMap::new()
            }
            fn init_system() -> Self::System {
                BTreeMap::new()
            }
            fn command_strategy() -> BoxedStrategy<Self::Command> {
                cmd_strategy()
            }
            fn precondition(_model: &Self::Model, command: &Self::Command) -> bool {
                !matches!(command, Cmd::Remove(_))
            }
            fn next(model: &mut Self::Model, command: &Self::Command) {
                apply_to_map(model, command);
            }
            fn apply(
                system: &mut Self::System,
                model: &Self::Model,
                command: &Self::Command,
            ) -> Result<(), String> {
                assert!(
                    !matches!(command, Cmd::Remove(_)),
                    "a precondition-forbidden command reached apply"
                );
                apply_to_map(system, command);
                check_get(system, model, command)
            }
        }

        let mut runner = runner(3);
        check::<NoRemovesKv>(&mut runner, 0..=24)
            .expect("skipping removes keeps the model correct");

        // And the executed trace never contains a skipped command.
        let commands = vec![Cmd::Insert(1, 2), Cmd::Remove(1), Cmd::Get(1)];
        let executed = execute::<NoRemovesKv>(&commands).expect("no divergence");
        assert!(
            !executed.iter().any(|c| matches!(c, Cmd::Remove(_))),
            "executed trace should have skipped the remove: {executed:?}"
        );
        assert_eq!(executed, vec![Cmd::Insert(1, 2), Cmd::Get(1)]);
    }
}
