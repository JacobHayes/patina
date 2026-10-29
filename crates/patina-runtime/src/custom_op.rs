//! Custom-operation protocols, seeded failures, and divergence classification.

use crate::{Context, RuntimeError};
use patina_dst_abi::{EffectError, ErrorCode, Operation, Outcome};
use patina_dst_rng_seeded::SplitMix64;
use patina_dst_trace::TraceError;

/// What [`Context::custom_op_begin`] tells the caller to do next — the whole
/// point of the custom-op protocol being two calls rather than one.
///
/// The guest's `perform` closure runs on exactly one of the two paths, and the
/// runtime, not the guest, decides which: that is what makes a custom op
/// deterministic by construction rather than by the guest's good behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomOpMode {
    /// Record (or plain seeded) execution: run `perform` and hand its result
    /// bytes to [`Context::custom_op_record`].
    Record,
    /// Replay: the recording already holds this operation's result. `perform`
    /// MUST NOT run; take the bytes from [`Context::custom_op_replay_result`].
    /// `len` is their length, so a `(pointer, capacity)` ABI caller can size its
    /// buffer before fetching.
    Replay { len: usize },
    /// A seeded fault fired (`--custom-op-fail-permille`), or the recording says
    /// one did. `perform` MUST NOT run and the caller returns the failure the
    /// operation declared at `begin` — the runtime never invents an error value,
    /// because only the guest knows a shape its own type admits.
    ///
    /// The operation is already closed: the fault IS the outcome, recorded when
    /// it fired, so there is nothing left to report and no closing call to make.
    Fault,
}

/// A custom operation announced by [`Context::custom_op_begin`] and not yet
/// closed out. It carries what the closing half needs to verify rather than
/// trust: the trace event to record, and the step counter at announce time.
pub(super) struct PendingCustomOp {
    pub(super) label: String,
    key: Vec<u8>,
    /// `self.steps` when the operation was announced. `perform` runs *outside*
    /// Patina's modeled boundary by definition, so a recorded operation landing
    /// between the two halves means the guest wrapped an effect Patina already
    /// models — a trace that cannot replay, because replay skips `perform` and
    /// therefore skips those events. Caught at record time instead of surfacing
    /// as an unexplained operation mismatch on some later replay.
    steps_at_begin: u64,
    /// The recorded result on replay, `None` on the record path. Also the
    /// discriminator the closing half checks, so a `record` on a replay pass (or
    /// a `replay_result` on a record pass) is refused rather than silently
    /// producing a divergent trace.
    replay_result: Option<Vec<u8>>,
}

/// Name a replay divergence at a custom operation for what it is.
///
/// The bare trace error says "operation N did not match"; for a custom op the
/// interesting fact is *which* part of the guest's question changed — the op
/// class (`label`) or the logical input (`key`) — because the answer the
/// recording holds is only valid for the exact question that produced it. Same
/// contract as the replayed `--env` reconcile: the trace is authoritative, and a
/// guest asking something else is refused rather than handed a stale answer.
///
/// A `key` is arbitrary guest bytes, so it is rendered as UTF-8 when it is text
/// (the SDK's serde encoding is) and as a byte count otherwise, never as lossy
/// text that would misreport what was compared.
fn classify_custom_op_divergence(label: &str, key: &[u8], error: RuntimeError) -> RuntimeError {
    let RuntimeError::Trace(error) = error else {
        return error;
    };
    let show = |bytes: &[u8]| match std::str::from_utf8(bytes) {
        Ok(text) => format!("{text:?}"),
        Err(_) => format!("<{} non-UTF-8 bytes>", bytes.len()),
    };
    let recorded = match &error {
        TraceError::OperationMismatch { expected, .. } => match expected.as_ref() {
            Operation::CustomOp {
                label: recorded_label,
                key: recorded_key,
            } => {
                if recorded_label != label {
                    format!(
                        "the recording expects custom op {recorded_label:?} at this point, not \
{label:?}"
                    )
                } else {
                    format!(
                        "the recording holds key {} for custom op {label:?}, but this run asked \
with {}",
                        show(recorded_key),
                        show(key)
                    )
                }
            }
            other => format!(
                "the recording expects a different operation entirely at this point: {other:?}"
            ),
        },
        TraceError::ReplayExhausted { .. } => {
            "the recording ended before this custom op; the run performed one the recording does \
not have"
                .to_string()
        }
        _ => return error.into(),
    };
    RuntimeError::CustomOp {
        label: label.to_string(),
        detail: format!(
            "custom op {label:?} diverged on replay: {recorded}. A recorded result answers exactly \
one question, so the trace is authoritative and a changed label or key is refused rather than \
answered from the recording. Underlying trace error: {error}"
        ),
    }
}

impl Context {
    /// Announce a custom operation and learn whether to run it — the opening
    /// half of the custom-op ABI (`patina_custom_op_begin` in the native shim).
    ///
    /// `label` names the operation class and `key` is its logical input; both are
    /// recorded, so a replay asserts the guest asked the *same* question of the
    /// same class before handing back an answer. A mismatch in either refuses,
    /// naming the label — the trace is authoritative, exactly as it is for a
    /// replayed `--env` value.
    ///
    /// Every `begin` must be closed by exactly one [`Context::custom_op_record`]
    /// (on [`CustomOpMode::Record`]) or [`Context::custom_op_replay_result`] (on
    /// [`CustomOpMode::Replay`]). A second `begin` while one is open is refused:
    /// a nested custom op would record an inner event that replay — which never
    /// runs the outer `perform` — could never produce.
    ///
    /// `fault_eligible` is the guest's declaration that this operation has a
    /// failure shape it handles — the precondition for
    /// `--custom-op-fail-permille` to fire on it. Declaring eligibility does not
    /// itself inject anything: with the knob off (the default) an eligible call
    /// behaves exactly like an ineligible one.
    ///
    /// These three methods are the ABI shape the shim's custom-op doors lower
    /// to; the SDK's `patina_dst::custom_op` types the key and result on the
    /// guest side.
    pub fn custom_op_begin(
        &mut self,
        label: &str,
        key: &[u8],
        fault_eligible: bool,
    ) -> Result<CustomOpMode, RuntimeError> {
        if let Some(open) = self.custom_op.as_ref() {
            return Err(RuntimeError::CustomOp {
                label: label.to_string(),
                detail: format!(
                    "custom op {label:?} was begun while custom op {:?} is still open; a custom \
operation may not nest or be left unclosed, because replay does not run the outer `perform` and \
so could never reproduce the inner operation",
                    open.label
                ),
            });
        }
        let operation = Operation::CustomOp {
            label: label.to_string(),
            key: key.to_vec(),
        };
        let expected = self
            .replay_expected(&operation)
            .map_err(|error| classify_custom_op_divergence(label, key, error))?;
        let steps_at_begin = self.steps;
        match expected {
            Some((_, Outcome::Bytes(recorded))) => {
                let len = recorded.len();
                self.custom_op = Some(PendingCustomOp {
                    label: label.to_string(),
                    key: key.to_vec(),
                    steps_at_begin,
                    replay_result: Some(recorded),
                });
                Ok(CustomOpMode::Replay { len })
            }
            // A recorded fault. The trace is the authority and eligibility is
            // NOT re-consulted: whether this call site still declares a failure
            // shape is a property of the guest source, and replay reproduces the
            // run that happened, not the run this build would produce. What IS
            // checked is that the caller can accept one — a call site with no
            // declared failure has no error to return, so handing it a fault
            // would leave it to invent a value. Refuse instead.
            Some((_, Outcome::Error(_))) if fault_eligible => Ok(CustomOpMode::Fault),
            Some((_, Outcome::Error(_))) => {
                // The recording took a fault on a call that declared a failure
                // shape; this one declares none: the two runs made different
                // calls here.
                self.note_replay_divergence(Some("custom_op_fault_shape"));
                Err(RuntimeError::CustomOp {
                    detail: format!(
                        "custom op {label:?} was recorded as a seeded fault, but this call declares no \
failure shape; the recording cannot be reproduced by a guest that no longer handles the operation \
failing"
                    ),
                    label: label.to_string(),
                })
            }
            Some((_, outcome)) => Err(RuntimeError::InvalidOutcome {
                operation: Box::new(operation),
                outcome: Box::new(outcome),
            }),
            None => {
                if fault_eligible {
                    self.custom_op_report.eligible_ops += 1;
                    if self.draw_custom_op_fault(label) {
                        self.custom_op_report.faults_injected += 1;
                        self.complete(
                            operation,
                            Outcome::Error(EffectError::new(
                                ErrorCode::Interrupted,
                                "injected custom-op fault: the operation did not run",
                            )),
                        );
                        return Ok(CustomOpMode::Fault);
                    }
                }
                self.custom_op = Some(PendingCustomOp {
                    label: label.to_string(),
                    key: key.to_vec(),
                    steps_at_begin,
                    replay_result: None,
                });
                Ok(CustomOpMode::Record)
            }
        }
    }

    /// Draw the seeded failure decision for one fault-eligible custom operation.
    ///
    /// Each label draws from its own child stream, derived once from the
    /// custom-op fault domain seed and the label's hash, so two operation
    /// classes never share a coin and adding a call site to one class cannot
    /// shift the other's decisions. Extreme rates are decision-free, mirroring
    /// [`Context::draw_entropy_failure`], so the never-fail default perturbs no
    /// stream at all.
    fn draw_custom_op_fault(&mut self, label: &str) -> bool {
        match self.custom_op_fail_permille {
            0 => false,
            1000 => true,
            permille => {
                let root = self.custom_op_fault_root;
                let stream = self
                    .custom_op_fault_rngs
                    .entry(label.to_string())
                    .or_insert_with(|| {
                        SplitMix64::new(patina_dst_rng_seeded::splitmix_hash(&[
                            root,
                            patina_dst_rng_seeded::splitmix_hash_str(label),
                        ]))
                    });
                (stream.next_u64() % 1000) < u64::from(permille)
            }
        }
    }

    /// The end-of-run custom-op fault summary, or `None` when the knob was never
    /// live. Filled entirely by the Context: a custom operation is announced
    /// through [`Context::custom_op_begin`], so there is no driver to ask.
    ///
    /// Unlike the other planes this is `Some` even when nothing was eligible —
    /// that case is exactly the vacuity worth reporting (see
    /// [`patina_dst_driver_api::CustomOpFaultReport::is_vacuous`]).
    pub fn custom_op_fault_report(&self) -> Option<patina_dst_driver_api::CustomOpFaultReport> {
        if self.custom_op_fail_permille == 0 {
            return None;
        }
        let mut report = self.custom_op_report;
        report.fail_vacuity_diagnosable = patina_dst_driver_api::vacuity_is_diagnosable(
            report.eligible_ops,
            self.custom_op_fail_permille,
        );
        Some(report)
    }

    /// The length of the open custom operation's recorded result, or `None` when
    /// no operation is open or the open one is on the record path. A read-only
    /// peek: a `(pointer, capacity)` ABI caller uses it to refuse a short buffer
    /// *without* consuming the recorded result, so the call can be retried.
    pub fn custom_op_pending_len(&self) -> Option<usize> {
        self.custom_op
            .as_ref()?
            .replay_result
            .as_ref()
            .map(Vec::len)
    }

    /// Take the recorded result of the open custom operation, closing it. Only
    /// valid after a [`CustomOpMode::Replay`]; on a record pass there is no
    /// recorded answer and the call is refused rather than answered with
    /// something invented.
    pub fn custom_op_replay_result(&mut self) -> Result<Vec<u8>, RuntimeError> {
        let Some(pending) = self.custom_op.take() else {
            return Err(RuntimeError::CustomOp {
                label: String::new(),
                detail: "custom-op replay result requested with no custom operation open; every \
fetch must follow its own `begin`"
                    .into(),
            });
        };
        let label = pending.label;
        pending.replay_result.ok_or(RuntimeError::CustomOp {
            detail: format!(
                "custom op {label:?} asked for a recorded result on a pass that is not a replay; \
the record pass must run `perform` and report its bytes instead"
            ),
            label,
        })
    }

    /// Record what the guest's `perform` produced, closing the open custom
    /// operation and appending its trace event. Only valid after a
    /// [`CustomOpMode::Record`].
    ///
    /// Refuses if any modeled boundary operation ran between the two halves: the
    /// wrapped effect is supposed to be one Patina does *not* model, and a
    /// recorded operation inside `perform` yields a trace that cannot replay
    /// (replay skips `perform`, so it would never produce those events). Failing
    /// here names the cause; failing on replay would only report an operation
    /// mismatch at an unrelated-looking index.
    pub fn custom_op_record(&mut self, result: Vec<u8>) -> Result<(), RuntimeError> {
        let Some(pending) = self.custom_op.take() else {
            return Err(RuntimeError::CustomOp {
                label: String::new(),
                detail: "custom-op result reported with no custom operation open; every result \
must follow its own `begin`"
                    .into(),
            });
        };
        if pending.replay_result.is_some() {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "custom op {:?} reported a freshly performed result on a replay pass, where \
the recording is authoritative and `perform` must not run",
                    pending.label
                ),
                label: pending.label,
            });
        }
        let inner = self.steps - pending.steps_at_begin;
        if inner != 0 {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "custom op {:?} performed {inner} modeled boundary operation(s) inside its \
`perform`; a custom op must wrap an effect Patina does NOT model, because replay returns the \
recorded bytes without running `perform` and could never reproduce those operations",
                    pending.label
                ),
                label: pending.label,
            });
        }
        let operation = Operation::CustomOp {
            label: pending.label,
            key: pending.key,
        };
        self.complete(operation, Outcome::Bytes(result));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::RuntimeConfig;
    use crate::custom_op::CustomOpMode;
    use crate::{Context, EntropyWait, RuntimeError};
    use patina_dst_abi::{Operation, Outcome};

    use patina_dst_trace::TraceBundle;
    use tempfile::tempdir;

    /// One custom operation through the byte protocol the shim drives.
    fn op(
        context: &mut Context,
        label: &str,
        key: &[u8],
        perform: impl FnOnce() -> Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        match context.custom_op_begin(label, key, false)? {
            CustomOpMode::Replay { .. } => context.custom_op_replay_result(),
            CustomOpMode::Record => {
                let value = perform();
                context.custom_op_record(value.clone())?;
                Ok(value)
            }
            CustomOpMode::Fault => unreachable!("no failure was declared"),
        }
    }

    // The custom-op record/replay contract end to end at the runtime layer: the
    // typed entry records a `CustomOp` event carrying the encoded key and result,
    // and a replay returns the recorded value WITHOUT running `perform` — proven
    // by a replay `perform` that would panic the test if it ever ran.
    #[test]
    fn custom_op_records_its_result_and_replays_without_running_perform() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op.patina");

        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        let recorded = op(&mut context, "s3.get_object", b"bucket/key", || {
            b"alpha,beta".to_vec()
        })
        .unwrap();
        assert_eq!(recorded, b"alpha,beta");
        let count = op(&mut context, "host.pid", b"7", || b"4242".to_vec()).unwrap();
        assert_eq!(count, b"4242");
        context.finish().unwrap();

        // Both calls are trace events carrying the label and the encoded key.
        let bundle = TraceBundle::load(&trace).unwrap();
        let events: Vec<_> = bundle
            .resolved_timeline("main")
            .unwrap()
            .into_iter()
            .filter_map(|event| match event.operation {
                Operation::CustomOp { label, key } => Some((label, key, event.outcome)),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].0, "s3.get_object");
        assert_eq!(events[0].1, b"bucket/key".to_vec());
        assert_eq!(
            events[0].2,
            Outcome::Bytes(b"alpha,beta".to_vec()),
            "the recorded outcome is the guest's result bytes"
        );
        assert_eq!(events[1].0, "host.pid");

        // Replay: `perform` must not run, and the recorded values come back typed.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let replayed = op(&mut replay, "s3.get_object", b"bucket/key", || {
            panic!("replay must not run perform")
        })
        .unwrap();
        assert_eq!(replayed, recorded);
        let replayed_count = op(&mut replay, "host.pid", b"7", || {
            panic!("replay must not run perform")
        })
        .unwrap();
        assert_eq!(replayed_count, b"4242");
        replay.finish().unwrap();
    }

    // A replay may only be answered for the exact question the recording holds:
    // a changed key, and a changed label, each refuse and name the label.
    #[test]
    fn custom_op_replay_refuses_a_changed_key_or_label_naming_the_label() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-key.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        op(&mut context, "dns.lookup", b"example.com", || b"1".to_vec()).unwrap();
        context.finish().unwrap();

        // Same label, different key.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let error = op(
            &mut replay,
            "dns.lookup",
            b"elsewhere.com",
            || unreachable!(),
        )
        .expect_err("a changed key must be refused");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "dns.lookup"),
            "{error:?}"
        );

        // Same key, different label.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let error = op(
            &mut replay,
            "dns.reverse",
            b"example.com",
            || unreachable!(),
        )
        .expect_err("a changed label must be refused");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "dns.reverse"),
            "{error:?}"
        );

        // The clean replay still works, so the two refusals above are not a
        // trace that simply cannot be replayed at all.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let value = op(&mut replay, "dns.lookup", b"example.com", || unreachable!()).unwrap();
        assert_eq!(value, b"1");
        replay.finish().unwrap();
    }

    // A `perform` that touches an effect Patina DOES model produces a trace that
    // replay could never reproduce (replay skips `perform`). Caught at record
    // time, naming the label and the count, instead of surfacing later as an
    // unexplained operation mismatch.
    #[test]
    fn custom_op_refuses_a_perform_that_performed_modeled_operations() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-inner.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        assert_eq!(
            context.custom_op_begin("wrapped.fs", b"k", false).unwrap(),
            CustomOpMode::Record
        );
        context.entropy_bytes(4, EntropyWait::UntilReady).unwrap();
        let error = context
            .custom_op_record(b"result".to_vec())
            .expect_err("a modeled operation inside perform must be refused");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "wrapped.fs"),
            "{error:?}"
        );
    }

    // The protocol's own invariants: no nesting, no unclosed operation, no
    // fetching a recorded result on a record pass.
    #[test]
    fn custom_op_protocol_misuse_is_refused_rather_than_recorded() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-misuse.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        context.custom_op_begin("outer", b"k", false).unwrap();
        let error = context
            .custom_op_begin("inner", b"k", false)
            .expect_err("a nested custom op must be refused");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "inner"),
            "{error:?}"
        );
        // A record pass has no recorded answer to hand back.
        let error = context
            .custom_op_replay_result()
            .expect_err("a record pass has no recorded result");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "outer"),
            "{error:?}"
        );

        // ... and the still-open operation is refused at finish rather than
        // silently leaving the trace short one event.
        let unclosed = directory.path().join("custom-op-unclosed.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &unclosed, "fp")).unwrap();
        context
            .custom_op_begin("never-closed", b"k", false)
            .unwrap();
        let error = context.finish().expect_err("an open custom op must refuse");
        assert!(
            matches!(&error, RuntimeError::CustomOp { label, .. } if label == "never-closed"),
            "{error:?}"
        );

        // Closing with no operation open is equally refused.
        let mut context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        assert!(context.custom_op_record(Vec::new()).is_err());
        assert!(context.custom_op_replay_result().is_err());
    }
}
