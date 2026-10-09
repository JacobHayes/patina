//! Clock and entropy effects and their seeded faults.

use crate::recording::{decode_bytes, decode_u64, decode_unit};
use crate::{Context, RuntimeError};
use patina_dst_abi::{ClockKind, EffectError, ErrorCode, Operation, Outcome};

impl Context {
    pub fn entropy_bytes(&mut self, len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.entropy.is_none() {
            return Err(EffectError::missing_driver("entropy").into());
        }
        let operation = Operation::EntropyFill { len };
        if let Some((_, recorded)) = self.replay_expected(&operation)? {
            return decode_bytes(&operation, recorded);
        }

        self.entropy_report.requests += 1;
        let outcome = match self.draw_entropy_failure() {
            Some(error) => {
                self.entropy_report.failures_injected += 1;
                Outcome::Error(error)
            }
            None => {
                let mut bytes = vec![0; len];
                let result = self
                    .entropy
                    .as_mut()
                    .expect("driver was checked")
                    .fill(&mut bytes);
                match result {
                    Ok(()) => Outcome::Bytes(bytes),
                    Err(error) => Outcome::Error(error),
                }
            }
        };
        let outcome = self.complete(operation.clone(), outcome);
        decode_bytes(&operation, outcome)
    }

    /// Draw the seeded entropy-request failure for one eligible call, or `None`
    /// when the knob does not fire. Extreme rates are decision-free so the
    /// never-fail default perturbs no stream, mirroring [`Context::draw_dns_failure`].
    fn draw_entropy_failure(&mut self) -> Option<EffectError> {
        let fires = match self.entropy_fail_permille {
            0 => false,
            1000 => true,
            permille => (self.entropy_fault_rng.next_u64() % 1000) < u64::from(permille),
        };
        fires.then(|| {
            EffectError::new(
                ErrorCode::Interrupted,
                "injected entropy failure: request did not complete",
            )
        })
    }

    /// The end-of-run entropy fault summary, or `None` when the knob was never
    /// live. Filled entirely by the Context: entropy has no driver-side fault
    /// model of its own.
    pub fn entropy_fault_report(&self) -> Option<patina_dst_driver_api::EntropyFaultReport> {
        if self.entropy_fail_permille == 0 {
            return None;
        }
        let mut report = self.entropy_report;
        report.fail_vacuity_diagnosable = patina_dst_driver_api::vacuity_is_diagnosable(
            report.requests,
            self.entropy_fail_permille,
        );
        Some(report)
    }

    pub fn now(&mut self, clock: ClockKind) -> Result<u64, RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        let operation = Operation::ClockNow { clock };
        let outcome = match self.replay_expected(&operation)? {
            // The time model cross-check: replay re-derives the monotonic
            // clock from the same charges and idle advances, so its value
            // must be the recorded one. A difference is a charge one side
            // made and the other did not, named here rather than surfacing
            // later as a different expiry.
            Some((sequence, recorded)) if clock == ClockKind::Monotonic => {
                let derived = self.current_monotonic()?;
                if recorded != Outcome::U64(derived) {
                    return Err(RuntimeError::TimeModel {
                        detail: format!(
                            "replay diverged from the time model at operation {sequence}: the \
recording read the monotonic clock as {recorded:?}, the replay's charges and idle advances derive \
{derived}"
                        ),
                    });
                }
                recorded
            }
            Some((_, recorded)) => recorded,
            None => {
                let result = self.clock.as_mut().expect("driver was checked").now(clock);
                let outcome = match result {
                    Ok(nanos) => {
                        let nanos = match clock {
                            ClockKind::Realtime => self.apply_epoch_jump(nanos),
                            ClockKind::Monotonic => nanos,
                        };
                        Outcome::U64(nanos)
                    }
                    Err(error) => Outcome::Error(error),
                };
                self.complete(operation.clone(), outcome)
            }
        };
        // A poll that completes a streak is escalated after its observation.
        self.escalate_due()?;
        decode_u64(&operation, outcome)
    }

    /// Perturb one realtime-epoch read with a seeded signed offset in `[-hi,
    /// hi]`, saturating at 0 (no negative epochs). Draws from its own
    /// domain-separated stream ([`fault_domain::EPOCH_JUMP`]), never the clock
    /// driver's own state, so a knob-off run is unperturbed and arming the knob
    /// never correlates with any other fault plane. No cumulative walk: the
    /// result is a pure function of this one draw and the true epoch, so a jump
    /// on one read never carries into the next. The perturbed value flows
    /// through the same recorded [`Operation::ClockNow`]/[`Outcome::U64`] every
    /// epoch read already uses, so replay reproduces it without redrawing.
    fn apply_epoch_jump(&mut self, true_epoch_nanos: u64) -> u64 {
        self.clock_report.reads += 1;
        let hi = match self.epoch_jump_nanos {
            0 => return true_epoch_nanos,
            hi => hi,
        };
        // u128 throughout: `hi` is an unconstrained CLI-supplied u64, so a span
        // of `2*hi + 1` could overflow u64 for a `hi` near its max.
        let span = 2u128 * u128::from(hi) + 1;
        let draw = u128::from(self.epoch_jump_rng.next_u64()) % span;
        let offset = draw as i128 - i128::from(hi); // in [-hi, hi]
        let perturbed = i128::from(true_epoch_nanos) + offset;
        let perturbed = perturbed.clamp(0, i128::from(u64::MAX)) as u64;
        if perturbed != true_epoch_nanos {
            self.clock_report.jumps_applied += 1;
        }
        perturbed
    }

    /// The end-of-run clock (epoch-jump) fault summary, or `None` when the knob
    /// was never live. Filled entirely by the Context: every realtime-epoch read
    /// is a single-site operation, so there is no driver-side fault model of its
    /// own.
    pub fn clock_fault_report(&self) -> Option<patina_dst_driver_api::ClockFaultReport> {
        if self.epoch_jump_nanos == 0 {
            return None;
        }
        let mut report = self.clock_report;
        report.jump_vacuity_diagnosable = patina_dst_driver_api::epoch_jump_vacuity_is_diagnosable(
            report.reads,
            self.epoch_jump_nanos,
        );
        Some(report)
    }

    /// Sleep until `deadline_nanos`. Plain: latency jitter is applied by the
    /// caller through [`Context::apply_sleep_jitter`] so that the single
    /// guest-sleep entry point (which may park managed tasks rather than route
    /// through this method) jitters exactly once, while runtime-internal sleeps
    /// (the deadlock-rescue advancing to a timer) never do.
    pub fn sleep_until(
        &mut self,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<(), RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        let operation = Operation::SleepUntil {
            clock,
            deadline_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let before = self.current_monotonic()?;
        let result = self
            .clock
            .as_mut()
            .expect("driver was checked")
            .sleep_until(clock, deadline_nanos);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)?;
        // An idle advance: no task computes through it. It covers charged
        // time the clock had yet to show (that work came before the wait),
        // and a guest that waited ends its poll episode.
        let idle = self.current_monotonic()?.saturating_sub(before);
        if idle > 0 {
            self.charges.absorb_idle(idle);
            self.spin.end_episode();
        }
        self.expire_due_timers()
    }

    /// Add the configured seeded sleep-latency jitter to an absolute sleep
    /// deadline, returning it unchanged when latency injection is off. Drawn from
    /// a domain-separated seeded stream so the inflation is deterministic per seed
    /// and reproduced on replay. A single decision-free range value consumes no
    /// draw. The embedder applies this once, at the guest-facing sleep entry,
    /// before parking a managed task or calling [`Context::sleep_until`].
    pub fn apply_sleep_jitter(&mut self, deadline_nanos: u64) -> u64 {
        let jitter = match self.sleep_jitter_nanos {
            None => return deadline_nanos,
            Some((min, max)) if min == max => min,
            Some((min, max)) => {
                let span = max - min + 1;
                min + (self.sleep_jitter_rng.next_u64() % span)
            }
        };
        deadline_nanos.saturating_add(jitter)
    }

    pub fn sleep_for(&mut self, duration_nanos: u64) -> Result<(), RuntimeError> {
        let now = self.now(ClockKind::Monotonic)?;
        let deadline = now.saturating_add(duration_nanos);
        // Direct-API sleeps jitter here (the native embedder jitters at its own
        // sleep entry instead); either way a guest sleep is jittered exactly once.
        let deadline = self.apply_sleep_jitter(deadline);
        self.sleep_until(ClockKind::Monotonic, deadline)
    }

    /// The current monotonic virtual time in nanoseconds, UNRECORDED. A
    /// readiness reactor (the native shim's `kqueue`/`kevent`) compares
    /// `EVFILT_TIMER` deadlines against it every scan; recording those reads
    /// would emit a `ClockNow` op per poll and diverge record from replay. Safe
    /// because virtual time only advances through recorded `SleepUntil`s and
    /// the charges of the guest's own calls, so a bare read reproduces
    /// identically (see [`Self::current_monotonic`]).
    pub fn monotonic_now_unrecorded(&mut self) -> Result<u64, RuntimeError> {
        self.current_monotonic()
    }
}
