//! A worker thread and the shared exactly-once accumulator it applies into.
//! Under redelivery two workers can process the same job at once, so the
//! applied-id guard is what the deterministic scheduler stress-tests.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::server::Bug;
use crate::wire::{Msg, Outcome};

/// The shared completion set whose correctness would race without the
/// deterministic scheduler.
#[derive(Default)]
pub struct Accumulator {
    /// Job ids already applied — the load-bearing dedup set.
    applied: BTreeSet<u64>,
    /// Applies that actually ran; must equal `applied.len()`, or a double-apply
    /// slipped past the guard.
    ran: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    Applied,
    Duplicate,
}

impl Accumulator {
    /// Apply a job's effect exactly once; a repeat id is a no-op `Duplicate`.
    pub fn apply(&mut self, job_id: u64) -> ApplyResult {
        if self.applied.insert(job_id) {
            self.ran += 1;
            ApplyResult::Applied
        } else {
            ApplyResult::Duplicate
        }
    }

    pub fn applied_ids(&self) -> &BTreeSet<u64> {
        &self.applied
    }

    /// Record an apply whose "already applied?" check ran earlier, OUTSIDE this
    /// lock. `ran` is bumped unconditionally, so if the racing check let two
    /// duplicate deliveries through, `ran` outruns `applied` and the exactly-once
    /// invariant trips. Used only by `apply-check-outside-lock`.
    pub fn apply_unchecked(&mut self, job_id: u64) {
        self.applied.insert(job_id);
        self.ran += 1;
    }

    /// A failure here means a double-apply slipped past the exactly-once guard.
    pub fn verify_internal(&self) -> Result<(), String> {
        if self.ran as usize != self.applied.len() {
            return Err(format!(
                "{} applies but {} distinct jobs (double-apply)",
                self.ran,
                self.applied.len()
            ));
        }
        Ok(())
    }
}

pub type AccumulatorHandle = Arc<Mutex<Accumulator>>;

pub struct WorkerSpec {
    pub id: u32,
    pub server: SocketAddr,
    pub accumulator: AccumulatorHandle,
    pub shutdown: Arc<AtomicBool>,
    pub poll_timeout: Duration,
    pub backoff: Duration,
    pub bug: Bug,
}

/// Bound on Complete re-sends before giving up; the visibility timeout then
/// redelivers the job (e.g. across a server-crash gap).
const MAX_COMPLETE_RETRIES: u32 = 64;

pub fn run(spec: WorkerSpec) {
    let socket = match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))) {
        Ok(socket) => socket,
        Err(error) => return eprintln!("worker {}: bind failed: {error}", spec.id),
    };
    let _ = socket.set_read_timeout(Some(spec.poll_timeout));
    let mut buffer = [0u8; 512];

    while !spec.shutdown.load(Ordering::Relaxed) {
        Msg::Poll(spec.id).send(&socket, spec.server);
        match Msg::recv(&socket, &mut buffer) {
            Some(Msg::Assign(job_id, work, _)) => {
                process(&spec, &socket, &mut buffer, job_id, work)
            }
            Some(Msg::PollEmpty) => std::thread::sleep(spec.backoff),
            _ => {} // stale reply or timeout: poll again
        }
    }
}

fn process(spec: &WorkerSpec, socket: &UdpSocket, buffer: &mut [u8], job_id: u64, work: u64) {
    // Cooperative fault: decline the job, driving the terminal-fail path.
    if patina_dst::buggify!("job-fail") {
        return deliver_complete(spec, socket, buffer, job_id, Outcome::Fail);
    }
    if spec.bug == Bug::ApplyCheckOutsideLock {
        apply_check_outside_lock(spec, job_id, work);
    } else {
        // The clean guard: the check, the apply, and the window-widening sleep
        // all run under ONE lock hold (the guard lives through the whole match).
        match spec.accumulator.lock().unwrap().apply(job_id) {
            ApplyResult::Applied => std::thread::sleep(Duration::from_millis((work % 5) + 1)),
            ApplyResult::Duplicate => patina_dst::sometimes!(true, "dedup-suppressed-double-apply"),
        }
    }
    deliver_complete(spec, socket, buffer, job_id, Outcome::Success);
}

/// The `apply-check-outside-lock` bug: the "already applied?" check runs OUTSIDE
/// the apply critical section and the lock is dropped before the record, so two
/// workers holding duplicate deliveries of one job both pass the check and each
/// record an apply — a double-apply the exactly-once invariant catches.
fn apply_check_outside_lock(spec: &WorkerSpec, job_id: u64, work: u64) {
    if spec
        .accumulator
        .lock()
        .unwrap()
        .applied_ids()
        .contains(&job_id)
    {
        return patina_dst::sometimes!(true, "dedup-suppressed-double-apply");
    }
    // Lock dropped above; this sleep is the check-then-act window a concurrent
    // duplicate delivery races through before either apply is recorded.
    std::thread::sleep(Duration::from_millis((work % 5) + 1));
    spec.accumulator.lock().unwrap().apply_unchecked(job_id);
}

/// Send Complete and await its ack, retrying on loss up to a bound.
fn deliver_complete(
    spec: &WorkerSpec,
    socket: &UdpSocket,
    buffer: &mut [u8],
    job_id: u64,
    outcome: Outcome,
) {
    for _ in 0..MAX_COMPLETE_RETRIES {
        if spec.shutdown.load(Ordering::Relaxed) {
            return;
        }
        Msg::Complete(spec.id, job_id, outcome).send(socket, spec.server);
        loop {
            match Msg::recv(socket, buffer) {
                Some(Msg::CompleteAck(acked)) if acked == job_id => return,
                Some(_) => continue, // stale datagram
                None => break,       // timeout: resend
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_applies_each_job_at_most_once() {
        let mut acc = Accumulator::default();
        assert_eq!(acc.apply(1), ApplyResult::Applied);
        assert_eq!(acc.apply(2), ApplyResult::Applied);
        assert_eq!(acc.apply(1), ApplyResult::Duplicate); // redelivery suppressed
        assert_eq!(acc.applied_ids().len(), 2);
        acc.verify_internal().unwrap();
    }
}
