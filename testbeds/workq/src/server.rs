//! The queue server: one thread owning the WAL and the in-memory queue state,
//! serving enqueue/poll/complete over a single UDP socket. Every durable fact
//! goes through the WAL before it is acked, so an acked job always survives
//! crash-recovery. Delivery is at-least-once; the workers' shared accumulator
//! makes the effect exactly-once on top of that.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::wal::{Durability, FailClosed, Wal, WalError};
use crate::wire::{Msg, Outcome, WalRecord};

/// The server's observable counts, republished each tick; the driver reads them
/// to decide convergence, and they reset across a restart.
#[derive(Clone, Default)]
pub struct ServerObservation {
    pub alive: bool,
    pub enqueued: u64,
    pub completed: u64,
    pub failed: u64,
    pub attempts: u64, // total deliveries handed out — kept OUT of the outcome hash
}

impl ServerObservation {
    pub fn converged(&self, target: u64) -> bool {
        self.enqueued == target && self.completed + self.failed == target
    }
}

pub type ObservationHandle = Arc<Mutex<ServerObservation>>;

/// A deliberately seeded bug, off by default (`--bug`). Each is a subtle,
/// plausible mistake that an EXISTING invariant catches — not a demo assertion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bug {
    None,
    /// Dedup keyed on `client_seq` alone: two producers that share a client_seq
    /// collide, so the second job is never enqueued and the run cannot converge.
    DedupIgnoreProducer,
    /// A redelivered job (attempt > 1) is acked + marked done in memory but its
    /// durable Complete record is skipped, so the log loses an acked completion.
    SkipRedeliveryCommit,
    /// The worker's exactly-once "already applied?" check happens OUTSIDE the
    /// mutex-held apply critical section, so two workers holding duplicate
    /// deliveries of one job can both pass the check and double-apply it.
    ApplyCheckOutsideLock,
    /// The WAL append path issues one raw `write()` and ignores the returned
    /// count instead of looping to completion. Under `--fs-short-permille` a
    /// frame's tail is silently dropped; recovery then truncates at the torn
    /// frame and the durability invariant (acked job present in the WAL) fires.
    IgnoreShortWrite,
}

impl Bug {
    pub const NAMES: &'static [&'static str] = &[
        "dedup-ignore-producer",
        "skip-redelivery-commit",
        "apply-check-outside-lock",
        "ignore-short-write",
    ];
    pub fn parse(name: &str) -> Option<Bug> {
        match name {
            "dedup-ignore-producer" => Some(Bug::DedupIgnoreProducer),
            "skip-redelivery-commit" => Some(Bug::SkipRedeliveryCommit),
            "apply-check-outside-lock" => Some(Bug::ApplyCheckOutsideLock),
            "ignore-short-write" => Some(Bug::IgnoreShortWrite),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub dir: PathBuf,
    pub segment_bytes: u64,
    pub max_attempts: u32,
    pub visibility: Duration,
    pub tick: Duration,
    pub bug: Bug,
}

/// Everything a server thread needs; all `Send`, built on the spawning side.
/// `failure` is set only on a fail-closed WAL error, so the driver can tell that
/// apart from a cooperative stop or a deliberate crash.
pub struct ServerSpec {
    pub config: ServerConfig,
    pub shutdown: Arc<AtomicBool>,
    pub crash: Arc<AtomicBool>,
    pub observation: ObservationHandle,
    pub failure: Arc<Mutex<Option<FailClosed>>>,
}

/// Per-job in-memory state (durable client facts live in the WAL).
struct Job {
    work: u64,
    status: Status,
    attempts: u32,
    /// This job's Enqueue seq, and whether it is fsync'd — the ack is withheld
    /// until `durable`.
    enqueue_seq: u64,
    durable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Ready,
    InFlight { deadline: Instant },
    Completed,
    Failed,
}

impl Status {
    fn terminal(self) -> bool {
        matches!(self, Status::Completed | Status::Failed)
    }
}

struct Queue {
    cfg: ServerConfig,
    wal: Wal,
    jobs: BTreeMap<u64, Job>,
    /// (producer, client_seq) -> job_id; the producer is dropped from the key
    /// under the `dedup-ignore-producer` bug.
    dedup: HashMap<(u32, u64), u64>,
    ready: VecDeque<u64>,
    next_job_id: u64,
    enqueued: u64,
    completed: u64,
    failed: u64,
    attempts_total: u64,
}

impl Queue {
    /// Open the WAL (recovering prior segments) and rebuild the queue; a
    /// fail-closed corruption surfaces as `WalError`.
    fn open(cfg: ServerConfig) -> Result<Self, WalError> {
        let (wal, records) = Wal::open(
            &cfg.dir,
            cfg.segment_bytes,
            cfg.bug == Bug::IgnoreShortWrite,
        )?;
        let mut q = Queue {
            cfg,
            wal,
            jobs: BTreeMap::new(),
            dedup: HashMap::new(),
            ready: VecDeque::new(),
            next_job_id: 1,
            enqueued: 0,
            completed: 0,
            failed: 0,
            attempts_total: 0,
        };
        for framed in records {
            match framed.record {
                WalRecord::Enqueue(job_id, producer, client_seq, _key, work) => {
                    let dk = q.dedup_key(producer, client_seq);
                    let job = Job {
                        work,
                        status: Status::Ready,
                        attempts: 0,
                        enqueue_seq: framed.seq,
                        durable: true,
                    };
                    q.jobs.insert(job_id, job);
                    q.dedup.insert(dk, job_id);
                    q.next_job_id = q.next_job_id.max(job_id + 1);
                    q.enqueued += 1;
                }
                WalRecord::Complete(job_id) => q.recover_terminal(job_id, Status::Completed),
                WalRecord::Fail(job_id) => q.recover_terminal(job_id, Status::Failed),
            }
        }
        // Recovery resets in-flight leases: everything Ready re-enters the queue.
        let ready: Vec<u64> = q
            .jobs
            .iter()
            .filter(|(_, j)| j.status == Status::Ready)
            .map(|(id, _)| *id)
            .collect();
        q.ready.extend(ready);
        Ok(q)
    }

    /// The `dedup-ignore-producer` bug collapses the producer out of the key.
    fn dedup_key(&self, producer: u32, client_seq: u64) -> (u32, u64) {
        if self.cfg.bug == Bug::DedupIgnoreProducer {
            (0, client_seq)
        } else {
            (producer, client_seq)
        }
    }

    fn recover_terminal(&mut self, job_id: u64, status: Status) {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            if !job.status.terminal() {
                match status {
                    Status::Completed => self.completed += 1,
                    Status::Failed => self.failed += 1,
                    _ => {}
                }
            }
            job.status = status;
        }
    }

    /// The single terminal-fail site, so `job-failed` has exactly one label.
    fn fail_job(&mut self, id: u64) -> Result<(), WalError> {
        self.wal.append(&WalRecord::Fail(id))?;
        if let Some(job) = self.jobs.get_mut(&id) {
            job.status = Status::Failed;
        }
        self.failed += 1;
        patina_dst::sometimes!(true, "job-failed");
        Ok(())
    }

    fn handle_enqueue(
        &mut self,
        socket: &UdpSocket,
        producer: u32,
        client_seq: u64,
        key: u32,
        work: u64,
        from: SocketAddr,
    ) -> Result<(), WalError> {
        let dk = self.dedup_key(producer, client_seq);
        let job_id = match self.dedup.get(&dk) {
            Some(&id) => id,
            None => {
                let id = self.next_job_id;
                self.next_job_id += 1;
                let (seq, durable) = match self
                    .wal
                    .append(&WalRecord::Enqueue(id, producer, client_seq, key, work))?
                {
                    Durability::Durable { seq } => (seq, true),
                    Durability::Deferred { seq } => (seq, false),
                };
                self.jobs.insert(
                    id,
                    Job {
                        work,
                        status: Status::Ready,
                        attempts: 0,
                        enqueue_seq: seq,
                        durable,
                    },
                );
                self.dedup.insert(dk, id);
                self.ready.push_back(id);
                if durable {
                    self.enqueued += 1;
                }
                id
            }
        };
        // Ack ONLY a durable job. A deferred (fsync-skipped) enqueue is left
        // unacked; the producer retries and a later flush makes it durable.
        if self.jobs[&job_id].durable && !patina_dst::buggify!("enqueue-ack-drop") {
            Msg::EnqueueAck(producer, client_seq, job_id).send(socket, from);
        }
        Ok(())
    }

    fn handle_poll(&mut self, socket: &UdpSocket, from: SocketAddr) -> Result<(), WalError> {
        let now = Instant::now();
        loop {
            let Some(id) = self.ready.pop_front() else {
                Msg::PollEmpty.send(socket, from);
                return Ok(());
            };
            if self.jobs.get(&id).map(|j| j.status) != Some(Status::Ready) {
                continue; // stale ready entry
            }
            if self.jobs[&id].attempts >= self.cfg.max_attempts {
                self.fail_job(id)?; // exhausted without completing
                continue;
            }
            // Cooperative fault: an early lease forces redelivery with no packet
            // loss, exercising the exactly-once dedup.
            let lease = if patina_dst::buggify!("early-redelivery") {
                Duration::from_millis(1)
            } else {
                self.cfg.visibility
            };
            let job = self.jobs.get_mut(&id).unwrap();
            job.attempts += 1;
            job.status = Status::InFlight {
                deadline: now + lease,
            };
            let (attempt, work) = (job.attempts, job.work);
            self.attempts_total += 1;
            patina_dst::sometimes!(attempt > 1, "redelivery-observed");
            Msg::Assign(id, work, attempt).send(socket, from);
            return Ok(());
        }
    }

    fn handle_complete(
        &mut self,
        socket: &UdpSocket,
        job_id: u64,
        outcome: Outcome,
        from: SocketAddr,
    ) -> Result<(), WalError> {
        let Some(status) = self.jobs.get(&job_id).map(|j| j.status) else {
            return Ok(()); // unknown job id
        };
        if status.terminal() {
            Msg::CompleteAck(job_id).send(socket, from); // idempotent re-ack
            return Ok(());
        }
        match outcome {
            Outcome::Success => {
                // BUG (skip-redelivery-commit): a job that was ever redelivered
                // skips its durable Complete record, wrongly assuming an earlier
                // delivery already logged it.
                let redelivered = self.jobs[&job_id].attempts > 1;
                let skip = self.cfg.bug == Bug::SkipRedeliveryCommit && redelivered;
                if !skip {
                    self.wal.append(&WalRecord::Complete(job_id))?;
                }
                self.jobs.get_mut(&job_id).unwrap().status = Status::Completed;
                self.completed += 1;
                // Cooperative fault: drop the ack — the completion is recorded, so
                // the worker's retry is harmless.
                if !patina_dst::buggify!("complete-ack-drop") {
                    Msg::CompleteAck(job_id).send(socket, from);
                }
            }
            Outcome::Fail => {
                // Declined: requeue, or fail it once out of attempts.
                if self.jobs[&job_id].attempts >= self.cfg.max_attempts {
                    self.fail_job(job_id)?;
                } else {
                    let job = self.jobs.get_mut(&job_id).unwrap();
                    job.status = Status::Ready;
                    self.ready.push_back(job_id);
                }
                Msg::CompleteAck(job_id).send(socket, from);
            }
        }
        Ok(())
    }

    /// Per-tick: promote now-durable deferred enqueues, expire visibility leases,
    /// assert the safety invariant, and publish the snapshot.
    fn tick(&mut self, observation: &ObservationHandle) -> Result<(), WalError> {
        let durable = self.wal.flush()?;
        for job in self.jobs.values_mut() {
            if !job.durable && job.enqueue_seq <= durable {
                job.durable = true; // the producer's next retry will now be acked
                self.enqueued += 1;
            }
        }

        let now = Instant::now();
        let expired: Vec<u64> = self
            .jobs
            .iter()
            .filter_map(|(id, j)| match j.status {
                Status::InFlight { deadline } if deadline <= now => Some(*id),
                _ => None,
            })
            .collect();
        for id in expired {
            if self.jobs[&id].attempts >= self.cfg.max_attempts {
                self.fail_job(id)?;
            } else {
                let job = self.jobs.get_mut(&id).unwrap();
                job.status = Status::Ready;
                self.ready.push_back(id);
            }
        }

        // Core safety invariant: terminated jobs never exceed enqueued jobs.
        patina_dst::always!(
            self.completed + self.failed <= self.enqueued,
            "terminal-le-enqueued"
        );

        *observation.lock().unwrap() = ServerObservation {
            alive: true,
            enqueued: self.enqueued,
            completed: self.completed,
            failed: self.failed,
            attempts: self.attempts_total,
        };
        Ok(())
    }
}

/// Run one server incarnation, recording a fail-closed WAL error into `failure`.
pub fn run(spec: ServerSpec) {
    let observation = spec.observation.clone();
    let failure = spec.failure.clone();
    if let Err(error) = run_inner(spec) {
        *failure.lock().unwrap() = Some(FailClosed::from(&error));
    }
    observation.lock().unwrap().alive = false;
}

fn run_inner(spec: ServerSpec) -> Result<(), WalError> {
    let ServerSpec {
        config,
        shutdown,
        crash,
        observation,
        failure: _,
    } = spec;
    let mut queue = Queue::open(config.clone())?;
    let socket = UdpSocket::bind(config.bind)?;
    socket.set_nonblocking(true)?;
    let mut buffer = [0u8; 512];

    loop {
        if crash.load(Ordering::Relaxed) {
            // Deliberate crash: drop in-memory state WITHOUT flushing; the WAL
            // keeps whatever was fsync'd and recovery rebuilds from it.
            return Ok(());
        }
        if shutdown.load(Ordering::Relaxed) {
            queue.wal.flush()?;
            return Ok(());
        }
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, from)) => match Msg::decode(&buffer[..len]) {
                    Some(Msg::Enqueue(producer, client_seq, key, work)) => {
                        queue.handle_enqueue(&socket, producer, client_seq, key, work, from)?
                    }
                    Some(Msg::Poll(_)) => queue.handle_poll(&socket, from)?,
                    Some(Msg::Complete(_, job_id, outcome)) => {
                        queue.handle_complete(&socket, job_id, outcome, from)?
                    }
                    _ => {} // undecodable, or a reply variant the server never receives
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(WalError::Io(e)),
            }
        }
        queue.tick(&observation)?;
        std::thread::sleep(config.tick);
    }
}
