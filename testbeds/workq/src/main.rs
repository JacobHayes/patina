//! workq — a single-process durable work queue exercised end to end under Patina.
//! One process runs a WAL-backed **server**, **worker** threads that poll and
//! process jobs, and **producer** threads that enqueue a seeded workload, all over
//! loopback UDP + append-only WAL segments on the virtual clock. The app has no
//! fault code of its own; every drop, jitter, fs-crash, and buggify fault comes
//! from Patina and the seed. A self-checked invariant breach prints
//! `WORKQ_VIOLATION` (exit 1); a fail-closed recovery abort prints `WORKQ_ABORT`
//! (exit 2).
//!
//! Two determinism properties: per-platform **schedule determinism** (one
//! `(seed, binary)` replays byte-for-byte, so trace hashes are platform-local),
//! and cross-platform **outcome invariance** — `WORKQ_RESULT applied_hash` is an
//! order-forced digest over each job's schedule-invariant client identity
//! `(producer, client_seq)`, terminal state, and derived effect, so macOS and
//! Linux agree even though schedules differ.

mod producer;
mod server;
mod wal;
mod wire;
mod worker;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use producer::{AckedHandle, AckedLedger};
use server::{Bug, ServerConfig, ServerObservation, ServerSpec};
use wire::WalRecord;
use worker::{Accumulator, AccumulatorHandle};

/// A job that exhausts this many deliveries without completing is terminally
/// failed; a delivery is redelivered if not completed within the visibility lease.
const MAX_ATTEMPTS: u32 = 5;
const VISIBILITY: Duration = Duration::from_millis(200);

struct Options {
    seed: u64,
    jobs: u64,
    workers: u32,
    producers: u32,
    base_port: u16,
    data_dir: PathBuf,
    timeout: Duration,
    tick: Duration,
    segment_bytes: u64,
    /// Crash + recover the server once `completed` first reaches this (0 = never).
    crash_at_completed: u64,
    bug: Bug,
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("--check-recovery-fail-closed") {
        std::process::exit(run_recovery_selftest());
    }
    let options = parse_options(std::env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("error: {message}");
        eprintln!(
            "usage: workq [--seed N] [--jobs N] [--workers N] [--producers N] [--base-port N] \
             [--data-dir PATH] [--timeout-secs N] [--tick-ms N] [--segment-bytes N] \
             [--crash-at-completed N] [--bug NAME] | --check-recovery-fail-closed\n\
             valid --bug names: {}",
            Bug::NAMES.join(", ")
        );
        std::process::exit(2);
    });
    std::process::exit(orchestrate(options));
}

/// In-process fail-closed-recovery self-test: a clean log recovers, a torn tail
/// truncates, mid-log corruption aborts.
fn run_recovery_selftest() -> i32 {
    let scratch =
        std::env::temp_dir().join(format!("workq-recovery-selftest-{}", std::process::id()));
    match wal::recovery_fail_closed_selftest(&scratch) {
        Ok(()) => {
            println!("WORKQ_RECOVERY_SELFTEST ok clean+torn-tail-recovered mid-log-corruption-failed-closed");
            0
        }
        Err(detail) => {
            eprintln!("WORKQ_VIOLATION recovery-not-fail-closed {detail}");
            1
        }
    }
}

type ObservationHandle = Arc<Mutex<ServerObservation>>;

/// One server incarnation's handles + config, so it can be respawned on the
/// in-process crash-recovery path.
struct ServerSupervisor {
    config: ServerConfig,
    observation: ObservationHandle,
    crash: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    join: Option<JoinHandle<()>>,
    restarts: u32,
}

impl ServerSupervisor {
    fn spawn(config: ServerConfig, observation: ObservationHandle) -> Self {
        let mut sup = ServerSupervisor {
            config,
            observation,
            crash: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            failure: Arc::new(Mutex::new(None)),
            join: None,
            restarts: 0,
        };
        sup.spawn_thread();
        sup
    }

    fn spawn_thread(&mut self) {
        self.crash = Arc::new(AtomicBool::new(false));
        self.shutdown = Arc::new(AtomicBool::new(false));
        self.failure = Arc::new(Mutex::new(None));
        let spec = ServerSpec {
            config: self.config.clone(),
            shutdown: self.shutdown.clone(),
            crash: self.crash.clone(),
            observation: self.observation.clone(),
            failure: self.failure.clone(),
        };
        self.join = Some(std::thread::spawn(move || server::run(spec)));
    }

    fn failed(&self) -> Option<String> {
        self.failure.lock().unwrap().clone()
    }

    /// Crash the running server (drop its state, keep the WAL) and restart it on
    /// the same data dir.
    fn crash_and_restart(&mut self) {
        self.crash.store(true, Ordering::Relaxed);
        let _ = self.join.take().map(|h| h.join());
        *self.observation.lock().unwrap() = ServerObservation::default();
        self.spawn_thread();
        self.restarts += 1;
    }

    fn shutdown_and_join(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.join.take().map(|h| h.join());
    }
}

/// Requests for producer `id`, so the counts partition `jobs` and every producer
/// numbers its own client_seq from 0.
fn producer_count(jobs: u64, producers: u32, id: u32) -> u64 {
    jobs / producers as u64 + u64::from((id as u64) < jobs % producers as u64)
}

fn orchestrate(options: Options) -> i32 {
    let bind = SocketAddr::from(([127, 0, 0, 1], options.base_port));
    let config = ServerConfig {
        bind,
        dir: options.data_dir.clone(),
        segment_bytes: options.segment_bytes,
        max_attempts: MAX_ATTEMPTS,
        visibility: VISIBILITY,
        tick: options.tick,
        bug: options.bug,
    };

    let accumulator: AccumulatorHandle = Arc::new(Mutex::new(Accumulator::default()));
    let acked: AckedHandle = Arc::new(Mutex::new(AckedLedger::default()));
    let observation: ObservationHandle = Arc::new(Mutex::new(ServerObservation::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut supervisor = ServerSupervisor::spawn(config, observation.clone());

    let mut joins: Vec<JoinHandle<()>> = Vec::new();
    for id in 0..options.workers {
        let spec = worker::WorkerSpec {
            id,
            server: bind,
            accumulator: accumulator.clone(),
            shutdown: shutdown.clone(),
            poll_timeout: options.tick * 2,
            backoff: options.tick,
            bug: options.bug,
        };
        joins.push(std::thread::spawn(move || worker::run(spec)));
    }
    for id in 0..options.producers {
        let spec = producer::ProducerSpec {
            id,
            server: bind,
            seed: options.seed,
            count: producer_count(options.jobs, options.producers, id),
            acked: acked.clone(),
            shutdown: shutdown.clone(),
            retry_timeout: options.tick * 3,
        };
        joins.push(std::thread::spawn(move || producer::run(spec)));
    }

    patina_dst::lifecycle::setup_complete(); // setup/workload boundary
    let outcome = drive(&options, &mut supervisor, &observation);

    shutdown.store(true, Ordering::Relaxed);
    supervisor.shutdown_and_join();
    for handle in joins {
        let _ = handle.join();
    }

    match outcome {
        DriveOutcome::FailClosed(message) => {
            eprintln!("WORKQ_ABORT storage-fault {message}");
            2
        }
        DriveOutcome::Converged | DriveOutcome::TimedOut => {
            let converged = matches!(outcome, DriveOutcome::Converged);
            report(&options, &accumulator, &acked, &supervisor, converged)
        }
    }
}

enum DriveOutcome {
    Converged,
    TimedOut,
    /// The server's recovery hit corruption and failed closed.
    FailClosed(String),
}

/// Watch for convergence, fire the crash-recovery plan, and bail on a fail-closed
/// recovery error or the timeout.
fn drive(
    options: &Options,
    supervisor: &mut ServerSupervisor,
    observation: &ObservationHandle,
) -> DriveOutcome {
    let deadline = Instant::now() + options.timeout;
    let mut crashed = false;
    loop {
        if let Some(message) = supervisor.failed() {
            return DriveOutcome::FailClosed(message);
        }
        if Instant::now() >= deadline {
            return DriveOutcome::TimedOut;
        }
        let view = observation.lock().unwrap().clone();
        // Crash-recovery: once `completed` first reaches the trigger, crash the
        // server and restart it on the same WAL.
        if options.crash_at_completed > 0
            && !crashed
            && view.alive
            && view.completed >= options.crash_at_completed
        {
            supervisor.crash_and_restart();
            crashed = true;
            patina_dst::reachable!("recovery-completed");
            eprintln!(
                "driver: crashed + restarted the server at completed={} (incarnation #{})",
                view.completed,
                supervisor.restarts + 1
            );
            std::thread::sleep(options.tick);
            continue;
        }
        if view.converged(options.jobs) && (options.crash_at_completed == 0 || crashed) {
            return DriveOutcome::Converged;
        }
        std::thread::sleep(options.tick);
    }
}

/// The durable WAL read back: distinct job ids per record kind, plus each job's
/// `(producer, client_seq, key, work)` facts.
struct WalAudit {
    enqueued: BTreeSet<u64>,
    completed: BTreeSet<u64>,
    failed: BTreeSet<u64>,
    facts: BTreeMap<u64, (u32, u64, u32, u64)>,
}

fn audit_wal(records: &[wire::FramedRecord]) -> WalAudit {
    let mut audit = WalAudit {
        enqueued: BTreeSet::new(),
        completed: BTreeSet::new(),
        failed: BTreeSet::new(),
        facts: BTreeMap::new(),
    };
    for framed in records {
        match framed.record {
            WalRecord::Enqueue(job_id, producer, client_seq, key, work) => {
                audit.enqueued.insert(job_id);
                audit
                    .facts
                    .insert(job_id, (producer, client_seq, key, work));
            }
            WalRecord::Complete(job_id) => {
                audit.completed.insert(job_id);
            }
            WalRecord::Fail(job_id) => {
                audit.failed.insert(job_id);
            }
        }
    }
    audit
}

/// The order-insensitive outcome fingerprint: one row per enqueued job keyed on
/// its schedule-invariant client identity, sorted, then SHA-256'd. Nothing here
/// depends on completion order, so the digest is platform-invariant.
fn outcome_hash(audit: &WalAudit) -> String {
    // (producer, client_seq, terminal-state, key, work); state 0=done 1=failed 2=pending.
    let mut rows: Vec<(u32, u64, u8, u32, u64)> = audit
        .facts
        .iter()
        .map(|(id, &(producer, client_seq, key, work))| {
            let state = if audit.completed.contains(id) {
                0
            } else if audit.failed.contains(id) {
                1
            } else {
                2
            };
            (producer, client_seq, state, key, work)
        })
        .collect();
    rows.sort();
    let mut hasher = Sha256::new();
    for (producer, client_seq, state, key, work) in rows {
        hasher.update(producer.to_le_bytes());
        hasher.update(client_seq.to_le_bytes());
        hasher.update([state]);
        hasher.update(key.to_le_bytes());
        hasher.update(work.to_le_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Final invariant audit + the `WORKQ_RESULT` line; returns the process code.
fn report(
    options: &Options,
    accumulator: &AccumulatorHandle,
    acked: &AckedHandle,
    supervisor: &ServerSupervisor,
    converged: bool,
) -> i32 {
    // Re-scan the WAL from disk — the authoritative durable state; a corruption
    // here fails closed.
    let recovered = match wal::recover(&options.data_dir) {
        Ok(recovered) => recovered,
        Err(error) => {
            eprintln!("WORKQ_ABORT final-wal {error}");
            return 2;
        }
    };
    let audit = audit_wal(&recovered.records);
    let accumulator = accumulator.lock().unwrap();
    let acked = acked.lock().unwrap();
    let mut violations: Vec<String> = Vec::new();

    for &id in acked.ids() {
        // (1) Durability: every acked job is present in the recovered WAL.
        if !audit.enqueued.contains(&id) {
            violations.push(format!("durability acked-job-{id}-missing-from-wal"));
        // (2) No loss: on a converged run every acked job is terminal (a timeout
        //     is a liveness failure reported separately).
        } else if converged && !audit.completed.contains(&id) && !audit.failed.contains(&id) {
            violations.push(format!("no-loss acked-job-{id}-never-terminated"));
        }
    }
    // (3) Exactly-once: the accumulator is internally consistent and every applied
    //     job is a real enqueued job.
    if let Err(detail) = accumulator.verify_internal() {
        violations.push(format!("exactly-once {detail}"));
    }
    for &id in accumulator.applied_ids() {
        if !audit.enqueued.contains(&id) {
            violations.push(format!("exactly-once phantom-apply-job-{id}"));
        }
    }

    let (enqueued, completed, failed) = (
        audit.enqueued.len() as u64,
        audit.completed.len() as u64,
        audit.failed.len() as u64,
    );
    // `attempts` is schedule-sensitive, so it is reported but kept OUT of the hash.
    let attempts = supervisor.observation.lock().unwrap().attempts;
    println!(
        "WORKQ_RESULT seed={} enqueued={enqueued} completed={completed} failed={failed} attempts={attempts} applied_hash={}",
        options.seed,
        outcome_hash(&audit)
    );

    if !violations.is_empty() {
        violations
            .iter()
            .for_each(|v| eprintln!("WORKQ_VIOLATION {v}"));
        return 1;
    }
    if !converged {
        eprintln!(
            "WORKQ_FAILURE not-converged enqueued={enqueued} completed={completed} failed={failed} target={}",
            options.jobs
        );
        return 1;
    }
    if enqueued != options.jobs {
        eprintln!(
            "WORKQ_FAILURE enqueued={enqueued} != target={} (producers did not finish)",
            options.jobs
        );
        return 1;
    }
    0
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        seed: 0,
        jobs: 32,
        workers: 3,
        producers: 2,
        base_port: 5001,
        data_dir: PathBuf::new(),
        timeout: Duration::from_secs(60),
        tick: Duration::from_millis(20),
        segment_bytes: 4096,
        crash_at_completed: 0,
        bug: Bug::None,
    };
    let mut data_dir: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        let (key, inline) = match flag.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (flag, None),
        };
        // The value for `key`, from `=inline` or the next arg; parsed as a number.
        let mut val = |name: &str| {
            inline
                .clone()
                .map_or_else(|| args.next().ok_or(format!("{name} needs a value")), Ok)
        };
        let mut n = |name: &str| {
            val(name)?
                .parse::<u64>()
                .map_err(|_| format!("{name} must be a number"))
        };
        match key.as_str() {
            "--seed" => o.seed = n("--seed")?,
            "--jobs" => o.jobs = n("--jobs")?,
            "--workers" => o.workers = n("--workers")? as u32,
            "--producers" => o.producers = n("--producers")? as u32,
            "--base-port" => o.base_port = n("--base-port")? as u16,
            "--data-dir" => data_dir = Some(PathBuf::from(val("--data-dir")?)),
            "--timeout-secs" => o.timeout = Duration::from_secs(n("--timeout-secs")?),
            "--tick-ms" => o.tick = Duration::from_millis(n("--tick-ms")?),
            "--segment-bytes" => o.segment_bytes = n("--segment-bytes")?,
            "--crash-at-completed" => o.crash_at_completed = n("--crash-at-completed")?,
            "--bug" => {
                let name = val("--bug")?;
                o.bug = Bug::parse(&name).ok_or_else(|| {
                    format!("unknown --bug {name:?}; valid: {}", Bug::NAMES.join(", "))
                })?;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if o.jobs == 0 || o.workers == 0 || o.producers == 0 || o.tick.is_zero() {
        return Err("--jobs/--workers/--producers must be at least 1 and --tick-ms nonzero".into());
    }
    o.data_dir = data_dir
        .unwrap_or_else(|| std::env::temp_dir().join(format!("workq-{}", std::process::id())));
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::FramedRecord;

    fn enqueue(seq: u64, job_id: u64, producer: u32, client_seq: u64) -> FramedRecord {
        FramedRecord {
            seq,
            record: WalRecord::Enqueue(job_id, producer, client_seq, 0, 1),
        }
    }

    #[test]
    fn wal_audit_partitions_records_and_producer_counts_partition_the_workload() {
        let records = vec![
            enqueue(0, 1, 0, 0),
            enqueue(1, 2, 1, 0),
            FramedRecord {
                seq: 2,
                record: WalRecord::Complete(1),
            },
            FramedRecord {
                seq: 3,
                record: WalRecord::Fail(2),
            },
        ];
        let audit = audit_wal(&records);
        assert!(audit.completed.contains(&1) && audit.failed.contains(&2));
        // 10 jobs across 3 producers -> 4 + 3 + 3, each numbered from 0.
        let counts: Vec<u64> = (0..3).map(|id| producer_count(10, 3, id)).collect();
        assert_eq!(counts, vec![4, 3, 3]);
        assert_eq!(counts.iter().sum::<u64>(), 10);
    }
}
