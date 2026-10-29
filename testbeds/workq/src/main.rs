//! workq — a single-process durable work queue exercised end to end under Patina.
//! One process runs a WAL-backed **server**, **worker** threads that poll and
//! process jobs, and **producer** threads that enqueue a seeded workload, all over
//! loopback UDP + append-only WAL segments on the virtual clock. The app has no
//! fault code of its own; every drop, jitter, crash, and buggify fault comes
//! from Patina and the seed.
//!
//! Outcomes are announced through the **verdict ABI** (`patina_dst::verdict`), not
//! through the printed `WORKQ_*` lines: a self-checked invariant breach reports a
//! `Violation` under the invariant's label (exit 1), and a fail-closed recovery
//! abort reports either a `Violation` (`wal-integrity` — the durable log is
//! corrupt) or an `AbortIntent` (`storage-fault` — the storage plane errored and
//! the queue refuses to run on) before exiting 2. A clean converged run reports a
//! `Pass` under `workq-outcome` carrying the outcome digest. The `WORKQ_*` lines
//! stay for log readability; nothing downstream needs them.
//!
//! The one outcome with no verdict is the guest's own convergence timeout
//! (`WORKQ_FAILURE not-converged`, exit 1). The verdict ABI has no liveness kind,
//! and whether a run *should* have converged depends on the injected fault
//! configuration, which the guest cannot see — Patina's liveness watchdog is the
//! structural channel for that question.
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

use patina_dst::VerdictKind;
use producer::{AckedHandle, AckedLedger};
use server::{Bug, ServerConfig, ServerObservation, ServerSpec};
use wal::FailClosed;
use wire::WalRecord;
use worker::{Accumulator, AccumulatorHandle};

/// Report one self-detected invariant breach: the verdict is the announcement,
/// the printed line is the human echo of it. `label` names the invariant and
/// aggregates across runs; `detail` carries the run-specific particulars.
fn report_violation(label: &str, detail: &str) {
    patina_dst::verdict(VerdictKind::Violation, label, detail);
    eprintln!("WORKQ_VIOLATION {label} {detail}");
}

/// A job that exhausts this many deliveries without completing is terminally
/// failed; a delivery is redelivered if not completed within the visibility lease.
const MAX_ATTEMPTS: u32 = 5;
const VISIBILITY: Duration = Duration::from_millis(200);

struct Options {
    seed: u64,
    /// The workload's size: given by flags, or drawn by [`resolve_workload`].
    jobs: u64,
    workers: u32,
    producers: u32,
    /// The sizes the flags pinned; the rest are drawn.
    pinned: Pinned,
    base_port: u16,
    data_dir: PathBuf,
    /// The virtual-time convergence budget; `None` scales it with `jobs`.
    timeout: Option<Duration>,
    tick: Duration,
    segment_bytes: u64,
    /// Crash + recover the server once `completed` first reaches this (0 = never).
    crash_at_completed: u64,
    bug: Bug,
    /// When set, producers/workers resolve this name (via
    /// `wire::resolve_server_host`) instead of dialing `base_port` on the
    /// literal `127.0.0.1` numeric path. `None` (the default) is unchanged
    /// behavior; this exists so a `--dns-entry`-backed campaign has a real DNS
    /// call site to exercise (workq otherwise never resolves a hostname).
    server_host: Option<String>,
    /// Keep producer acks on disk here too, so the durability invariant spans
    /// a process restart (see `producer::AckedLedger`).
    ack_ledger: Option<PathBuf>,
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
             [--crash-at-completed N] [--bug NAME] [--server-host NAME] [--ack-ledger PATH] | \
             --check-recovery-fail-closed\n\
             valid --bug names: {}",
            Bug::NAMES.join(", ")
        );
        std::process::exit(2);
    });
    let options = match resolve_workload(options) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: workload manifest: {error}");
            std::process::exit(2);
        }
    };
    std::process::exit(orchestrate(options));
}

/// Workload sizes given on the command line.
#[derive(Default)]
struct Pinned {
    jobs: Option<u64>,
    workers: Option<u32>,
    producers: Option<u32>,
}

/// The ranges an unpinned size is drawn from.
const JOBS: std::ops::RangeInclusive<u64> = 16..=64;
const WORKERS: std::ops::RangeInclusive<u64> = 2..=4;
const PRODUCERS: std::ops::RangeInclusive<u64> = 1..=2;

/// Name of the file in the data dir that keeps the drawn sizes.
const MANIFEST: &str = "workload";

/// Fill in the sizes the flags left open, and print the workload.
///
/// An open size is drawn from `patina_dst::rng()`, so under Patina it is a pure
/// function of the run seed, and a reproduce command re-draws it. The drawn
/// sizes are kept in the data dir, synced before the queue writes anything:
/// a process restarted after a disk crash draws from a different stream, and
/// it must resume the workload the crashed process acknowledged jobs of. A
/// manifest that is missing or torn was never synced, so nothing durable
/// depends on it and the sizes are drawn afresh.
fn resolve_workload(mut options: Options) -> std::io::Result<Options> {
    let draw = |range: &std::ops::RangeInclusive<u64>| {
        range.start() + patina_dst::rng() % (range.end() - range.start() + 1)
    };
    let pinned = &options.pinned;
    let drawn = pinned.jobs.is_none() || pinned.workers.is_none() || pinned.producers.is_none();
    let path = options.data_dir.join(MANIFEST);
    let kept: Option<[u64; 3]> = if drawn {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| parse_manifest(&text))
    } else {
        None
    };
    let [jobs, workers, producers] =
        kept.unwrap_or_else(|| [draw(&JOBS), draw(&WORKERS), draw(&PRODUCERS)]);
    options.jobs = pinned.jobs.unwrap_or(jobs);
    options.workers = pinned.workers.unwrap_or(workers as u32);
    options.producers = pinned.producers.unwrap_or(producers as u32);
    if drawn && kept.is_none() {
        std::fs::create_dir_all(&options.data_dir)?;
        let mut file = std::fs::File::create(&path)?;
        use std::io::Write;
        writeln!(file, "{jobs} {workers} {producers}")?;
        file.sync_all()?;
        std::fs::File::open(&options.data_dir)?.sync_all()?;
    }
    let open = |pinned: bool| if pinned { "" } else { " (drawn)" };
    println!(
        "WORKQ_WORKLOAD jobs={}{} workers={}{} producers={}{} timeout_secs={}",
        options.jobs,
        open(options.pinned.jobs.is_some()),
        options.workers,
        open(options.pinned.workers.is_some()),
        options.producers,
        open(options.pinned.producers.is_some()),
        timeout(&options).as_secs(),
    );
    Ok(options)
}

/// The sizes a whole manifest line records, or `None` for a torn one.
fn parse_manifest(text: &str) -> Option<[u64; 3]> {
    let line = text.strip_suffix('\n')?;
    let fields: Vec<u64> = line
        .split(' ')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let sizes: [u64; 3] = fields.try_into().ok()?;
    let ranges = [JOBS, WORKERS, PRODUCERS];
    sizes
        .iter()
        .zip(&ranges)
        .all(|(size, range)| range.contains(size))
        .then_some(sizes)
}

/// The convergence budget: the given one, or 120 virtual seconds per 16 jobs
/// (at least 60), so a drawn large workload is not cut off by a small one's
/// budget.
fn timeout(options: &Options) -> Duration {
    options
        .timeout
        .unwrap_or_else(|| Duration::from_secs((120 * options.jobs / 16).max(60)))
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
            report_violation("recovery-not-fail-closed", &detail);
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
    failure: Arc<Mutex<Option<FailClosed>>>,
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

    fn failed(&self) -> Option<FailClosed> {
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
    // Opened before the server starts, so the ledger is durable on its own.
    let mut ledger = match &options.ack_ledger {
        Some(path) => match AckedLedger::open(path) {
            Ok(ledger) => ledger,
            Err(error) => {
                eprintln!("error: --ack-ledger {}: {error}", path.display());
                return 2;
            }
        },
        None => AckedLedger::default(),
    };
    // Hold the recovered log to the earlier incarnation's acks NOW, before a
    // producer can resend: a resent request for a lost job can be re-acked
    // under its old id and pass a check made only at the end.
    if !ledger.prior().is_empty() {
        match wal::recover(&options.data_dir) {
            Ok(recovered) => ledger.audit_prior(
                &audit_wal(&recovered.records)
                    .facts
                    .into_iter()
                    .map(|(id, (producer, seq, ..))| (id, (producer, seq)))
                    .collect(),
            ),
            Err(error) => {
                report_fail_closed("restart-wal", &FailClosed::from(&error));
                return 2;
            }
        }
    }
    let acked: AckedHandle = Arc::new(Mutex::new(ledger));
    let observation: ObservationHandle = Arc::new(Mutex::new(ServerObservation::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut supervisor = ServerSupervisor::spawn(config, observation.clone());

    let mut joins: Vec<JoinHandle<()>> = Vec::new();
    for id in 0..options.workers {
        let spec = worker::WorkerSpec {
            id,
            server: bind,
            server_host: options.server_host.clone(),
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
            server_host: options.server_host.clone(),
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
        DriveOutcome::FailClosed(failure) => {
            report_fail_closed("storage-fault", &failure);
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
    FailClosed(FailClosed),
}

/// Announce a fail-closed WAL stop before exiting 2. Corruption of the durable
/// log is a broken invariant, so it reports a `Violation`; a storage-plane I/O
/// error is not the queue's own bug, so it reports the deliberate stop as an
/// `AbortIntent` — attributed to the guest, never mistaken for a Patina refusal.
/// `site` names where the stop happened (the running server, or the final audit).
fn report_fail_closed(site: &str, failure: &FailClosed) {
    let detail = format!("{site} {}", failure.message);
    let kind = if failure.corruption {
        VerdictKind::Violation
    } else {
        VerdictKind::AbortIntent
    };
    patina_dst::verdict(kind, failure.label, &detail);
    eprintln!("WORKQ_ABORT {site} {}", failure.message);
}

/// Watch for convergence, fire the crash-recovery plan, and bail on a fail-closed
/// recovery error or the timeout.
fn drive(
    options: &Options,
    supervisor: &mut ServerSupervisor,
    observation: &ObservationHandle,
) -> DriveOutcome {
    let deadline = Instant::now() + timeout(options);
    let mut crashed = false;
    loop {
        if let Some(failure) = supervisor.failed() {
            return DriveOutcome::FailClosed(failure);
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
        // Every job terminal with fewer completed than the trigger (failures
        // took the rest) means the crash can no longer fire.
        let crash_pending = options.crash_at_completed > 0
            && !crashed
            && view.completed >= options.crash_at_completed;
        if view.converged(options.jobs) && !crash_pending {
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
            report_fail_closed("final-wal", &FailClosed::from(&error));
            return 2;
        }
    };
    let audit = audit_wal(&recovered.records);
    let accumulator = accumulator.lock().unwrap();
    let acked = acked.lock().unwrap();
    // (label, detail) per breach: the label names the invariant and is what
    // verdicts aggregate on, so job ids stay in the detail.
    let mut violations: Vec<(&'static str, String)> = Vec::new();

    for &id in acked.ids() {
        // (1) Durability: every acked job is present in the recovered WAL.
        if !audit.enqueued.contains(&id) {
            violations.push(("durability", format!("acked-job-{id}-missing-from-wal")));
        // (2) No loss: on a converged run every acked job is terminal (a timeout
        //     is a liveness failure reported separately).
        } else if converged && !audit.completed.contains(&id) && !audit.failed.contains(&id) {
            violations.push(("no-loss", format!("acked-job-{id}-never-terminated")));
        }
    }
    // (1b) Durability across a process restart: a job an earlier incarnation
    //      was acked for is still in the log under the same client identity.
    //      Checked at startup (before any resend) and again here.
    let mut lost = acked.prior_lost().clone();
    for (&id, &identity) in acked.prior() {
        let recovered = audit
            .facts
            .get(&id)
            .map(|&(producer, seq, ..)| (producer, seq));
        if recovered != Some(identity) {
            lost.insert(id);
        }
    }
    for id in lost {
        violations.push(("durability", format!("acked-job-{id}-lost-across-restart")));
    }
    // (3) Exactly-once: the accumulator is internally consistent and every applied
    //     job is a real enqueued job.
    if let Err(detail) = accumulator.verify_internal() {
        violations.push(("exactly-once", detail));
    }
    for &id in accumulator.applied_ids() {
        if !audit.enqueued.contains(&id) {
            violations.push(("exactly-once", format!("phantom-apply-job-{id}")));
        }
    }

    let (enqueued, completed, failed) = (
        audit.enqueued.len() as u64,
        audit.completed.len() as u64,
        audit.failed.len() as u64,
    );
    // `attempts` is schedule-sensitive, so it is reported but kept OUT of the hash.
    let attempts = supervisor.observation.lock().unwrap().attempts;
    let outcome = format!(
        "workload_seed={} enqueued={enqueued} completed={completed} failed={failed} attempts={attempts} applied_hash={}",
        options.seed,
        outcome_hash(&audit)
    );
    println!("WORKQ_RESULT {outcome}");

    if !violations.is_empty() {
        for (label, detail) in &violations {
            report_violation(label, detail);
        }
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
    // Every invariant held on a fully converged run: the one place a `Pass` is
    // meaningful. Its detail carries the outcome digest, so a consumer reading
    // only the verdict channel gets the schedule-invariant `applied_hash` that
    // the cross-platform outcome-invariance property is stated over.
    patina_dst::verdict(VerdictKind::Pass, "workq-outcome", &outcome);
    0
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        seed: 0,
        jobs: 0,
        workers: 0,
        producers: 0,
        pinned: Pinned::default(),
        base_port: 5001,
        data_dir: PathBuf::new(),
        timeout: None,
        tick: Duration::from_millis(20),
        segment_bytes: 4096,
        crash_at_completed: 0,
        bug: Bug::None,
        server_host: None,
        ack_ledger: None,
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
            "--jobs" => o.pinned.jobs = Some(n("--jobs")?),
            "--workers" => o.pinned.workers = Some(n("--workers")? as u32),
            "--producers" => o.pinned.producers = Some(n("--producers")? as u32),
            "--base-port" => o.base_port = n("--base-port")? as u16,
            "--data-dir" => data_dir = Some(PathBuf::from(val("--data-dir")?)),
            "--timeout-secs" => o.timeout = Some(Duration::from_secs(n("--timeout-secs")?)),
            "--tick-ms" => o.tick = Duration::from_millis(n("--tick-ms")?),
            "--segment-bytes" => o.segment_bytes = n("--segment-bytes")?,
            "--crash-at-completed" => o.crash_at_completed = n("--crash-at-completed")?,
            "--server-host" => o.server_host = Some(val("--server-host")?),
            "--ack-ledger" => o.ack_ledger = Some(PathBuf::from(val("--ack-ledger")?)),
            "--bug" => {
                let name = val("--bug")?;
                o.bug = Bug::parse(&name).ok_or_else(|| {
                    format!("unknown --bug {name:?}; valid: {}", Bug::NAMES.join(", "))
                })?;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    let p = &o.pinned;
    if [p.jobs, p.workers.map(u64::from), p.producers.map(u64::from)].contains(&Some(0))
        || o.tick.is_zero()
    {
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

    #[test]
    fn only_a_whole_in_range_manifest_line_is_kept() {
        assert_eq!(parse_manifest("24 3 2\n"), Some([24, 3, 2]));
        for torn in ["", "24 3 2", "24 3 ", "24 3\n", "24 3 x\n", "24 9 2\n"] {
            assert_eq!(parse_manifest(torn), None, "{torn:?}");
        }
    }
}
