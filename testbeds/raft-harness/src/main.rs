//! A 3-node tikv/raft cluster in one process, driven to consensus over UDP with
//! file-backed logs. Native entry point for the Patina raft testbed.
//!
//! Layout: `wire` (encoding), `storage` (file-backed `Storage`), `shared`
//! (cross-thread observations), `node` (per-node tick loop). `main` spawns the
//! nodes through a `Supervisor` that can kill and restart individual nodes,
//! runs the seeded client driver, checks invariants continuously and at the
//! end, and prints the `RAFT_RESULT` summary line.
//!
//! ## Crash-recovery supervision
//!
//! Each node is owned by the [`Supervisor`]. A node stops either cooperatively
//! (its shutdown flag is set) or by a storage failure (its `run` propagates the
//! I/O error via a shared `exit` slot instead of aborting the process). The
//! supervisor decides what happens next:
//!
//! - a **permanently** killed node (`--kill-node ID --kill-after-secs N`, the
//!   original quorum-survival scenario) stays down;
//! - a node killed by the **kill plan** (`--kill-plan ID:AT,...`, fired
//!   deterministically when the committed count reaches `AT`) is **restarted**
//!   after `--restart-after-ticks` ticks of virtual time: a fresh thread reopens
//!   `FileStorage` on the SAME data dir (recovery reconstruction), rebinds the
//!   node's UDP port, and rejoins;
//! - a node that **fails its storage** is restarted the same way when
//!   `--recover-storage-faults` is set (the fs-crash composition); without that
//!   flag a storage failure is fatal and the run fails closed (`RAFT_ABORT`,
//!   exit 2) exactly as before.
//!
//! Invariants must hold ACROSS a restart. A reincarnated node re-applies its
//! recovered log from index 0 into a fresh in-thread `applied` history, so the
//! applied-index-regression check (which is scoped to one thread's lifetime)
//! never trips on legitimate re-application, while the cross-node log-matching
//! and single-leader-per-term checks compare the reincarnation against the
//! survivors and must still pass. Election safety survives because raft loads
//! its fsync'd `HardState` (term + vote) from `FileStorage` on reopen.

mod node;
mod shared;
mod storage;
mod wire;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use node::{ClientProposal, NodeExit, NodeSpec, ProposeReply};
use shared::{LeadershipLog, NodeObservation, ObservationHandle};

struct Options {
    seed: u64,
    proposals: u64,
    timeout: Duration,
    base_port: u16,
    data_dir: std::path::PathBuf,
    tick_millis: u64,
    /// Permanent cooperative kill (never restarted): quorum-survival scenario.
    kill_node: u64,
    kill_after: Duration,
    /// Deterministic restartable kills, each fired when the committed count
    /// first reaches its threshold: `(node id, at committed count)`.
    kill_plan: Vec<(u64, u64)>,
    /// Virtual-time delay a downed-but-restartable node waits before its
    /// reincarnation is spawned.
    restart_after: Duration,
    /// Restart a node that dies from a storage fault (the fs-crash composition)
    /// instead of failing the run closed.
    recover_storage_faults: bool,
    /// Cap on client proposals in flight at once (0 = unlimited = the default
    /// pipelined workload). A small window makes the committed count advance one
    /// step at a time, so a kill-plan anchored to `committed == N` lands at a
    /// precise, intermediate point and the reincarnation must catch up the
    /// entries it missed via raft — rather than the whole batch committing in a
    /// single burst.
    propose_window: u64,
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!(
                "usage: raft-harness [--seed N] [--proposals N] [--timeout-secs N] \
                 [--base-port N] [--data-dir PATH] [--tick-millis N] \
                 [--kill-node ID] [--kill-after-secs N] \
                 [--kill-plan ID:AT[,ID:AT...]] [--restart-after-ticks N] \
                 [--recover-storage-faults] [--propose-window N]"
            );
            std::process::exit(2);
        }
    };
    std::process::exit(orchestrate(options));
}

/// Static, reincarnation-independent identity of one node. The per-incarnation
/// pieces (shutdown flag, exit slot, client receiver, thread) are created fresh
/// on every spawn; everything here — including the shared observation slot the
/// driver reads — is reused across restarts.
#[derive(Clone)]
struct NodeConfig {
    id: u64,
    voters: Vec<u64>,
    dir: std::path::PathBuf,
    bind: SocketAddr,
    peers: Vec<(u64, SocketAddr)>,
    seed: u64,
    tick_millis: u64,
    observation: ObservationHandle,
    leadership: Arc<Mutex<LeadershipLog>>,
}

/// Why a node is currently down, for reporting.
#[derive(Clone, Debug)]
enum DownCause {
    Killed,
    StorageFault(String),
}

/// The supervisor's view of one node's lifecycle.
enum NodeStatus {
    Alive,
    Down {
        since: Instant,
        /// Whether this node is to be reincarnated (kill plan / storage
        /// recovery) or is gone for good (permanent kill).
        restart: bool,
        #[allow(dead_code)]
        cause: DownCause,
    },
}

/// One node's live runtime state: the reusable config plus the current
/// incarnation's handles.
struct NodeRuntime {
    config: NodeConfig,
    shutdown: Arc<AtomicBool>,
    exit: Arc<Mutex<NodeExit>>,
    join: Option<JoinHandle<()>>,
    client_tx: Sender<ClientProposal>,
    status: NodeStatus,
    restarts: u32,
}

/// Owns every node thread and performs kills and restarts. All supervision
/// decisions run in the driver (main) thread, so they are a deterministic
/// function of the observed schedule.
struct Supervisor {
    runtimes: HashMap<u64, NodeRuntime>,
    order: Vec<u64>,
    restart_after: Duration,
    recover_storage_faults: bool,
}

/// A fatal, run-ending condition surfaced from the supervisor (a fail-closed
/// storage failure when recovery is not enabled).
struct Fatal {
    message: String,
}

/// Human-readable reason a node went down, for the restart log line.
fn describe_cause(cause: &DownCause) -> String {
    match cause {
        DownCause::Killed => "a deliberate kill".to_string(),
        DownCause::StorageFault(message) => format!("a storage fault ({message})"),
    }
}

/// Build a fresh incarnation of a node: new shutdown flag, exit slot, client
/// channel, and thread. Returns the spawn-side handles plus the sending end of
/// the client channel.
fn spawn_node(
    config: &NodeConfig,
) -> (Arc<AtomicBool>, Arc<Mutex<NodeExit>>, Sender<ClientProposal>, JoinHandle<()>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let exit = Arc::new(Mutex::new(NodeExit::Running));
    let (tx, rx) = channel::<ClientProposal>();
    let spec = NodeSpec {
        id: config.id,
        voters: config.voters.clone(),
        dir: config.dir.clone(),
        bind: config.bind,
        peers: config.peers.clone(),
        seed: config.seed,
        tick_millis: config.tick_millis,
        shutdown: shutdown.clone(),
        exit: exit.clone(),
        observation: config.observation.clone(),
        leadership: config.leadership.clone(),
        client_rx: rx,
    };
    let handle = std::thread::spawn(move || node::run(spec));
    (shutdown, exit, tx, handle)
}

impl Supervisor {
    fn new(configs: Vec<NodeConfig>, restart_after: Duration, recover_storage_faults: bool) -> Self {
        let mut runtimes = HashMap::new();
        let mut order = Vec::new();
        for config in configs {
            let id = config.id;
            let (shutdown, exit, client_tx, join) = spawn_node(&config);
            runtimes.insert(
                id,
                NodeRuntime {
                    config,
                    shutdown,
                    exit,
                    join: Some(join),
                    client_tx,
                    status: NodeStatus::Alive,
                    restarts: 0,
                },
            );
            order.push(id);
        }
        order.sort();
        Supervisor { runtimes, order, restart_after, recover_storage_faults }
    }

    /// Ids currently believed alive, sorted.
    fn alive_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .order
            .iter()
            .copied()
            .filter(|id| matches!(self.runtimes[id].status, NodeStatus::Alive))
            .collect();
        ids.sort();
        ids
    }

    fn is_alive(&self, id: u64) -> bool {
        self.runtimes.get(&id).is_some_and(|rt| matches!(rt.status, NodeStatus::Alive))
    }

    fn client_tx(&self, id: u64) -> Option<&Sender<ClientProposal>> {
        self.runtimes.get(&id).map(|rt| &rt.client_tx)
    }

    /// True while at least one node is down but slated to come back — used to
    /// keep the driver from declaring victory before a recovery has happened.
    fn restart_pending(&self) -> bool {
        self.runtimes
            .values()
            .any(|rt| matches!(rt.status, NodeStatus::Down { restart: true, .. }))
    }

    fn total_restarts(&self) -> u32 {
        self.runtimes.values().map(|rt| rt.restarts).sum()
    }

    /// Cooperatively kill a node. `restart` selects reincarnation (kill plan /
    /// recovery) vs permanent removal (quorum-survival scenario).
    fn kill(&mut self, id: u64, cause: DownCause, restart: bool, now: Instant) {
        if let Some(rt) = self.runtimes.get_mut(&id) {
            if matches!(rt.status, NodeStatus::Alive) {
                rt.shutdown.store(true, Ordering::Relaxed);
                rt.status = NodeStatus::Down { since: now, restart, cause };
            }
        }
    }

    /// Per-iteration bookkeeping: notice threads that died on their own, and
    /// reincarnate downed-but-restartable nodes once their delay elapses.
    ///
    /// Returns `Err(Fatal)` when a node dies of a storage fault and storage
    /// recovery is not enabled — the fail-closed policy.
    fn poll(&mut self, now: Instant) -> Result<(), Fatal> {
        // 1. Detect nodes that stopped on their own (storage failure). A
        //    cooperative kill already moved the node to `Down`, so only `Alive`
        //    nodes whose thread has finished are unexpected deaths.
        for id in self.order.clone() {
            let rt = self.runtimes.get_mut(&id).expect("known node");
            if !matches!(rt.status, NodeStatus::Alive) {
                continue;
            }
            let finished = rt.join.as_ref().is_some_and(|h| h.is_finished());
            if !finished {
                continue;
            }
            let exit = rt.exit.lock().unwrap().clone();
            match exit {
                NodeExit::StorageFailed(message) => {
                    if self.recover_storage_faults {
                        rt.status = NodeStatus::Down {
                            since: now,
                            restart: true,
                            cause: DownCause::StorageFault(message),
                        };
                    } else {
                        return Err(Fatal {
                            message: format!("node {id} storage failure: {message}"),
                        });
                    }
                }
                // A clean `Stopped` on an `Alive` node means the tick loop exited
                // for a reason other than our flag; treat it as a permanent stop.
                NodeExit::Stopped => {
                    rt.status = NodeStatus::Down {
                        since: now,
                        restart: false,
                        cause: DownCause::Killed,
                    };
                }
                NodeExit::Running => {
                    // Thread finished but slot not yet written; observe next poll.
                }
            }
        }

        // 2. Reincarnate downed-but-restartable nodes whose delay has elapsed and
        //    whose previous thread has fully unwound (so its UDP port is free).
        for id in self.order.clone() {
            let rt = self.runtimes.get_mut(&id).expect("known node");
            let (due, cause) = match &rt.status {
                NodeStatus::Down { since, restart: true, cause } => {
                    (now.duration_since(*since) >= self.restart_after, describe_cause(cause))
                }
                _ => (false, String::new()),
            };
            if !due {
                continue;
            }
            let unwound = rt.join.as_ref().is_none_or(|h| h.is_finished());
            if !unwound {
                continue;
            }
            if let Some(handle) = rt.join.take() {
                let _ = handle.join();
            }
            // Reset the shared observation so the driver never compares the dead
            // incarnation's stale applied log; the fresh thread republishes its
            // re-applied state within a tick.
            *rt.config.observation.lock().unwrap() = NodeObservation::default();
            let (shutdown, exit, client_tx, join) = spawn_node(&rt.config);
            rt.shutdown = shutdown;
            rt.exit = exit;
            rt.client_tx = client_tx;
            rt.join = Some(join);
            rt.status = NodeStatus::Alive;
            rt.restarts += 1;
            eprintln!(
                "driver: restarted node {id} (incarnation #{}) after {cause}",
                rt.restarts + 1
            );
        }
        Ok(())
    }

    /// Stop every node and join all threads.
    fn shutdown_all(&mut self) {
        for rt in self.runtimes.values() {
            rt.shutdown.store(true, Ordering::Relaxed);
        }
        for rt in self.runtimes.values_mut() {
            if let Some(handle) = rt.join.take() {
                let _ = handle.join();
            }
        }
    }
}

fn orchestrate(options: Options) -> i32 {
    let voters: Vec<u64> = vec![1, 2, 3];
    let addr_of = |id: u64| -> SocketAddr {
        format!("127.0.0.1:{}", options.base_port + (id as u16 - 1))
            .parse()
            .expect("valid loopback address")
    };

    let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
    let observations: HashMap<u64, ObservationHandle> = voters
        .iter()
        .map(|&id| (id, Arc::new(Mutex::new(NodeObservation::default())) as ObservationHandle))
        .collect();

    let configs: Vec<NodeConfig> = voters
        .iter()
        .map(|&id| {
            let peers: Vec<(u64, SocketAddr)> = voters
                .iter()
                .filter(|&&other| other != id)
                .map(|&other| (other, addr_of(other)))
                .collect();
            NodeConfig {
                id,
                voters: voters.clone(),
                dir: options.data_dir.join(format!("node{id}")),
                bind: addr_of(id),
                peers,
                seed: options.seed,
                tick_millis: options.tick_millis,
                observation: observations[&id].clone(),
                leadership: leadership.clone(),
            }
        })
        .collect();

    let mut supervisor =
        Supervisor::new(configs, options.restart_after, options.recover_storage_faults);

    let result = drive(&options, &mut supervisor, &leadership, &observations);

    supervisor.shutdown_all();

    match result {
        Err(fatal) => {
            eprintln!("RAFT_ABORT {}", fatal.message);
            2
        }
        Ok(outcome) => report(&options, &observations, &leadership, &supervisor, outcome),
    }
}

/// The result of the drive phase: which nodes were alive at the end and whether
/// the client saw every proposal committed everywhere.
struct Outcome {
    alive: Vec<u64>,
    completed: bool,
}

fn drive(
    options: &Options,
    supervisor: &mut Supervisor,
    leadership: &Arc<Mutex<LeadershipLog>>,
    observations: &HashMap<u64, ObservationHandle>,
) -> Result<Outcome, Fatal> {
    let start = Instant::now();
    let deadline = start + options.timeout;
    let (reply_tx, reply_rx) = channel::<ProposeReply>();
    let mut permanent_killed = false;
    // Which kill-plan entries have already fired.
    let mut plan_fired = vec![false; options.kill_plan.len()];
    // Rate-limit re-proposals of a still-unapplied id.
    let mut last_proposed: HashMap<u64, Instant> = HashMap::new();
    let retry_after = Duration::from_millis(500);
    // Leader hint learned from a `NotLeader` reply, used only when no alive node
    // is currently advertising leadership in its observation.
    let mut leader_hint: Option<u64> = None;

    loop {
        if Instant::now() >= deadline {
            return Ok(Outcome { alive: supervisor.alive_ids(), completed: false });
        }

        // Supervisor bookkeeping: detect deaths and perform restarts. A
        // fail-closed storage fault propagates out as a fatal.
        supervisor.poll(Instant::now())?;

        let alive = supervisor.alive_ids();

        // Permanent cooperative kill: drop one node mid-run for good (the
        // quorum-survival scenario) and stop expecting it.
        if !permanent_killed
            && options.kill_node != 0
            && start.elapsed() >= options.kill_after
            && alive.contains(&options.kill_node)
        {
            supervisor.kill(options.kill_node, DownCause::Killed, false, Instant::now());
            permanent_killed = true;
            eprintln!(
                "driver: killed node {} after {:?} (permanent)",
                options.kill_node, options.kill_after
            );
        }

        let snapshots = snapshot(observations, &alive);

        // Continuous invariant checks; any violation is fatal to the run's
        // success but not to the process — we report it and stop the drive.
        if let Err(message) = check_invariants(&snapshots, leadership) {
            eprintln!("RAFT_VIOLATION {message}");
            return Ok(Outcome { alive, completed: false });
        }

        // Completion: every proposal applied on every alive node.
        let committed = committed_count(options.proposals, &snapshots);

        // Kill-plan: fire deterministic restartable kills anchored to the
        // committed count, so a kill lands at the same logical point every run.
        for (i, &(id, at)) in options.kill_plan.iter().enumerate() {
            if !plan_fired[i] && committed >= at && supervisor.is_alive(id) {
                supervisor.kill(id, DownCause::Killed, true, Instant::now());
                plan_fired[i] = true;
                eprintln!(
                    "driver: killed node {id} at committed={committed} (restart in {:?})",
                    options.restart_after
                );
            }
        }

        // Victory requires every proposal committed everywhere alive, no restart
        // still pending, and every scheduled kill already fired — so we never
        // finish before a planned kill happens or before its reincarnation has
        // rejoined and caught up.
        let plan_complete = plan_fired.iter().all(|&f| f);
        if committed == options.proposals && !supervisor.restart_pending() && plan_complete {
            return Ok(Outcome { alive, completed: true });
        }

        // Propose still-unapplied ids to the current leader, paced per id.
        let leader = current_leader(&snapshots)
            .or_else(|| leader_hint.filter(|hint| alive.contains(hint)));
        if let Some(leader) = leader {
            if let Some(tx) = supervisor.client_tx(leader) {
                let now = Instant::now();
                // With a proposal window, only keep `window` ids past the first
                // still-unapplied one in flight, so commits advance gradually.
                let ceiling = if options.propose_window == 0 {
                    options.proposals
                } else {
                    let base = (0..options.proposals)
                        .find(|&id| !applied_on_all(id, &snapshots))
                        .unwrap_or(options.proposals);
                    (base + options.propose_window).min(options.proposals)
                };
                for id in 0..ceiling {
                    if applied_on_all(id, &snapshots) {
                        continue;
                    }
                    let due = last_proposed
                        .get(&id)
                        .map(|at| now.duration_since(*at) >= retry_after)
                        .unwrap_or(true);
                    if due {
                        let request = ClientProposal { id, reply: reply_tx.clone() };
                        if tx.send(request).is_ok() {
                            last_proposed.insert(id, now);
                        }
                    }
                }
            }
        }

        // Drain replies so the channel does not grow unbounded. Progress is
        // judged by observed application; a NotLeader reply only refreshes the
        // fallback leader hint.
        while let Ok(reply) = reply_rx.try_recv() {
            if let ProposeReply::NotLeader(hint) = reply {
                if hint != 0 {
                    leader_hint = Some(hint);
                }
            }
        }

        std::thread::sleep(Duration::from_millis(options.tick_millis / 2 + 10));
    }
}

fn report(
    options: &Options,
    observations: &HashMap<u64, ObservationHandle>,
    leadership: &Arc<Mutex<LeadershipLog>>,
    supervisor: &Supervisor,
    outcome: Outcome,
) -> i32 {
    let snapshots = snapshot(observations, &outcome.alive);

    // Final invariant check after all nodes have stopped and converged.
    let invariants_ok = match check_invariants(&snapshots, leadership) {
        Ok(()) => true,
        Err(message) => {
            eprintln!("RAFT_VIOLATION {message}");
            false
        }
    };

    let committed = committed_count(options.proposals, &snapshots);
    let max_term = snapshots.iter().map(|(_, view)| view.term).max().unwrap_or(0);
    let common = common_applied_len(&snapshots);
    let applied_hash = snapshots
        .first()
        .map(|(_, view)| view.applied_hash_prefix(common))
        .unwrap_or_else(|| shared::hex(&[0u8; 32]));

    let restarts = supervisor.total_restarts();
    println!(
        "RAFT_RESULT seed={} proposals={} committed={} terms={} restarts={} applied_hash={}",
        options.seed, options.proposals, committed, max_term, restarts, applied_hash
    );

    let success = invariants_ok && outcome.completed && committed == options.proposals;
    if success {
        0
    } else {
        if !outcome.completed {
            eprintln!(
                "RAFT_FAILURE not all proposals committed on alive nodes ({committed}/{})",
                options.proposals
            );
        }
        1
    }
}

/// Clone the observations of the currently-alive nodes.
fn snapshot(
    observations: &HashMap<u64, ObservationHandle>,
    alive: &[u64],
) -> Vec<(u64, NodeObservation)> {
    let mut out: Vec<(u64, NodeObservation)> = alive
        .iter()
        .filter_map(|id| observations.get(id).map(|handle| (*id, handle.lock().unwrap().clone())))
        .collect();
    out.sort_by_key(|(id, _)| *id);
    out
}

/// The alive node currently claiming leadership at the highest term, if any.
fn current_leader(snapshots: &[(u64, NodeObservation)]) -> Option<u64> {
    snapshots
        .iter()
        .filter(|(_, view)| view.is_leader)
        .max_by_key(|(_, view)| view.term)
        .map(|(id, _)| *id)
}

fn applied_on_all(id: u64, snapshots: &[(u64, NodeObservation)]) -> bool {
    !snapshots.is_empty() && snapshots.iter().all(|(_, view)| view.applied_ids.contains(&id))
}

fn committed_count(proposals: u64, snapshots: &[(u64, NodeObservation)]) -> u64 {
    (0..proposals).filter(|&id| applied_on_all(id, snapshots)).count() as u64
}

/// Shortest applied history among the snapshots (their agreed prefix length).
fn common_applied_len(snapshots: &[(u64, NodeObservation)]) -> usize {
    snapshots.iter().map(|(_, view)| view.applied.len()).min().unwrap_or(0)
}

/// Check the safety invariants across the alive nodes:
/// - at most one leader per term (from the accumulated leadership log);
/// - log matching: applied entries agree in content and order on the common
///   prefix shared by every alive node.
///
/// Both checks are robust to restarts. Leadership is accumulated across
/// incarnations, so a reincarnated node that (correctly, from fsync'd hard
/// state) refuses to elect a second leader in a term keeps the log clean, while
/// a reincarnation that re-applied a divergent log would surface here once its
/// re-applied prefix reaches the disagreeing position.
fn check_invariants(
    snapshots: &[(u64, NodeObservation)],
    leadership: &Arc<Mutex<LeadershipLog>>,
) -> Result<(), String> {
    if let Some((term, ids)) = leadership.lock().unwrap().conflicting_term() {
        return Err(format!("two leaders in term {term}: nodes {ids:?}"));
    }

    let common = common_applied_len(snapshots);
    if let Some((reference_id, reference)) = snapshots.first() {
        for (id, view) in snapshots.iter().skip(1) {
            for position in 0..common {
                let a = &reference.applied[position];
                let b = &view.applied[position];
                if a != b {
                    return Err(format!(
                        "log mismatch at applied position {position}: node {reference_id} has \
                         (idx {}, term {}) but node {id} has (idx {}, term {})",
                        a.index, a.term, b.index, b.term
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Parse a `--kill-plan` value: `ID:AT[,ID:AT...]`.
fn parse_kill_plan(spec: &str) -> Result<Vec<(u64, u64)>, String> {
    let mut plan = Vec::new();
    for part in spec.split(',').filter(|p| !p.is_empty()) {
        let (id, at) = part
            .split_once(':')
            .ok_or_else(|| format!("--kill-plan entry {part:?} must be ID:AT"))?;
        let id: u64 = id.parse().map_err(|_| format!("--kill-plan id {id:?} must be u64"))?;
        let at: u64 = at.parse().map_err(|_| format!("--kill-plan at {at:?} must be u64"))?;
        if id == 0 {
            return Err("--kill-plan id must be a real node id".into());
        }
        plan.push((id, at));
    }
    Ok(plan)
}

fn parse_options() -> Result<Options, String> {
    let mut seed = 0u64;
    let mut proposals = 50u64;
    let mut timeout_secs = 60u64;
    let mut base_port = 4001u16;
    let mut tick_millis = 100u64;
    let mut kill_node = 0u64;
    let mut kill_after_secs = 5u64;
    let mut kill_plan: Vec<(u64, u64)> = Vec::new();
    let mut restart_after_ticks = 5u64;
    let mut recover_storage_faults = false;
    let mut propose_window = 0u64;
    let mut data_dir: Option<std::path::PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let (key, inline) = match flag.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (flag, None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                Ok(v)
            } else {
                args.next().ok_or_else(|| format!("{name} requires a value"))
            }
        };
        match key.as_str() {
            "--seed" => seed = value("--seed")?.parse().map_err(|_| "--seed must be u64")?,
            "--proposals" => {
                proposals = value("--proposals")?.parse().map_err(|_| "--proposals must be u64")?
            }
            "--timeout-secs" => {
                timeout_secs =
                    value("--timeout-secs")?.parse().map_err(|_| "--timeout-secs must be u64")?
            }
            "--base-port" => {
                base_port = value("--base-port")?.parse().map_err(|_| "--base-port must be u16")?
            }
            "--tick-millis" => {
                tick_millis =
                    value("--tick-millis")?.parse().map_err(|_| "--tick-millis must be u64")?
            }
            "--kill-node" => {
                kill_node = value("--kill-node")?.parse().map_err(|_| "--kill-node must be u64")?
            }
            "--kill-after-secs" => {
                kill_after_secs = value("--kill-after-secs")?
                    .parse()
                    .map_err(|_| "--kill-after-secs must be u64")?
            }
            "--kill-plan" => kill_plan = parse_kill_plan(&value("--kill-plan")?)?,
            "--restart-after-ticks" => {
                restart_after_ticks = value("--restart-after-ticks")?
                    .parse()
                    .map_err(|_| "--restart-after-ticks must be u64")?
            }
            "--recover-storage-faults" => recover_storage_faults = true,
            "--propose-window" => {
                propose_window = value("--propose-window")?
                    .parse()
                    .map_err(|_| "--propose-window must be u64")?
            }
            "--data-dir" => data_dir = Some(std::path::PathBuf::from(value("--data-dir")?)),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if proposals == 0 {
        return Err("--proposals must be at least 1".into());
    }
    if tick_millis == 0 {
        return Err("--tick-millis must be at least 1".into());
    }
    for &(id, _) in &kill_plan {
        if id > 3 {
            return Err(format!("--kill-plan references unknown node {id} (cluster is 1..3)"));
        }
    }

    let data_dir = data_dir
        .unwrap_or_else(|| std::env::temp_dir().join(format!("raft-harness-{}", std::process::id())));

    Ok(Options {
        seed,
        proposals,
        timeout: Duration::from_secs(timeout_secs),
        base_port,
        data_dir,
        tick_millis,
        kill_node,
        kill_after: Duration::from_secs(kill_after_secs),
        kill_plan,
        restart_after: Duration::from_millis(restart_after_ticks.saturating_mul(tick_millis)),
        recover_storage_faults,
        propose_window,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::AppliedEntry;

    fn view(applied: Vec<(u64, u64, u8)>) -> NodeObservation {
        let mut observation = NodeObservation::default();
        for (index, term, byte) in applied {
            observation.applied.push(AppliedEntry { index, term, data: vec![byte] });
            observation.applied_ids.insert(index);
        }
        observation
    }

    #[test]
    fn matching_logs_pass_invariants() {
        let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
        let snapshots = vec![
            (1, view(vec![(1, 1, 10), (2, 1, 20)])),
            (2, view(vec![(1, 1, 10), (2, 1, 20)])),
        ];
        assert!(check_invariants(&snapshots, &leadership).is_ok());
    }

    #[test]
    fn divergent_logs_fail_invariants() {
        let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
        // Same index/term but different payload at position 1 -> log mismatch.
        let snapshots = vec![
            (1, view(vec![(1, 1, 10), (2, 1, 20)])),
            (2, view(vec![(1, 1, 10), (2, 1, 99)])),
        ];
        let error = check_invariants(&snapshots, &leadership).expect_err("must detect mismatch");
        assert!(error.contains("log mismatch"), "got: {error}");
    }

    #[test]
    fn committed_count_requires_all_alive_nodes() {
        let snapshots = vec![
            (1, view(vec![(1, 1, 10), (2, 1, 20)])),
            (2, view(vec![(1, 1, 10)])), // missing id 2
        ];
        // ids are the applied indices here: id 1 is on both, id 2 only on node 1.
        assert_eq!(committed_count(3, &snapshots), 1);
    }

    #[test]
    fn reincarnation_reapplying_prefix_matches_survivors() {
        // A restarted node that has re-applied only the first entry so far still
        // matches the survivors on the common (length-1) prefix: no false
        // violation while it catches up.
        let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
        let snapshots = vec![
            (1, view(vec![(1, 1, 10), (2, 1, 20), (3, 1, 30)])),
            (2, view(vec![(1, 1, 10), (2, 1, 20), (3, 1, 30)])),
            (3, view(vec![(1, 1, 10)])), // reincarnation mid-catch-up
        ];
        assert!(check_invariants(&snapshots, &leadership).is_ok());
        // Not yet converged: ids 2 and 3 are not on the reincarnation.
        assert_eq!(committed_count(3, &snapshots), 1);
    }

    #[test]
    fn reincarnation_with_divergent_reapply_is_flagged() {
        // If a reincarnation re-applied a DIFFERENT entry at a shared position,
        // the check bites as soon as its prefix reaches that position.
        let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
        let snapshots = vec![
            (1, view(vec![(1, 1, 10), (2, 1, 20)])),
            (3, view(vec![(1, 1, 10), (2, 1, 77)])), // divergent re-apply
        ];
        assert!(check_invariants(&snapshots, &leadership).is_err());
    }

    #[test]
    fn kill_plan_parses_multiple_entries() {
        assert_eq!(parse_kill_plan("2:5").unwrap(), vec![(2, 5)]);
        assert_eq!(parse_kill_plan("1:3,2:10").unwrap(), vec![(1, 3), (2, 10)]);
        assert!(parse_kill_plan("bogus").is_err());
        assert!(parse_kill_plan("0:5").is_err());
    }
}
