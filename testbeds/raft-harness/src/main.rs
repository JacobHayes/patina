//! A 3-node tikv/raft cluster in one process, driven to consensus over UDP with
//! file-backed logs. Native entry point for the Patina raft testbed.
//!
//! Layout: `wire` (encoding), `storage` (file-backed `Storage`), `shared`
//! (cross-thread observations), `node` (per-node tick loop). `main` spawns the
//! nodes, runs the seeded client driver, checks invariants continuously and at
//! the end, and prints the `RAFT_RESULT` summary line.

mod node;
mod shared;
mod storage;
mod wire;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use node::{ClientProposal, NodeSpec, ProposeReply};
use shared::{LeadershipLog, NodeObservation, ObservationHandle};

struct Options {
    seed: u64,
    proposals: u64,
    timeout: Duration,
    base_port: u16,
    data_dir: std::path::PathBuf,
    tick_millis: u64,
    kill_node: u64,
    kill_after: Duration,
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!(
                "usage: raft-harness [--seed N] [--proposals N] [--timeout-secs N] \
                 [--base-port N] [--data-dir PATH] [--tick-millis N] \
                 [--kill-node ID] [--kill-after-secs N]"
            );
            std::process::exit(2);
        }
    };
    std::process::exit(orchestrate(options));
}

fn orchestrate(options: Options) -> i32 {
    let voters: Vec<u64> = vec![1, 2, 3];
    let addr_of = |id: u64| -> SocketAddr {
        format!("127.0.0.1:{}", options.base_port + (id as u16 - 1))
            .parse()
            .expect("valid loopback address")
    };

    let leadership = Arc::new(Mutex::new(LeadershipLog::default()));
    let mut observations: HashMap<u64, ObservationHandle> = HashMap::new();
    let mut shutdowns: HashMap<u64, Arc<AtomicBool>> = HashMap::new();
    let mut client_tx: HashMap<u64, Sender<ClientProposal>> = HashMap::new();
    let mut handles = Vec::new();

    for &id in &voters {
        let observation: ObservationHandle = Arc::new(Mutex::new(NodeObservation::default()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel::<ClientProposal>();
        let peers: Vec<(u64, SocketAddr)> = voters
            .iter()
            .filter(|&&other| other != id)
            .map(|&other| (other, addr_of(other)))
            .collect();
        let spec = NodeSpec {
            id,
            voters: voters.clone(),
            dir: options.data_dir.join(format!("node{id}")),
            bind: addr_of(id),
            peers,
            seed: options.seed,
            tick_millis: options.tick_millis,
            shutdown: shutdown.clone(),
            observation: observation.clone(),
            leadership: leadership.clone(),
            client_rx: rx,
        };
        observations.insert(id, observation);
        shutdowns.insert(id, shutdown);
        client_tx.insert(id, tx);
        handles.push(std::thread::spawn(move || node::run(spec)));
    }

    let outcome = drive(&options, &voters, &observations, &leadership, &client_tx, &shutdowns);

    // Stop every node and wait for the tick loops to exit cleanly.
    for shutdown in shutdowns.values() {
        shutdown.store(true, Ordering::Relaxed);
    }
    for handle in handles {
        let _ = handle.join();
    }

    report(&options, &observations, &leadership, outcome)
}

/// The result of the drive phase: which nodes were alive at the end and whether
/// the client saw every proposal committed everywhere.
struct Outcome {
    alive: Vec<u64>,
    completed: bool,
}

fn drive(
    options: &Options,
    voters: &[u64],
    observations: &HashMap<u64, ObservationHandle>,
    leadership: &Arc<Mutex<LeadershipLog>>,
    client_tx: &HashMap<u64, Sender<ClientProposal>>,
    shutdowns: &HashMap<u64, Arc<AtomicBool>>,
) -> Outcome {
    let start = Instant::now();
    let deadline = start + options.timeout;
    let (reply_tx, reply_rx) = channel::<ProposeReply>();
    let mut alive: Vec<u64> = voters.to_vec();
    let mut killed = false;
    // Rate-limit re-proposals of a still-unapplied id.
    let mut last_proposed: HashMap<u64, Instant> = HashMap::new();
    let retry_after = Duration::from_millis(500);
    // Leader hint learned from a `NotLeader` reply, used only when no alive node
    // is currently advertising leadership in its observation.
    let mut leader_hint: Option<u64> = None;

    loop {
        if Instant::now() >= deadline {
            return Outcome { alive, completed: false };
        }

        // Cooperative kill: drop one node mid-run and stop expecting it.
        if !killed
            && options.kill_node != 0
            && start.elapsed() >= options.kill_after
            && alive.contains(&options.kill_node)
        {
            if let Some(flag) = shutdowns.get(&options.kill_node) {
                flag.store(true, Ordering::Relaxed);
            }
            alive.retain(|&id| id != options.kill_node);
            killed = true;
            eprintln!(
                "driver: killed node {} after {:?}",
                options.kill_node, options.kill_after
            );
        }

        let snapshots = snapshot(observations, &alive);

        // Continuous invariant checks; any violation is fatal.
        if let Err(message) = check_invariants(&snapshots, leadership) {
            eprintln!("RAFT_VIOLATION {message}");
            return Outcome { alive, completed: false };
        }

        // Completion: every proposal applied on every alive node.
        let committed = committed_count(options.proposals, &snapshots);
        if committed == options.proposals {
            return Outcome { alive, completed: true };
        }

        // Propose still-unapplied ids to the current leader, paced per id.
        let leader = current_leader(&snapshots)
            .or_else(|| leader_hint.filter(|hint| alive.contains(hint)));
        if let Some(leader) = leader {
            if let Some(tx) = client_tx.get(&leader) {
                let now = Instant::now();
                for id in 0..options.proposals {
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

    println!(
        "RAFT_RESULT seed={} proposals={} committed={} terms={} applied_hash={}",
        options.seed, options.proposals, committed, max_term, applied_hash
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

fn parse_options() -> Result<Options, String> {
    let mut seed = 0u64;
    let mut proposals = 50u64;
    let mut timeout_secs = 60u64;
    let mut base_port = 4001u16;
    let mut tick_millis = 100u64;
    let mut kill_node = 0u64;
    let mut kill_after_secs = 5u64;
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
}
