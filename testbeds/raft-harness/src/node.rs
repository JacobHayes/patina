//! One raft node: a std thread owning a `RawNode<FileStorage>`, a UDP socket for
//! inter-node raft traffic, and an mpsc inbox for client proposals.
//!
//! The tick loop honours raft's Ready contract in the documented order —
//! send-unpersisted, persist entries + hard state, send-persisted, apply,
//! advance — so that entries and hard state always reach disk before the
//! messages that depend on them leave the node.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use raft::prelude::{ConfState, Entry, EntryType, Message};
use raft::{Config, RawNode, StateRole};
use slog::{o, Discard, Logger};

use crate::shared::{AppliedEntry, LeadershipLog, ObservationHandle};
use crate::storage::FileStorage;
use crate::wire;

/// Maximum UDP datagram we will receive. One encoded raft `Message` must fit in
/// a single datagram; see the README for why this bounds the native harness and
/// what the Patina phase must watch for.
const RECV_BUFFER: usize = 64 * 1024;

/// A client's request to append one unique payload, routed to the current leader.
pub struct ClientProposal {
    pub id: u64,
    pub reply: Sender<ProposeReply>,
}

/// The leader's answer to a client proposal.
pub enum ProposeReply {
    /// Accepted into the leader's log (not yet necessarily committed).
    Accepted,
    /// This node is not the leader; the id it currently believes is (0 = none).
    NotLeader(u64),
    /// The proposal was dropped by raft (e.g. leadership changed mid-step).
    Dropped,
}

/// Everything a node thread needs; built on the spawning side because all fields
/// are `Send`, then moved into the thread which constructs the `RawNode`.
pub struct NodeSpec {
    pub id: u64,
    pub voters: Vec<u64>,
    pub dir: std::path::PathBuf,
    pub bind: SocketAddr,
    pub peers: Vec<(u64, SocketAddr)>,
    pub seed: u64,
    pub tick_millis: u64,
    pub shutdown: Arc<AtomicBool>,
    pub observation: ObservationHandle,
    pub leadership: Arc<std::sync::Mutex<LeadershipLog>>,
    pub client_rx: Receiver<ClientProposal>,
}

/// Election-timeout bounds (in ticks). Randomized timeout lives in `[MIN, MAX)`.
const ELECTION_TICK: usize = 10;
const HEARTBEAT_TICK: usize = 3;
const MIN_ELECTION: usize = ELECTION_TICK;
const MAX_ELECTION: usize = 2 * ELECTION_TICK;

/// Run the node to completion (until its shutdown flag is set). Any storage I/O
/// error aborts the process — a node that cannot persist must not keep voting.
pub fn run(spec: NodeSpec) {
    if let Err(error) = run_inner(spec) {
        eprintln!("RAFT_ABORT node storage failure: {error}");
        std::process::exit(2);
    }
}

fn run_inner(spec: NodeSpec) -> std::io::Result<()> {
    let NodeSpec {
        id,
        voters,
        dir,
        bind,
        peers,
        seed,
        tick_millis,
        shutdown,
        observation,
        leadership,
        client_rx,
    } = spec;

    let conf_state = ConfState::from((voters.clone(), vec![]));
    let storage = FileStorage::open(&dir, conf_state)?;

    let config = Config {
        id,
        election_tick: ELECTION_TICK,
        heartbeat_tick: HEARTBEAT_TICK,
        min_election_tick: MIN_ELECTION,
        max_election_tick: MAX_ELECTION,
        // Fresh cluster members already share the static 3-voter conf state, so
        // no application-driven applied index is carried in here.
        applied: 0,
        ..Default::default()
    };
    config.validate().expect("raft config invalid");

    let logger = Logger::root(Discard, o!());
    let mut node = RawNode::new(&config, storage, &logger).expect("failed to build RawNode");
    enforce_deterministic_timeout(&mut node, seed);

    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;

    let peer_addrs: std::collections::HashMap<u64, SocketAddr> = peers.into_iter().collect();
    let tick = Duration::from_millis(tick_millis);
    let mut buffer = vec![0u8; RECV_BUFFER];

    // Per-node applied history, mirrored into the shared observation each tick.
    let mut applied: Vec<AppliedEntry> = Vec::new();
    let mut applied_ids: BTreeSet<u64> = BTreeSet::new();
    let mut last_applied: u64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Drain inbound raft datagrams and step them.
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, _from)) => match wire::decode_message(&buffer[..len]) {
                    Ok(message) => {
                        let _ = node.step(message);
                        enforce_deterministic_timeout(&mut node, seed);
                    }
                    Err(error) => eprintln!("node {id}: dropping undecodable datagram: {error}"),
                },
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        // 2. Service client proposals: only the leader can accept them.
        while let Ok(request) = client_rx.try_recv() {
            let reply = if node.raft.state == StateRole::Leader {
                match node.propose(vec![], request.id.to_le_bytes().to_vec()) {
                    Ok(()) => ProposeReply::Accepted,
                    Err(_) => ProposeReply::Dropped,
                }
            } else {
                ProposeReply::NotLeader(node.raft.leader_id)
            };
            let _ = request.reply.send(reply);
        }

        // 3. Drive the logical clock, then re-assert the deterministic timeout in
        //    case the tick triggered an internal reset.
        node.tick();
        enforce_deterministic_timeout(&mut node, seed);

        // 4. Process any Ready produced by the steps/tick above.
        process_ready(
            &mut node,
            id,
            &socket,
            &peer_addrs,
            &mut applied,
            &mut applied_ids,
            &mut last_applied,
        )?;

        // 5. Publish this node's observable state.
        let is_leader = node.raft.state == StateRole::Leader;
        let term = node.raft.term;
        if is_leader {
            leadership.lock().unwrap().record(term, id);
        }
        {
            let mut view = observation.lock().unwrap();
            view.alive = true;
            view.is_leader = is_leader;
            view.term = term;
            view.leader_id = node.raft.leader_id;
            view.applied_index = last_applied;
            view.committed_index = node.raft.raft_log.committed;
            view.applied_ids = applied_ids.clone();
            view.applied = applied.clone();
        }

        std::thread::sleep(tick);
    }

    // On cooperative shutdown, mark ourselves not alive so the checker and
    // completion logic stop expecting progress from this node.
    observation.lock().unwrap().alive = false;
    Ok(())
}

/// The canonical raft-rs 0.7 Ready loop. Ordering is load-bearing: unpersisted
/// messages first, then entries + hard state to disk, then persisted messages,
/// then apply, then advance and handle the resulting `LightReady`.
fn process_ready(
    node: &mut RawNode<FileStorage>,
    id: u64,
    socket: &UdpSocket,
    peers: &std::collections::HashMap<u64, SocketAddr>,
    applied: &mut Vec<AppliedEntry>,
    applied_ids: &mut BTreeSet<u64>,
    last_applied: &mut u64,
) -> std::io::Result<()> {
    if !node.has_ready() {
        return Ok(());
    }
    let mut ready = node.ready();

    // Messages safe to send before this Ready is persisted.
    send_messages(socket, peers, ready.take_messages());

    // A snapshot must be installed before anything else touches the log.
    let snapshot = ready.snapshot().clone();
    if !snapshot.is_empty() {
        node.mut_store().apply_snapshot(snapshot)?;
    }

    // Apply entries that committed as of this Ready.
    apply_entries(id, ready.take_committed_entries(), applied, applied_ids, last_applied);

    // Persist newly appended entries, then the hard state, BEFORE their
    // dependent messages leave the node.
    let entries = ready.take_entries();
    if !entries.is_empty() {
        node.mut_store().append(&entries)?;
    }
    if let Some(hard_state) = ready.hs().cloned() {
        node.mut_store().set_hard_state(hard_state)?;
    }

    // Messages that were only safe to send after the persist above.
    send_messages(socket, peers, ready.take_persisted_messages());

    // Advance: hand the Ready back and process the follow-up LightReady.
    let mut light = node.advance(ready);
    if let Some(commit) = light.commit_index() {
        node.mut_store().set_commit(commit)?;
    }
    send_messages(socket, peers, light.take_messages());
    apply_entries(id, light.take_committed_entries(), applied, applied_ids, last_applied);
    node.advance_apply();
    Ok(())
}

fn apply_entries(
    id: u64,
    entries: Vec<Entry>,
    applied: &mut Vec<AppliedEntry>,
    applied_ids: &mut BTreeSet<u64>,
    last_applied: &mut u64,
) {
    for entry in entries {
        let index = entry.get_index();
        // Invariant: the applied index never regresses.
        if index <= *last_applied && *last_applied != 0 {
            eprintln!(
                "RAFT_VIOLATION node {id}: applied index regressed from {} to {index}",
                *last_applied
            );
            std::process::exit(1);
        }
        *last_applied = index;

        let data = entry.get_data().to_vec();
        // Client payloads are EntryNormal with an 8-byte id; raft's own no-op
        // leader entry is EntryNormal with empty data and is not counted.
        if entry.get_entry_type() == EntryType::EntryNormal && data.len() >= 8 {
            let mut id_bytes = [0u8; 8];
            id_bytes.copy_from_slice(&data[..8]);
            applied_ids.insert(u64::from_le_bytes(id_bytes));
        }
        applied.push(AppliedEntry {
            index,
            term: entry.get_term(),
            data,
        });
    }
}

fn send_messages(
    socket: &UdpSocket,
    peers: &std::collections::HashMap<u64, SocketAddr>,
    messages: Vec<Message>,
) {
    for message in messages {
        if let Some(addr) = peers.get(&message.get_to()) {
            // A dropped datagram is a legitimate network event; raft recovers
            // via retransmission, so send failures are non-fatal here.
            let _ = socket.send_to(&wire::encode(&message), addr);
        }
    }
}

/// Overwrite raft's `thread_rng`-seeded election timeout with a value that is a
/// pure function of `(seed, node id, current term)`. raft-rs draws its timeout
/// from `rand::thread_rng()` (see README, "randomness"), which is NOT seedable
/// through `Config`; this override is the seam the Patina phase uses to make
/// elections reproducible. Distinct per node so terms still break split votes.
fn enforce_deterministic_timeout(node: &mut RawNode<FileStorage>, seed: u64) {
    let term = node.raft.term;
    let id = node.raft.id;
    let span = (MAX_ELECTION - MIN_ELECTION) as u64;
    let timeout = MIN_ELECTION + (splitmix64(seed, id, term) % span) as usize;
    node.raft.set_randomized_election_timeout(timeout);
}

/// A cheap deterministic mix of three integers into a `u64`.
fn splitmix64(seed: u64, id: u64, term: u64) -> u64 {
    let mut z = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(id.wrapping_mul(0xD1B5_4A32_D192_ED03))
        .wrapping_add(term.wrapping_mul(0xA076_1D64_78BD_642F));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
