//! pubsub — a minimal single-process tokio pub-sub broker under Patina.
//!
//! One process runs a **broker** (TcpListener fan-in, per-topic registry,
//! per-subscriber bounded queues, heartbeat timers), **subscriber** tasks, and
//! **publisher** tasks, all as tokio tasks on one current-thread runtime over
//! loopback TCP. Readiness multiplexing IS the app's core problem — many
//! connections, timers, and backpressured queues on one event loop — which is
//! why it is an async program: this is the classic single-threaded broker
//! architecture (an I/O-bound fan-out gains nothing from CPU parallelism).
//! Under Patina, mio's selector runs on the deterministic readiness reactor
//! (kqueue on macOS, epoll on Linux) and every timer on the virtual clock.
//!
//! Self-checking, workq conventions: an invariant breach prints
//! `PUBSUB_VIOLATION` (exit 1), a liveness/convergence miss prints
//! `PUBSUB_FAILURE` (exit 1), and an internal broker fault fails closed with
//! `PUBSUB_ABORT` (exit 2). The `PUBSUB_RESULT ... hash=` line is an
//! order-invariant digest over the delivery outcome: per-topic payload digests
//! are wrapping sums of per-message FNV values, so the hash does not depend on
//! how two publishers' messages interleaved on a shared topic — for a fixed
//! guest `--seed` it is identical across Patina schedule seeds and across
//! platforms.

mod broker;
mod clients;

use std::collections::BTreeMap;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use clients::{PublisherSpec, StartGate, SubOutcome, SubscriberSpec, TopicFacts};

/// Broker heartbeat period per subscriber connection. Must be shorter than
/// [`IDLE_LIMIT`] so an idle-but-alive subscriber never trips its liveness
/// timeout on a clean run.
const HEARTBEAT: Duration = Duration::from_millis(40);
/// A subscriber that sees NOTHING (no MSG, no HB) for this long declares the
/// broker dead and gives up.
const IDLE_LIMIT: Duration = Duration::from_millis(150);
/// Per-message pacing of the designated slow subscriber (id 0): keeps its
/// bounded queue full so broker backpressure and read coalescing are exercised
/// on every run.
const SLOW_PACE: Duration = Duration::from_millis(15);
/// Per-subscriber queue depth; small so the slow subscriber actually pushes
/// back on the broker's fanout.
const QUEUE_DEPTH: usize = 8;
/// Initial per-subscriber delivery-credit window (replenished one credit per
/// processed message); small so the slow subscriber's pacing meters the whole
/// pipeline on every clean run.
const WINDOW: usize = 4;

/// Planted bugs, one per async failure class, each a single legible site
/// (workq's `--bug` convention). The clean program must never trip a marker.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bug {
    None,
    /// The publisher start signal is broadcast as an EDGE (`Notify::
    /// notify_waiters`, which stores no permit) instead of a LEVEL (`watch`):
    /// fired immediately after spawning the publishers, before any of them has
    /// ever been polled to its await, the edge is lost outright — the classic
    /// spawn-then-broadcast lost wakeup — and the run never converges. The
    /// LEVEL signal is immune with identical placement.
    LostWakeup,
    /// The subscriber's frame reader assumes one readiness event delivers
    /// exactly one frame: a single `read()` is parsed for its first line and
    /// the remaining bytes are DISCARDED. Whenever fanout coalesces two `MSG`
    /// lines into one read (guaranteed for the paced slow subscriber), the
    /// dropped line surfaces as a per-topic sequence gap.
    DropReadRemainder,
    /// The subscriber's liveness deadline is computed ONCE at connect and never
    /// re-armed by traffic, so a live stream trips the idle timeout mid-run —
    /// the timeout races the heartbeats/messages that should have reset it.
    StaleTimeout,
}

impl Bug {
    pub const NAMES: &'static [&'static str] =
        &["lost-wakeup", "drop-read-remainder", "stale-timeout"];
    fn parse(name: &str) -> Option<Bug> {
        match name {
            "lost-wakeup" => Some(Bug::LostWakeup),
            "drop-read-remainder" => Some(Bug::DropReadRemainder),
            "stale-timeout" => Some(Bug::StaleTimeout),
            _ => None,
        }
    }
}

struct Options {
    seed: u64,
    topics: u32,
    subscribers: u32,
    publishers: u32,
    /// Messages per publisher.
    messages: u64,
    base_port: u16,
    timeout: Duration,
    bug: Bug,
}

fn main() {
    let options = parse_options(std::env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("error: {message}");
        eprintln!(
            "usage: pubsub [--seed N] [--topics N] [--subscribers N] [--publishers N] \
             [--messages N] [--base-port N] [--timeout-secs N] [--bug NAME]\n\
             valid --bug names: {}",
            Bug::NAMES.join(", ")
        );
        std::process::exit(2);
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    std::process::exit(runtime.block_on(orchestrate(options)));
}

/// Topic names are `t0..tN`; subscriber `i` takes two adjacent topics so every
/// topic has multiple subscribers and every subscriber multiplexes streams —
/// except the LAST subscriber, which takes only the sentinel topic `idle` that
/// no publisher ever writes. That subscriber survives the whole run on
/// heartbeats alone, so the HB path is load-bearing on every clean run: break
/// it and the idle subscriber trips its liveness timeout.
fn topic_name(index: u32) -> String {
    format!("t{index}")
}

fn subscriber_topics(id: u32, topics: u32, subscribers: u32) -> Vec<String> {
    if id + 1 == subscribers {
        return vec!["idle".into()];
    }
    vec![topic_name(id % topics), topic_name((id + 1) % topics)]
}

async fn orchestrate(options: Options) -> i32 {
    let addr = format!("127.0.0.1:{}", options.base_port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("PUBSUB_ABORT bind {addr}: {error}");
            return 2;
        }
    };
    let broker = tokio::spawn(broker::run(broker::BrokerSpec {
        listener,
        publishers: options.publishers,
        heartbeat: HEARTBEAT,
        queue_depth: QUEUE_DEPTH,
        window: WINDOW,
    }));

    // Subscribers first: each reports Ready once its SUB is acknowledged, so
    // publishers only start against a fully registered topic registry and the
    // expected-delivery audit below is exact.
    let (ready_tx, mut ready_rx) = mpsc::channel::<u32>(options.subscribers as usize);
    let (report_tx, mut report_rx) = mpsc::channel(options.subscribers as usize);
    for id in 0..options.subscribers {
        tokio::spawn(clients::subscriber(SubscriberSpec {
            id,
            addr: addr.clone(),
            topics: subscriber_topics(id, options.topics, options.subscribers),
            pace: if id == 0 { SLOW_PACE } else { Duration::ZERO },
            idle_limit: IDLE_LIMIT,
            bug: options.bug,
            ready: ready_tx.clone(),
            report: report_tx.clone(),
        }));
    }
    drop(ready_tx);
    drop(report_tx);

    // The publisher start gate: a LEVEL signal (watch) that publishers await.
    // Bug::LostWakeup swaps it for an EDGE broadcast (see [`StartGate`]).
    let (start_tx, start_rx) = watch::channel(false);
    let start_edge = std::sync::Arc::new(tokio::sync::Notify::new());

    let drive = async {
        for _ in 0..options.subscribers {
            ready_rx
                .recv()
                .await
                .ok_or_else(|| "a subscriber exited before becoming ready".to_string())?;
        }
        patina_dst::lifecycle::setup_complete(); // setup/workload boundary

        // Every subscriber is registered: launch the publishers and release the
        // start gate. The LEVEL signal reaches each publisher whenever it first
        // gets polled; the buggy EDGE broadcast fires before any just-spawned
        // publisher has ever been polled to its await, so on a cooperative
        // scheduler the wakeup is lost outright and the run never converges.
        let mut publisher_joins = Vec::new();
        for id in 0..options.publishers {
            let gate = if options.bug == Bug::LostWakeup {
                StartGate::Edge(start_edge.clone())
            } else {
                StartGate::Level(start_rx.clone())
            };
            publisher_joins.push(tokio::spawn(clients::publisher(PublisherSpec {
                id,
                addr: addr.clone(),
                seed: options.seed,
                messages: options.messages,
                topics: options.topics,
                gate,
            })));
        }
        let _ = start_tx.send(true);
        start_edge.notify_waiters();

        let mut published: BTreeMap<String, TopicFacts> = BTreeMap::new();
        for join in publisher_joins {
            let facts = join
                .await
                .map_err(|error| format!("publisher task panicked: {error}"))?
                .map_err(|error| format!("publisher io: {error}"))?;
            for (topic, fact) in facts {
                published.entry(topic).or_default().absorb(&fact);
            }
        }
        let mut reports = Vec::new();
        for _ in 0..options.subscribers {
            reports.push(
                report_rx
                    .recv()
                    .await
                    .ok_or_else(|| "a subscriber exited without reporting".to_string())?,
            );
        }
        let stats = broker
            .await
            .map_err(|error| format!("broker task panicked: {error}"))?
            .map_err(|error| format!("broker: {error}"))?;
        Ok::<_, String>((published, reports, stats))
    };

    let (published, reports, stats) = match tokio::time::timeout(options.timeout, drive).await {
        Ok(Ok(parts)) => parts,
        Ok(Err(message)) => {
            eprintln!("PUBSUB_ABORT {message}");
            return 2;
        }
        Err(_) => {
            eprintln!(
                "PUBSUB_FAILURE not-converged within {}s of virtual time",
                options.timeout.as_secs()
            );
            return 1;
        }
    };
    report(&options, &published, &reports, stats.heartbeats)
}

/// Final audit + the `PUBSUB_RESULT` line; returns the process exit code.
fn report(
    options: &Options,
    published: &BTreeMap<String, TopicFacts>,
    reports: &[clients::SubscriberReport],
    heartbeats: u64,
) -> i32 {
    let mut violations: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut delivered: u64 = 0;
    for sub in reports {
        match &sub.outcome {
            SubOutcome::Finished => {}
            // (1) Protocol invariants checked at the subscriber: per-topic seq
            //     contiguity, frame well-formedness, topic membership — and the
            //     liveness timeout, unreachable on a clean run because the
            //     heartbeat period is shorter than the idle limit.
            SubOutcome::Violation(detail) => {
                violations.push(format!("subscriber-{} {detail}", sub.id));
            }
            SubOutcome::TimedOut => {
                violations.push(format!(
                    "subscriber-{} liveness-timeout-despite-heartbeats",
                    sub.id
                ));
            }
            SubOutcome::Failed(detail) => {
                failures.push(format!("subscriber-{} {detail}", sub.id));
            }
        }
        // (2) Exact delivery: every subscriber of a topic receives every message
        //     published to it (subscribers registered before publishers start),
        //     with byte-identical payload content (order-invariant digest).
        for topic in subscriber_topics(sub.id, options.topics, options.subscribers) {
            let expected = published.get(&topic).cloned().unwrap_or_default();
            let got = sub.received.get(&topic).cloned().unwrap_or_default();
            delivered += got.count;
            if got.count != expected.count {
                violations.push(format!(
                    "incomplete-delivery subscriber-{} {topic} got={} expected={}",
                    sub.id, got.count, expected.count
                ));
            } else if got.digest != expected.digest {
                violations.push(format!("payload-divergence subscriber-{} {topic}", sub.id));
            }
        }
    }

    let total_published: u64 = published.values().map(|f| f.count).sum();
    println!(
        "PUBSUB_RESULT seed={} topics={} subscribers={} publishers={} published={} \
         delivered={} heartbeats={heartbeats} hash={}",
        options.seed,
        options.topics,
        options.subscribers,
        options.publishers,
        total_published,
        delivered,
        outcome_hash(options, published, reports)
    );
    if !violations.is_empty() {
        violations
            .iter()
            .for_each(|v| eprintln!("PUBSUB_VIOLATION {v}"));
        return 1;
    }
    if !failures.is_empty() {
        failures
            .iter()
            .for_each(|f| eprintln!("PUBSUB_FAILURE {f}"));
        return 1;
    }
    if total_published != options.messages * u64::from(options.publishers) {
        eprintln!(
            "PUBSUB_FAILURE published={total_published} != target={}",
            options.messages * u64::from(options.publishers)
        );
        return 1;
    }
    0
}

/// The order-invariant outcome fingerprint: one row per published topic and one
/// per (subscriber, topic) delivery, each carrying the topic's count and its
/// order-invariant payload digest (a wrapping sum of per-message FNV values),
/// sorted and SHA-256'd. Nothing depends on fanout interleaving or completion
/// order, so for a fixed guest seed the digest is schedule- and
/// platform-invariant. `heartbeats` is schedule-sensitive and deliberately
/// excluded (reported, workq's `attempts` convention).
fn outcome_hash(
    options: &Options,
    published: &BTreeMap<String, TopicFacts>,
    reports: &[clients::SubscriberReport],
) -> String {
    let mut rows: Vec<(u32, String, u64, u64)> = Vec::new();
    for (topic, facts) in published {
        // u32::MAX marks the publisher-side row, sorting after all subscribers.
        rows.push((u32::MAX, topic.clone(), facts.count, facts.digest));
    }
    for sub in reports {
        for (topic, facts) in &sub.received {
            rows.push((sub.id, topic.clone(), facts.count, facts.digest));
        }
    }
    rows.sort();
    let mut hasher = Sha256::new();
    hasher.update(options.seed.to_le_bytes());
    for (who, topic, count, digest) in rows {
        hasher.update(who.to_le_bytes());
        hasher.update(topic.as_bytes());
        hasher.update(count.to_le_bytes());
        hasher.update(digest.to_le_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// splitmix64: the seeded payload stream (pure function of guest seed,
/// publisher id, and message index).
pub fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// FNV-1a over a payload string, the per-message unit of the order-invariant
/// topic digest.
pub fn fnv(payload: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in payload.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        seed: 0,
        topics: 3,
        subscribers: 4,
        publishers: 2,
        messages: 16,
        base_port: 6001,
        timeout: Duration::from_secs(30),
        bug: Bug::None,
    };
    while let Some(flag) = args.next() {
        let (key, inline) = match flag.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (flag, None),
        };
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
            "--topics" => o.topics = n("--topics")? as u32,
            "--subscribers" => o.subscribers = n("--subscribers")? as u32,
            "--publishers" => o.publishers = n("--publishers")? as u32,
            "--messages" => o.messages = n("--messages")?,
            "--base-port" => o.base_port = n("--base-port")? as u16,
            "--timeout-secs" => o.timeout = Duration::from_secs(n("--timeout-secs")?),
            "--bug" => {
                let name = val("--bug")?;
                o.bug = Bug::parse(&name).ok_or_else(|| {
                    format!("unknown --bug {name:?}; valid: {}", Bug::NAMES.join(", "))
                })?;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if o.topics == 0 || o.subscribers == 0 || o.publishers == 0 || o.messages == 0 {
        return Err("--topics/--subscribers/--publishers/--messages must be at least 1".into());
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriber_topics_are_adjacent_and_wrap() {
        assert_eq!(subscriber_topics(0, 3, 4), vec!["t0", "t1"]);
        assert_eq!(subscriber_topics(2, 3, 4), vec!["t2", "t0"]);
        // The last subscriber holds only the never-published sentinel, living
        // on heartbeats alone.
        assert_eq!(subscriber_topics(3, 3, 4), vec!["idle"]);
    }

    #[test]
    fn payload_stream_is_seed_deterministic() {
        assert_eq!(splitmix64(1), splitmix64(1));
        assert_ne!(splitmix64(1), splitmix64(2));
        assert_eq!(fnv("abc"), fnv("abc"));
        assert_ne!(fnv("abc"), fnv("abd"));
    }
}
