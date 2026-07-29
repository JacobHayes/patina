//! The in-process clients: subscriber tasks (frame reader, per-topic sequence
//! checking, liveness timeout) and publisher tasks (seeded workload, ACK-paced
//! publishing). Two of the three planted bugs live here — the frame reader's
//! one-read-one-frame assumption and the stale liveness deadline — and the
//! third (the lost start wakeup) is the [`StartGate`] the publishers await.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};

use crate::{fnv, splitmix64, topic_name, Bug};

/// Per-topic delivery facts: the message count and an ORDER-INVARIANT payload
/// digest (a wrapping sum of per-message FNV values), so publisher
/// interleavings on a shared topic cannot perturb it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TopicFacts {
    pub count: u64,
    pub digest: u64,
}

impl TopicFacts {
    pub fn note(&mut self, payload: &str) {
        self.count += 1;
        self.digest = self.digest.wrapping_add(fnv(payload));
    }
    pub fn absorb(&mut self, other: &TopicFacts) {
        self.count += other.count;
        self.digest = self.digest.wrapping_add(other.digest);
    }
}

/// A buffered line reader over one read half. The clean path carries leftover
/// bytes between calls; `Bug::DropReadRemainder` plants the classic readiness
/// misassumption instead.
pub struct LineReader {
    read: OwnedReadHalf,
    buffer: Vec<u8>,
    drop_remainder: bool,
}

impl LineReader {
    pub fn new(read: OwnedReadHalf, drop_remainder: bool) -> Self {
        LineReader {
            read,
            buffer: Vec::new(),
            drop_remainder,
        }
    }

    /// The next `\n`-terminated line, or `None` at EOF.
    pub async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            if let Some(pos) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = String::from_utf8_lossy(&self.buffer[..pos]).into_owned();
                if self.drop_remainder {
                    // BUG(drop-read-remainder): one readiness event is assumed
                    // to deliver exactly one frame, so every byte after the
                    // first newline of the buffered read is DISCARDED. Whenever
                    // the broker's writes coalesce into one read, the dropped
                    // lines surface as a per-topic sequence gap.
                    self.buffer.clear();
                } else {
                    self.buffer.drain(..=pos);
                }
                return Ok(Some(line));
            }
            let mut chunk = [0u8; 1024];
            let n = self.read.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }
}

pub struct SubscriberSpec {
    pub id: u32,
    pub addr: String,
    pub topics: Vec<String>,
    /// Per-message pacing (the designated slow subscriber), `ZERO` otherwise.
    pub pace: Duration,
    pub idle_limit: Duration,
    pub bug: Bug,
    pub ready: mpsc::Sender<u32>,
    pub report: mpsc::Sender<SubscriberReport>,
}

pub enum SubOutcome {
    Finished,
    /// The liveness timeout fired (on a clean run the heartbeats make this
    /// unreachable, so it audits as a violation).
    TimedOut,
    /// A protocol invariant broke: sequence gap, malformed frame, or a message
    /// for a topic this subscriber never subscribed to.
    Violation(String),
    /// Unexpected transport failure (connect/read error, EOF before FIN).
    Failed(String),
}

pub struct SubscriberReport {
    pub id: u32,
    pub received: BTreeMap<String, TopicFacts>,
    pub outcome: SubOutcome,
}

pub async fn subscriber(spec: SubscriberSpec) {
    let mut received = BTreeMap::new();
    let outcome = run_subscriber(&spec, &mut received).await;
    let _ = spec
        .report
        .send(SubscriberReport {
            id: spec.id,
            received,
            outcome,
        })
        .await;
}

async fn run_subscriber(
    spec: &SubscriberSpec,
    received: &mut BTreeMap<String, TopicFacts>,
) -> SubOutcome {
    let stream = match TcpStream::connect(&spec.addr).await {
        Ok(stream) => stream,
        Err(error) => return SubOutcome::Failed(format!("connect: {error}")),
    };
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, spec.bug == Bug::DropReadRemainder);
    let hello = format!("SUB {}\n", spec.topics.join(","));
    if let Err(error) = write.write_all(hello.as_bytes()).await {
        return SubOutcome::Failed(format!("subscribe write: {error}"));
    }
    match reader.next_line().await {
        Ok(Some(line)) if line == "OK" => {}
        Ok(other) => return SubOutcome::Failed(format!("expected OK, got {other:?}")),
        Err(error) => return SubOutcome::Failed(format!("subscribe read: {error}")),
    }
    let _ = spec.ready.send(spec.id).await;

    let mut next_seq: BTreeMap<&str, u64> = spec.topics.iter().map(|t| (t.as_str(), 0)).collect();
    // BUG(stale-timeout): the liveness deadline is computed ONCE here and never
    // re-armed, so heartbeats and messages the clean per-read timeout would
    // reset it with instead race a deadline that silently expired mid-run.
    let stale_deadline = Instant::now() + spec.idle_limit;
    loop {
        let next = reader.next_line();
        let line = if spec.bug == Bug::StaleTimeout {
            match timeout_at(stale_deadline, next).await {
                Ok(line) => line,
                Err(_) => return SubOutcome::TimedOut,
            }
        } else {
            match timeout(spec.idle_limit, next).await {
                Ok(line) => line,
                Err(_) => return SubOutcome::TimedOut,
            }
        };
        let text = match line {
            Ok(Some(text)) => text,
            Ok(None) => return SubOutcome::Failed("eof before FIN".into()),
            Err(error) => return SubOutcome::Failed(format!("read: {error}")),
        };
        if text == "FIN" {
            return SubOutcome::Finished;
        }
        if text.starts_with("HB ") || text == "OK" {
            continue;
        }
        let Some((topic, seq, payload)) = parse_msg(&text) else {
            return SubOutcome::Violation(format!("malformed-frame {text:?}"));
        };
        let Some(expected) = next_seq.get_mut(topic) else {
            return SubOutcome::Violation(format!("unsubscribed-topic {topic}"));
        };
        *expected += 1;
        if seq != *expected {
            return SubOutcome::Violation(format!("seq-gap {topic} got={seq} expected={expected}"));
        }
        received.entry(topic.to_owned()).or_default().note(payload);
        if !spec.pace.is_zero() {
            sleep(spec.pace).await;
        }
        // Replenish one delivery credit now that the message is processed —
        // the subscriber's half of the credit-window flow control, so a slow
        // subscriber meters the broker instead of the socket buffer absorbing
        // the whole workload.
        if let Err(error) = write.write_all(b"CR 1\n").await {
            return SubOutcome::Failed(format!("credit write: {error}"));
        }
    }
}

/// `MSG <topic> <seq> <payload>` → `(topic, seq, payload)`.
fn parse_msg(text: &str) -> Option<(&str, u64, &str)> {
    let rest = text.strip_prefix("MSG ")?;
    let (topic, rest) = rest.split_once(' ')?;
    let (seq, payload) = rest.split_once(' ')?;
    Some((topic, seq.parse().ok()?, payload))
}

/// How publishers learn the workload may start (all subscribers registered).
pub enum StartGate {
    /// A LEVEL signal: `watch` stores the state, so a late-arriving waiter
    /// still observes it. The correct tool.
    Level(watch::Receiver<bool>),
    /// BUG(lost-wakeup): an EDGE broadcast — `Notify::notify_waiters` stores no
    /// permit, so a publisher that has not yet reached its await when the
    /// signal fires misses it forever and the run never converges. The signal
    /// fires right after the publishers are spawned, before any has been
    /// polled, so the edge is always lost.
    Edge(Arc<Notify>),
}

pub struct PublisherSpec {
    pub id: u32,
    pub addr: String,
    pub seed: u64,
    pub messages: u64,
    pub topics: u32,
    pub gate: StartGate,
}

/// Publish the seeded workload, one in-flight message at a time (write PUB,
/// await ACK), and return the per-topic published facts. The connection opens
/// before the start gate (connections are established during startup; the gate
/// governs only when the workload begins).
pub async fn publisher(mut spec: PublisherSpec) -> Result<BTreeMap<String, TopicFacts>, String> {
    let stream = TcpStream::connect(&spec.addr)
        .await
        .map_err(|error| format!("publisher-{} connect: {error}", spec.id))?;
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, false);
    match &mut spec.gate {
        StartGate::Level(rx) => {
            rx.wait_for(|started| *started)
                .await
                .map_err(|_| "start gate dropped".to_string())?;
        }
        StartGate::Edge(notify) => notify.notified().await,
    }
    let mut published: BTreeMap<String, TopicFacts> = BTreeMap::new();
    for index in 0..spec.messages {
        let topic = topic_name(((u64::from(spec.id) + index) % u64::from(spec.topics)) as u32);
        let payload = format!(
            "{:016x}",
            splitmix64(
                spec.seed
                    .wrapping_add(u64::from(spec.id) << 40)
                    .wrapping_add(index)
            )
        );
        write
            .write_all(format!("PUB {topic} {payload}\n").as_bytes())
            .await
            .map_err(|error| format!("publisher-{} write: {error}", spec.id))?;
        match reader.next_line().await {
            Ok(Some(line)) if line.starts_with("ACK ") => {}
            other => {
                return Err(format!("publisher-{} expected ACK, got {other:?}", spec.id));
            }
        }
        published.entry(topic).or_default().note(&payload);
    }
    write
        .write_all(b"DONE\n")
        .await
        .map_err(|error| format!("publisher-{} done: {error}", spec.id))?;
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_frames_parse_and_reject_garbage() {
        assert_eq!(parse_msg("MSG t0 3 abc"), Some(("t0", 3, "abc")));
        assert_eq!(parse_msg("MSG t0 x abc"), None);
        assert_eq!(parse_msg("MSGT t0 3"), None);
    }

    #[test]
    fn topic_facts_digest_is_order_invariant() {
        let (mut forward, mut reverse) = (TopicFacts::default(), TopicFacts::default());
        forward.note("a");
        forward.note("b");
        reverse.note("b");
        reverse.note("a");
        assert!(forward == reverse);
    }
}
