//! The broker: a TcpListener accept loop, per-connection reader tasks feeding a
//! single-owner core actor (topic registry + fanout), and one writer task per
//! subscriber draining a bounded queue with a heartbeat timer. All state lives
//! in the core task — no shared locks; connection tasks talk to it over an mpsc
//! command channel, the idiomatic tokio actor shape.
//!
//! Backpressure is credit-window flow control (the MQTT receive-maximum /
//! AMQP link-credit shape — socket buffers alone absorb any small workload, so
//! real brokers meter on application credits): each subscriber starts with
//! `window` delivery credits and replenishes one per processed message
//! (`CR 1`), the writer blocks awaiting a credit before each MSG, the bounded
//! queue behind it fills, and the core's fanout `send().await` parks — so one
//! slow subscriber propagates pressure back through the core to the
//! publishers' ACKs (head-of-line across topics — the honest cost of a single
//! fanout actor, and exactly the coupling a deterministic schedule explorer
//! wants to poke at). While credit-stalled, the writer keeps emitting
//! heartbeats, which double as the failure detector for a subscriber that
//! departed mid-stall.
//!
//! Ordering argument for the delivery audit: a subscriber's OK is enqueued by
//! the core AFTER its Subscribe is processed, and publishers only start once
//! every subscriber has seen its OK (the app-level ready barrier), so every
//! Publish command is ordered after every Subscribe in the core's single FIFO —
//! no fanout can miss a registered subscriber. FIN rides the same per-subscriber
//! queue as the messages, so it is guaranteed to be the last line delivered.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

use crate::clients::LineReader;

pub struct BrokerSpec {
    pub listener: TcpListener,
    /// FIN broadcasts once this many publishers have sent DONE.
    pub publishers: u32,
    pub heartbeat: Duration,
    /// Per-subscriber queue depth (small, so slow subscribers push back).
    pub queue_depth: usize,
    /// Initial per-subscriber delivery-credit window.
    pub window: usize,
}

#[derive(Default)]
pub struct BrokerStats {
    /// Total HB lines written across all subscriber connections
    /// (schedule-sensitive; reported, never hashed).
    pub heartbeats: u64,
}

/// One unit queued to a subscriber's writer task. Only `Msg` consumes a
/// delivery credit; control frames flow regardless of window state.
enum SubLine {
    Msg(String),
    Control(String),
    Fin,
}

enum Command {
    Subscribe {
        topics: Vec<String>,
        queue: mpsc::Sender<SubLine>,
        writer: JoinHandle<u64>,
    },
    Publish {
        topic: String,
        payload: String,
        acked: oneshot::Sender<u64>,
    },
    Done,
}

pub async fn run(spec: BrokerSpec) -> Result<BrokerStats, String> {
    let (commands_tx, mut commands) = mpsc::channel::<Command>(64);
    // The accept loop only classifies connections and parses lines into
    // commands; it holds no broker state. Aborted after FIN — the in-process
    // workload opens no further connections.
    let accept = tokio::spawn(accept_loop(
        spec.listener,
        commands_tx,
        spec.heartbeat,
        spec.queue_depth,
        spec.window,
    ));

    let mut next_seq: BTreeMap<String, u64> = BTreeMap::new();
    let mut topic_queues: BTreeMap<String, Vec<mpsc::Sender<SubLine>>> = BTreeMap::new();
    let mut queues: Vec<mpsc::Sender<SubLine>> = Vec::new();
    let mut writers: Vec<JoinHandle<u64>> = Vec::new();
    let mut done = 0u32;

    while done < spec.publishers {
        let command = commands
            .recv()
            .await
            .ok_or("command channel closed before every publisher finished")?;
        match command {
            Command::Subscribe {
                topics,
                queue,
                writer,
            } => {
                for topic in topics {
                    topic_queues.entry(topic).or_default().push(queue.clone());
                }
                // The OK ack goes through the queue so the core enqueues it
                // strictly after processing the registration (see the module
                // ordering argument).
                queue
                    .send(SubLine::Control("OK\n".into()))
                    .await
                    .map_err(|_| "a subscriber queue closed at registration")?;
                queues.push(queue);
                writers.push(writer);
            }
            Command::Publish {
                topic,
                payload,
                acked,
            } => {
                let seq = next_seq.entry(topic.clone()).or_insert(0);
                *seq += 1;
                let line = format!("MSG {topic} {seq} {payload}\n");
                let mut departed: Vec<mpsc::Sender<SubLine>> = Vec::new();
                for queue in topic_queues.get(&topic).into_iter().flatten() {
                    // Bounded: a full queue parks the core here until that
                    // subscriber's writer drains — the backpressure edge. A
                    // send error means the subscriber's writer exited (the
                    // peer hung up): normal subscriber churn, so the broker
                    // DROPS that subscriber and keeps serving the rest — the
                    // departed subscriber's own report is what fails the run's
                    // audit, not a broker collapse.
                    if queue.send(SubLine::Msg(line.clone())).await.is_err() {
                        departed.push(queue.clone());
                    }
                }
                for dead in departed {
                    for subscribed in topic_queues.values_mut() {
                        subscribed.retain(|queue| !queue.same_channel(&dead));
                    }
                    queues.retain(|queue| !queue.same_channel(&dead));
                }
                let _ = acked.send(*seq);
            }
            Command::Done => done += 1,
        }
    }
    for queue in &queues {
        // A departure racing the shutdown is fine; FIN is best-effort.
        let _ = queue.send(SubLine::Fin).await;
    }
    accept.abort();

    let mut stats = BrokerStats::default();
    for writer in writers {
        stats.heartbeats += writer
            .await
            .map_err(|error| format!("subscriber writer panicked: {error}"))?;
    }
    Ok(stats)
}

/// Accept connections and spawn a handler per connection. The first line
/// classifies the peer: `SUB` registers a subscriber (spawning its writer
/// task), anything else is a publisher stream of `PUB`/`DONE` lines.
async fn accept_loop(
    listener: TcpListener,
    commands: mpsc::Sender<Command>,
    heartbeat: Duration,
    queue_depth: usize,
    window: usize,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(connection(
            stream,
            commands.clone(),
            heartbeat,
            queue_depth,
            window,
        ));
    }
}

/// A malformed or prematurely closed peer drops out silently here; the peer
/// task then observes a dead connection (no ACK / no OK) and fails LOUDLY
/// through its own reporting path — the fixture's clients never misbehave, so
/// this path is unreachable on a clean run.
async fn connection(
    stream: TcpStream,
    commands: mpsc::Sender<Command>,
    heartbeat: Duration,
    queue_depth: usize,
    window: usize,
) {
    let (read, mut write) = stream.into_split();
    let mut reader = LineReader::new(read, false);
    let Ok(Some(first)) = reader.next_line().await else {
        return;
    };
    if let Some(topics) = first.strip_prefix("SUB ") {
        let topics: Vec<String> = topics.split(',').map(str::to_owned).collect();
        let credits = Arc::new(Semaphore::new(window));
        let (queue_tx, queue_rx) = mpsc::channel(queue_depth);
        let writer = tokio::spawn(subscriber_writer(
            write,
            queue_rx,
            heartbeat,
            credits.clone(),
        ));
        if commands
            .send(Command::Subscribe {
                topics,
                queue: queue_tx,
                writer,
            })
            .await
            .is_err()
        {
            return;
        }
        // The subscriber's uplink carries only credit grants until it closes
        // after FIN; anything else drops the connection (loud through the
        // subscriber's own reporting path).
        while let Ok(Some(line)) = reader.next_line().await {
            let Some(granted) = line
                .strip_prefix("CR ")
                .and_then(|n| n.parse::<usize>().ok())
            else {
                return;
            };
            credits.add_permits(granted);
        }
        return;
    }
    // Publisher: `first` and every following line is `PUB <topic> <payload>`
    // until `DONE`.
    let mut line = Some(first);
    while let Some(text) = line.take() {
        if text == "DONE" {
            let _ = commands.send(Command::Done).await;
            return;
        }
        let Some((topic, payload)) = text
            .strip_prefix("PUB ")
            .and_then(|rest| rest.split_once(' '))
        else {
            return;
        };
        let (acked_tx, acked_rx) = oneshot::channel();
        if commands
            .send(Command::Publish {
                topic: topic.to_owned(),
                payload: payload.to_owned(),
                acked: acked_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let Ok(seq) = acked_rx.await else { return };
        if write
            .write_all(format!("ACK {topic} {seq}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
        line = match reader.next_line().await {
            Ok(next) => next,
            Err(_) => return,
        };
    }
}

/// Drain one subscriber's queue to its socket, interleaving HB lines whenever
/// the connection has been quiet for a full heartbeat period. Returns the HB
/// count at FIN — or on a write error, which means the subscriber hung up:
/// normal churn the core handles by dropping the queue (see the fanout path),
/// never a broker fault.
async fn subscriber_writer(
    mut write: OwnedWriteHalf,
    mut queue: mpsc::Receiver<SubLine>,
    heartbeat: Duration,
    credits: Arc<Semaphore>,
) -> u64 {
    let mut heartbeats = 0u64;
    let mut deadline = Instant::now() + heartbeat;
    loop {
        tokio::select! {
            line = queue.recv() => match line {
                Some(SubLine::Msg(line)) => {
                    // Wait out the credit window before delivering, keeping
                    // heartbeats flowing meanwhile — under a stall the HB write
                    // doubles as the departed-subscriber failure detector.
                    loop {
                        tokio::select! {
                            permit = credits.acquire() => {
                                match permit {
                                    Ok(permit) => permit.forget(),
                                    Err(_) => return heartbeats,
                                }
                                break;
                            }
                            _ = tokio::time::sleep_until(deadline) => {
                                heartbeats += 1;
                                if write
                                    .write_all(format!("HB {heartbeats}\n").as_bytes())
                                    .await
                                    .is_err()
                                {
                                    return heartbeats;
                                }
                                deadline = Instant::now() + heartbeat;
                            }
                        }
                    }
                    if write.write_all(line.as_bytes()).await.is_err() {
                        return heartbeats;
                    }
                    deadline = Instant::now() + heartbeat;
                }
                Some(SubLine::Control(line)) => {
                    if write.write_all(line.as_bytes()).await.is_err() {
                        return heartbeats;
                    }
                    deadline = Instant::now() + heartbeat;
                }
                Some(SubLine::Fin) => {
                    let _ = write.write_all(b"FIN\n").await;
                    return heartbeats;
                }
                // The core unregistered this (departed) subscriber and dropped
                // its senders.
                None => return heartbeats,
            },
            _ = tokio::time::sleep_until(deadline) => {
                heartbeats += 1;
                if write
                    .write_all(format!("HB {heartbeats}\n").as_bytes())
                    .await
                    .is_err()
                {
                    return heartbeats;
                }
                deadline = Instant::now() + heartbeat;
            }
        }
    }
}
