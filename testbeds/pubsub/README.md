# pubsub

A pub-sub broker on one tokio current-thread runtime. The broker, 4 subscribers and 2
publishers (16 messages each) talk over loopback TCP with a line protocol. Subscribers meter
delivery with credits, the broker sends a heartbeat after 40 ms of quiet, and a subscriber that
hears nothing for 150 ms gives up. The last subscriber takes only a topic no one publishes to,
so it lives on heartbeats. At the end the program checks that every subscriber got every
message of its topics, in sequence; a breach is a `patina_dst::violation` under the invariant's
name. Clients do not reconnect, so clean runs use delayed and chunked TCP delivery but not
resets or refused connections.

Planted bugs (`--bug NAME`), each found by the schedule alone:

- `lost-wakeup`: publishers are started by an edge (`Notify::notify_waiters`) fired before
  they wait, so the run never converges (`failure`).
- `drop-read-remainder`: the subscriber keeps only the first line of each read
  (`seq-gap`).
- `stale-timeout`: the subscriber's idle deadline is set once at connect and never re-armed
  (`liveness-timeout`).

```sh
./sim.sh                    # build, then sweep the clean program and every bug over seeds 1..200
SEEDS=50 ./sim.sh
cargo build --release && patina run --seed 1 --fault net-delay-ms=0..40 -- target/release/pubsub
```
