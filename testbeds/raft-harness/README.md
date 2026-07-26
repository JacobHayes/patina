# raft-harness — tikv/raft cluster testbed for Patina

A 3-node [tikv `raft`](https://crates.io/crates/raft) cluster running in **one
process**, driven to consensus over real loopback UDP with **file-backed** raft
logs. This is the native-only scaffolding; a later change runs the *same* binary
under Patina to explore message drop/reorder/partition and crash-restart
interleavings deterministically.

This package is a **standalone workspace** (note the empty `[workspace]` table in
`Cargo.toml`); it is intentionally not a member of the root Patina workspace and
does not touch `crates/` or the root manifest.

### Std-pure by design

The harness binary is **100% std-only**: no Patina crate imports, no
`cfg(patina)` blocks, nothing that knows Patina exists. Fault topology (message
loss, reorder, partition, crash) is injected by Patina's experiment plane later,
not by code here. Consequently the native↔Patina swap is *only* the runner
command, with **identical harness args**:

```
native :  cargo run --release        -- <harness args>
patina :  cargo patina run --release -- <harness args>
```

All invariants live **inside** the binary: any violation prints `RAFT_VIOLATION`
and exits non-zero. Shell scripts only orchestrate and check the exit code and
the `RAFT_RESULT` line.

## Build & run

```sh
cargo build --release
./run-native.sh          # healthy + one-node-down scenarios, asserts committed == proposals
cargo test --release     # unit tests for the invariants, leadership, and log format
```

`run-native.sh` puts the runner in a single `RUNNER` variable (default
`cargo run --release --`). To dry-run the Patina invocation shape with the same
scenarios, override it: `RUNNER='cargo patina run --release --seed 1 --' ./run-native.sh`.
`run-patina.sh` is the (UNTESTED) sketch of the real Patina phase.

Binary flags:

```
raft-harness [--seed N] [--proposals N] [--timeout-secs N] [--base-port N]
             [--data-dir PATH] [--tick-millis N] [--kill-node ID] [--kill-after-secs N]
```

Final stdout line:

```
RAFT_RESULT seed=<s> proposals=<n> committed=<n> terms=<max_term> applied_hash=<hex64>
```

`applied_hash` is SHA-256 (64 hex chars) over the applied-entry sequence
(`index || term || len || data` per entry) of the agreed prefix shared by all
alive nodes. It is identical across nodes on success; a divergence fails the run.

## Architecture

```
                    single OS process
  ┌───────────────────────────────────────────────────────────────┐
  │                                                                 │
  │   driver thread (seeded)                                        │
  │     - finds current leader from observations                    │
  │     - proposes unique payloads 0..N, retries un-applied ids     │
  │     - checks invariants continuously; prints RAFT_RESULT        │
  │        │ mpsc ClientProposal          ▲ Arc<Mutex<Observation>> │
  │        │ (client->node, NOT raft)     │ (role/term/applied)     │
  │        ▼                              │                         │
  │   ┌─ node 1 thread ─┐   ┌─ node 2 ─┐   ┌─ node 3 ─┐             │
  │   │ RawNode<File-   │   │  RawNode  │   │  RawNode  │            │
  │   │   Storage>      │   │           │   │           │           │
  │   │ tick every 100ms│   │           │   │           │           │
  │   │ Ready loop      │   │           │   │           │           │
  │   └──┬────────┬─────┘   └─────┬─────┘   └────┬──────┘           │
  │      │ files  │ UDP           │ UDP          │ UDP              │
  │      ▼        └───────────────┴──────────────┘                 │
  │  node1/ dir      127.0.0.1 datagrams (raft messages only)      │
  │  (entries.log,   :4001  :4002  :4003                           │
  │   hardstate.bin,                                               │
  │   snapshot.bin)                                                │
  └───────────────────────────────────────────────────────────────┘
```

- **Inter-node raft messages** travel exclusively over `std::net::UdpSocket` on
  `127.0.0.1` with fixed ports, so Patina's SimNet interposition applies later.
  There are no channels for raft traffic.
- The **only** non-socket path is client→leader proposal injection (an mpsc
  channel). That is a client request, not a raft message, and is explicitly out
  of scope for network fault injection.
- Node threads never share their `RawNode`. Each publishes an
  `Arc<Mutex<NodeObservation>>` for the driver and invariant checker.

### Port map

| node id | UDP bind (`--base-port 4001`) |
|--------:|-------------------------------|
| 1       | `127.0.0.1:4001`              |
| 2       | `127.0.0.1:4002`              |
| 3       | `127.0.0.1:4003`              |

Node `i` binds `base_port + (i - 1)`.

## Ready-loop contract (as implemented)

Each tick follows the canonical raft-rs 0.7 sequence (`src/node.rs`,
`process_ready`). Ordering is load-bearing — **entries and hard state reach disk
before the messages that depend on them are sent**:

1. `take_messages()` — send messages safe to transmit *before* this Ready is persisted.
2. If `!ready.snapshot().is_empty()` — `apply_snapshot` (persist + install) first.
3. `take_committed_entries()` — apply to the state machine.
4. `append(entries)` — **persist** newly appended log entries (fsync).
5. `set_hard_state(hs)` — **persist** the hard state (fsync).
6. `take_persisted_messages()` — send messages that were only safe *after* the persist above.
7. `advance(ready)` → `LightReady`:
   - `set_commit(commit_index)` — persist the advanced commit index;
   - `take_messages()` — send follow-up messages;
   - `take_committed_entries()` — apply;
   - `advance_apply()`.

## Invariants

Checked continuously in the driver loop and again after all nodes stop; a
violation prints `RAFT_VIOLATION …` and exits non-zero.

- **At most one leader per term** — each node records `(term, id)` whenever it
  observes its own leader role into a shared `LeadershipLog`; any term with two
  distinct ids is a violation.
- **Log matching** — applied entries agree in content *and* order across all
  alive nodes on their common prefix (`index`, `term`, `data` compared per position).
- **Every acked proposal eventually applied on all nodes** — the driver
  re-proposes any id not yet applied everywhere; success requires
  `committed == proposals`, i.e. every payload applied on every alive node.
- **Applied index never regresses** — enforced inside each node's apply loop
  (`src/node.rs`, `apply_entries`); a regress exits immediately.

These are exercised by unit tests (`cargo test`) with deliberately divergent
inputs, so the checks are known to bite rather than pass vacuously.

## Storage file format

Per node, under `<data-dir>/node<id>/` (`src/storage.rs`). Reads delegate to
raft's own `MemStorage` (correct first-index/compaction/bounds behaviour); every
durable mutation is mirrored to files:

| file            | contents                                                        |
|-----------------|-----------------------------------------------------------------|
| `hardstate.bin` | whole-file prost-encoded `HardState`, replaced atomically       |
| `snapshot.bin`  | whole-file prost-encoded `Snapshot` (only when a snapshot exists)|
| `entries.log`   | length-prefixed prost `Entry` records: `u32` LE length + bytes  |

- `entries.log` is **rewritten in full** from the authoritative in-memory log on
  every persist. O(n), but the format stays trivial and raft's conflicting-suffix
  truncation is handled for free.
- Every file is written **atomically with explicit sync**: stage `*.tmp`, `flush`
  + `sync_all`, `rename` over the target, then fsync the directory. These sync
  points are the fault boundaries the crash-injection phase interposes on.
- `FileStorage::open` reconstructs a node from whatever survived: apply
  `snapshot.bin` (or seed the static conf state), replay `entries.log`, then load
  `hardstate.bin`. A torn final `entries.log` record is reported, not silently
  dropped. Restart is verified natively by pointing a second run at a populated
  data dir — the reconstructed log hashes identically.

## Dependency choice: prost codec + raft 0.7.0 pinned exact

- `raft = "=0.7.0"` pinned exact, `default-features = false, features = ["prost-codec"]`.
- **Why prost, not the default `protobuf-codec`:** `raft-proto`'s build script
  runs `protoc` for *both* codecs. This host's `protoc` is `libprotoc 35.1`, whose
  version string `protobuf-build 0.14` cannot parse (and its bundled fallback
  isn't available for arm64 macOS), so `protobuf-codec` fails to build. The
  `prost-codec` path uses `prost-build`, which accepts the host `protoc` on `PATH`
  as-is. **No system packages are installed** — `protoc` is already present.
- `prost = "0.11"` (matches `raft-proto`) is used directly to encode/decode the
  `eraftpb` messages for both the on-disk log and the UDP wire.
- `slog` with a `Discard` drain satisfies raft's logger API silently. `sha2` backs
  the applied-sequence digest.

## Randomness: election-timeout entropy (important for Patina)

raft-rs randomizes each node's election timeout in
`reset_randomized_election_timeout` via **`rand::thread_rng().gen_range(min..max)`**
(`raft-0.7.0/src/raft.rs:2810`). This entropy is **NOT seedable through `Config`** —
`thread_rng` is OS/thread-seeded.

The harness therefore overrides it deterministically. After construction, after
every `step`, and after every `tick`, `enforce_deterministic_timeout`
(`src/node.rs`) calls the public seam
`RawNode.raft.set_randomized_election_timeout(t)` with `t` a **pure function of
`(seed, node id, term)`** in `[min_election_tick, max_election_tick)`. This makes
elections reproducible regardless of whether Patina interposes `thread_rng`'s
`getrandom` entropy, and spreads timeouts per node/term to avoid split votes.
(Native runs are not required to be seed-deterministic — real threads and real
UDP — but this seam is what the Patina phase relies on.)

## Patina-phase plan (later change)

Run the same binary under `cargo patina native-run` (see `run-patina.sh`, an
**untested sketch**). Under Patina, `std::thread` (deterministic scheduler),
`std::net` UDP/TCP (SimNet over loopback), and `std::time` (`sleep` advances
virtual time) are interposed, so a `--seed` reproduces an entire world.

Planned exploration:

- **Message loss / reorder** — SimNet drops and reorders datagrams; raft must
  recover via retransmission while invariants hold.
- **Partitions** — isolate a node or split the cluster; a minority cannot elect,
  a majority keeps committing; healing re-converges.
- **Crash-restart from files** — fault an injected `FileStorage` fsync point
  mid-write, then re-open the node from whatever bytes survived
  (`FileStorage::open`), asserting log matching still holds after recovery.
- **Seed sweeps** — enumerate seeds (`explore` / a `--seed` loop) to shake out
  rare interleavings; `native-run --record` + `minimize` shrink any failing seed
  to a minimal boundary trace.

### Known risks / notes for the Patina phase

- **UDP datagram size** — one encoded raft `Message` must fit a single datagram
  (recv buffer 64 KiB). Small proposals are fine; large `MsgAppend` batches or
  snapshot messages could exceed a datagram. The native harness never triggers a
  snapshot (no compaction); the Patina phase should either bound message size
  (`Config.max_size_per_msg`) or add framing before enabling snapshots.
- **Port binding** — fixed ports; native runs use distinct ranges to avoid
  lingering binds, and back-to-back rebinds on the same ports were verified clean.
  Under Patina the ports are virtual.
- **Sleep granularity** — the 100 ms tick and `election_tick = 10` mean elections
  take ~1-2 s of virtual time; adjust `--tick-millis` if a scenario needs finer
  interleaving.
- **raft-rs internal `thread_rng`** — see the randomness section above; the
  deterministic-timeout override is the seam that neutralizes it.
