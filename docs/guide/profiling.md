# Profiling: attribution, CPU flamegraphs, traces and edge coverage

Patina can profile any unmodified Linux program deterministically without relying on host
performance counters (`perf_event_open` is not needed, so profiling works inside unprivileged
containers). Every profile metric is derived either offline from a run directory or from
deterministic opt-in sidecars that never change the boundary log or the schedule.

## Profiling any existing run (`patina profile`)

Any run directory already records syscalls, virtual timestamps, blocking waits, memory mappings,
and injected faults in `boundary.log`. Run `patina profile RUNDIR` after the fact with zero
overhead during the run:

<!-- no-run profile-formats: example invocations against an existing run directory -->
```sh
patina profile patina-out/run-1
patina profile patina-out/run-1 --format json
patina profile patina-out/run-1 --format trace --out trace.json
patina profile patina-out/run-1 --format html --out report.html
```

`patina profile` attributes every run into four decoupled buckets so slow runtime intercepts
never masquerade as slow guest code:

| Bucket | What it measures |
|---|---|
| Guest user compute | Deterministic compute-point events outside `patina-rt` |
| Logical I/O and syscalls | Exact syscall counts, read/write/network byte volumes, fsyncs, futexes, and faults |
| Modeled virtual latency | Virtual clock breakdown (`compute`, `io`, `fsync`, `futex`, `net`, `sleep`, `memory`, `fault`) plus deterministic p50/p95/p99/max tail latency |
| Patina runtime tax | Wall-clock time and host intercept overhead, isolated from guest virtual time |

The memory section tracks `mmap`, `munmap`, `mremap`, and `brk` deltas over virtual time,
reporting peak mapped bytes, allocation counts, and top allocations.

### Formats and local dashboard server

| Command / Option | Output |
|---|---|
| `patina profile PATH --format summary` | Human-readable four-bucket report, top syscalls, memory peak, tail latencies, and top CPU functions |
| `patina profile PATH --format json` | Structured machine-readable profile JSON |
| `patina profile PATH --format trace` | Perfetto / Chrome Trace Event JSON (`traceEvents` with virtual microsecond timestamps, thread lanes, faults, and a `guest_memory_bytes` counter track) |
| `patina profile PATH --format folded` | Standard collapsed stack lines (`main;parse;hash 4200`) for flamegraph tools |
| `patina profile PATH --format html` | Self-contained, zero-CDN interactive HTML dashboard (virtual-time swimlane canvas, click-to-zoom CPU flamegraph, memory chart, tail-latency chart, coverage summary, and embedded JSON/trace download buttons) |
| `--out FILE` | Write the chosen format to `FILE` instead of stdout |
| `--serve` | Serve the interactive HTML dashboard locally (default `127.0.0.1:8080`, or `--serve=0.0.0.0:9090`), exposing `/`, `/profile.json`, and `/trace.json` |

### Profiling a sweep or campaign directory

Point `patina profile` at a sweep directory (a directory containing `report.json` or run
subdirectories) to inspect the whole campaign:

<!-- no-run profile-sweep: example sweep dashboard and local server commands -->
```sh
patina profile patina-out/sweep --format html --out sweep.html
patina profile patina-out/sweep --serve
```

The sweep dashboard shows the outcome breakdown, grouped findings with copyable `patina replay`
and `patina run` commands, per-seed virtual duration and syscall/fault distribution charts, and a
searchable, sortable seed table.

## Deterministic compute-point CPU flamegraphs (`--profile-cpu`)

Pass `--profile-cpu` (default interval: every 1000 compute events) or `--profile-cpu=N` to
`patina run`, `patina replay`, `patina verify`, `patina sweep`, or `patina batch`:

<!-- no-run profile-cpu: example CPU flamegraph capture against a user program -->
```sh
patina run --seed 7 --profile-cpu=200 -- ./app
patina profile patina-out/run-7 --format folded > stacks.folded
patina profile patina-out/run-7 --format html --out profile.html
```

At every N-th deterministic compute point, the runtime walks the guest frame-pointer chain
(compile C/C++/Rust guests with frame pointers kept, such as `cc -fno-omit-frame-pointer`),
filters out any address inside `patina-rt`, and appends raw stack samples and mapped image load
biases to `boot-K/cpu_profile.bin`.

- Same seed gives bit-for-bit identical `cpu_profile.bin` and `patina profile RUNDIR --format folded` output across runs.
- `boundary.log` and the run digest are completely unchanged: you can enable `--profile-cpu` on
  `patina replay RUNDIR --profile-cpu=200` to capture a CPU flamegraph of an existing run without
  re-searching for the seed.
- `patina profile` resolves guest addresses offline against `.symtab` and `.dynsym` of the mapped
  ELF binaries.

## Black-box ELF-rewriter edge coverage (`--coverage`)

Pass `--coverage` to `patina run`, `patina replay`, `patina verify`, `patina sweep`, or
`patina batch` to collect deterministic control-flow edge coverage from unmodified Linux binaries
without recompiling them:

<!-- no-run profile-coverage: example edge-coverage capture against a user program -->
```sh
patina run --seed 1 --coverage -- ./app
jq '.coverage' patina-out/run-1/result.json
```

When `--coverage` is active, Patina's load-time ELF rewriter instruments branch and call sites to
update a shared 64 KiB edge bitmap with saturating byte counters. At the end of the run, Patina
hashes each hit edge with its log2 hit-count bucket and emits a `coverage` object in
`result.json` and in `patina batch` NDJSON responses:

- `edges_hit`: number of distinct bitmap slots hit
- `total_hits`: sum of saturated hits across slots
- `edge_hashes`: sorted FNV-1a hashes of `(edge_index, hit_bucket)` for coverage-guided fuzzers
