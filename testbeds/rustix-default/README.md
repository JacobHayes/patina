# rustix-default — the SUD acceptance MRE

A minimal `std` + [`rustix`](https://github.com/bytecodealliance/rustix) program
on rustix's **default backend**. On Linux that backend (`linux_raw`) issues raw
inline `syscall` instructions with no libc wrapper — the exact binary class that
Patina's import audit cannot see (no import symbols) and its instruction scan
refuses (a `direct-syscall` finding). This is the program that was **unrunnable**
under the deterministic runtime before syscall-user-dispatch (SUD).

Under SUD the shim arms `PR_SET_SYSCALL_USER_DISPATCH` (allowed region = glibc's
text, NULL selector) and each raw `syscall` instruction outside glibc delivers a
synchronous `SIGSYS` that the shim decodes and routes into the **same** `patina_*`
runtime entries the C interposers use. So this program observes virtual time, the
deterministic filesystem, seed-derived entropy, and SimNet — deterministically.

What it exercises (all via raw syscalls on the default backend):

- **clocks** — `clock_gettime(MONOTONIC/REALTIME)` read the virtual clock;
- **sleep** — `clock_nanosleep` advances virtual time;
- **filesystem** — `openat`/`write`/`read`/`close`/`fstat` over the deterministic FS;
- **directory iteration** — `rustix::fs::Dir` → raw `getdents64` over a directory fd
  (the SUD layer models the directory fd, snapshotting through the same
  `patina_read_dir` the interposed `opendir` uses);
- **entropy** — `getrandom` returns seed-derived bytes;
- **network** — a UDP loopback (`socket`/`bind`/`sendto`/`recvfrom`/`getsockname`)
  and a TCP socket lifecycle (`socket`/`setsockopt`/`bind`/`listen`/`close`) over
  SimNet.

## Running

```sh
./run-patina.sh
```

This testbed is **SUD-only**. SUD needs the kernel's generic-entry code (x86_64
≥ 5.11; arm64 does not have it yet), so on a non-SUD kernel or a non-Linux host
`run-patina.sh` prints a **loud, counted** `rustix-default: SKIPPED 1 …` line and
exits 0 — never a silent pass. Where SUD is present (GitHub CI's x86_64 runners)
it asserts: the binary audits as `direct-syscall (SUD-managed)`, runs with the
expected `RUSTIX_RESULT`, is byte-identical across same-seed repeats, varies its
entropy across seeds, and records/replays byte-identically, then prints
`RUSTIX_LEGS_RAN branch=sud …`.

## Why it is the MRE

`cargo patina build` injects `--cfg rustix_use_libc` (rustix's own escape hatch,
flipping it to interposable libc imports) **only on non-SUD targets** now; on
x86_64 it is dropped, because SUD traps the raw syscalls instead. So a green
`run-patina.sh` here is the end-to-end proof that the default rustix backend runs
deterministically under SUD with no build-time workaround.
