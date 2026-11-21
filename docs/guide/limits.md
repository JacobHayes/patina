# Limits: host setup, containers, CI, and what Patina refuses

## The host

Patina runs on Linux x86_64 and arm64, not on macOS. It makes its own sandbox and needs a kernel
that lets an ordinary user create a user namespace. `patina doctor` checks the host, one line per
requirement, and prints the fix for anything missing; its last line is `this host can run
patina` when it can.

| Host | What it needs |
|---|---|
| Debian 11 and later, Fedora, Arch, most others | nothing |
| Ubuntu 24.04 and later | an AppArmor profile for the patina executable, installed once as root (below) |
| an older kernel with `kernel.unprivileged_userns_clone=0` | that sysctl set to 1 |
| a Docker or Podman container | three options (below) |
| arm64 | Linux 6.12 or later, 4 KiB pages, one CPU model among the CPUs a run uses |

On Ubuntu 24.04 and later, `patina doctor` prints the root command that installs the profile:

<!-- no-run apparmor: needs root -->
```sh
patina doctor --print-apparmor-profile | sudo tee /etc/apparmor.d/patina >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/patina
```

The profile admits whatever file is at that one path, so install patina where only root can
write (`/usr/local/bin`, or the release's Debian package, which installs `/usr/bin/patina` with
its profile). A copy at another path is refused until it has one: run the installed binary.
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` instead lifts the restriction
for every program. On a Mac, run Patina in a Linux arm64 VM with 4 KiB pages and a 6.12 or
newer kernel. As root, Patina runs the program as the user sudo was run by.

**Containers.** A container's default profile blocks the namespaces Patina makes. Run it with
`docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined --security-opt
systempaths=unconfined ...`; on an Ubuntu 24.04 host, an ordinary user in the container also needs
the host's fix, for the path patina has inside the container.

**CI on GitHub Actions.** The `ubuntu-24.04` and `ubuntu-24.04-arm` runners need one setup line:

<!-- no-run ci: a workflow file for a GitHub Actions runner -->
```yaml
jobs:
  patina:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - run: curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
      - run: cargo build && patina sweep --seeds 1..200 -- target/debug/myprog
```

The sweep's exit status fails the job on a finding (1) or when Patina could not do what was
asked (2). Upload `patina-out` to keep the failing runs, with the program binary: a run replays
only with the same binary and Patina version.

## What the program sees

A fixed machine: 4 CPUs, a clock that starts at the same time every run, an empty writable
`/work` (its working directory and `HOME`), `/tmp`, the host's `/usr` read-only, and its own
directory read-only. Each filesystem is 256 MiB of memory (`[run] disk-mb`); a write past that
fails with `ENOSPC`, as on a full disk. The work tree is the one crash-modelled disk. Every file
in it starts with the same modification time.

## What Patina refuses

- **The network outside the run.** A connection to another host fails with `Network is
  unreachable`; names resolve only from the sandbox's `/etc/hosts`. Servers and clients must run
  inside the run, in one program, in programs it starts, or on nodes.
- **Some sockets.** TCP and UDP on loopback and between nodes work; multicast, broadcast, raw
  sockets and ancillary data are refused: the call fails with an error and `patina run` lists it
  under `refused:`.
- **What Patina does not model** ends the run `unsupported`, naming it (`timer_create`,
  `io_uring`, another process's `/proc/PID`, a 32-bit program, a full table of the runtime's:
  stop `capacity`). Neither a refusal nor `unsupported` is a bug in the program: report the
  named call.
- **A program's own sandbox.** Headless Chromium runs with its own sandbox off (`chromium
  --no-sandbox`); its namespaces and seccomp filters are not supported.

A seed reproduces a run on the same kind of host with the same Patina build and the same program
and libraries; on another CPU model or architecture it is another run. `patina replay` refuses a
changed program or another build, and a run whose mounted inputs changed ends `error`, stop
`inputs-changed`.
