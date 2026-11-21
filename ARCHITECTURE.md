# Architecture

How Patina runs a program deterministically, what that rests on, and where it stops. Each
part names the module that implements it. It is for maintainers; users read `patina guide`.

## The parts

```
patina (patina-cli)
 ├─ launcher        one sandbox per incarnation; fixed process state; restart after a crash
 └─ supervisor      PID 1 in the sandbox: the turn, virtual time, signals, the network wire,
     │              crash points; answers the runtime over a shared control region
     └─ guest processes, each with the runtime (patina-rt) loaded first
          runtime   traps every system call (seccomp), decides faults, writes the boundary log
          program   unmodified; its system calls reach the kernel only through the runtime
```

Three crates: `patina-proto` (no_std; everything the runtime and the supervisor must agree
on: layouts, the syscall table, records, the fault and SDK wire), `patina-rt` (the runtime,
no_std, built for the host's bare target: `x86_64-unknown-none` or
`aarch64-unknown-none-softfloat`) and `patina-cli` (the `patina` binary). The SDK
crate `crates/patina` is separate and has no dependencies. `patina-cli/build.rs` builds the
runtime and embeds it; at run time it is written once to `~/.cache/patina/rt-<hash>` and
executed from there (`launch.rs`).

The architecture seam: in the runtime, `arch/x86_64/` and `arch/aarch64/` export the same names
(the trap frame and its accessors, the system-call stub, process entry, the signal frame, the
clone trampoline, instruction sites and their patch, the stepper of a spin probe), and portable code names no register or instruction (`arch/mod.rs`). In `patina-proto`,
what both sides must agree on per architecture: system-call numbers (`nr/`), the structure
layouts and flags that differ (`abi.rs`), the instruction-site rules (`insn/`), and for arm64
the successor decoder (`step.rs`) and signal-frame records (`sigrec.rs`), compiled and tested
on every host. In `patina-cli`, the host checks (`host.rs`). One build serves one architecture;
seeds do not cross.

## The trap

The runtime is started by `execveat` with the program's path. It loads the program itself
(`loader.rs`: static or dynamic, its own stack and auxiliary vector, a seeded `AT_RANDOM`, no
vDSO), then installs a seccomp filter that traps every system call but those made by the
runtime's one system-call instruction (`syscall`; `svc #0` on arm64) (`entry.rs`, `raw.rs`,
`arch/`). Each trap lands in the runtime's SIGSYS handler: look up the
call's row, decide faults, do the call, write the boundary record, return.

What runs is resolved as the kernel's `execve` resolves it, for the first program and for every
`execve` alike (`exec.rs`, `resolve`): permission and file type, an ELF image of this
architecture and its interpreter, `#!` lines read as the kernel reads them (one optional
argument, the first 255 bytes, five nested interpreters; `proto::exec`); an interpreter's
symbolic links are checked against the paths Patina keeps from the program. A program that
cannot run ends the run `error`, stop `exec`, naming why and the kernel's errno (`unsupported`
when the kernel would run it and the runtime does not load it, as a 32-bit image); `execve`
returns that errno. `execve` loads the runtime again with the new program; `fork` is real
(`sys/proc.rs`). Signals are virtual: the kernel never delivers one to program code; the
runtime builds the signal frame on the way out of a trap (`sys/sig.rs`, the frame itself in
`arch/<arch>/sigframe.rs`), so a signal arrives only at a trap boundary: a system call, a
fault, a compute point, never in the middle of straight-line code. The frame is the kernel's
layout with its contents normalised to the registers, not to the kernel's history: no stale
fault code or address from an earlier fault (on arm64 the counter-timer reads and the
runtime's own faults leave none), unused fields and the tail zeroed. `rt_sigreturn` is
emulated: the runtime checks the frame the program hands back as the kernel does, and a
frame it would refuse ends in `SIGSEGV`, never in a fault of the runtime; the runtime reads and
writes the program's frames only through its guest copy (`guest.rs`), so a frame it cannot
write is the kernel's failed delivery (`SIGSEGV`) too. On arm64 the frame
carries the records the host's kernel writes (FP/SIMD, the fault syndrome, SVE, `TPIDR2`, the
ZA header, `FPMR`, `POR_EL0`; `proto/src/sigrec.rs`); one Patina does not build (SME's
streaming mode or ZA contents, ZT, GCS, the extra record) ends the run `unsupported`, stop
`signal-context`, naming it. The
handler returns through its own restorer; on x86_64 a handler installed without
`SA_RESTORER` is a failed delivery, as the kernel has it; on arm64 it returns through a fixed
page holding `rt_sigreturn`, and is entered with `BTYPE` set for a branch-target host. The runtime has no thread-local
storage; each thread's state sits at the base of its alternate signal stack.

## The syscall table

Every system call number has a row in `patina-proto/src/table/` with a class, a strength and
a reason; `patina --help --format json` lists them (`syscalls`). Rows, handlers and the runtime's own calls name a call
(`nr::OPENAT`), never its number: the numbers are per architecture, in `patina-proto/src/nr/`,
generated from the kernel's tables by `scripts/gen-syscalls.py`.

| Class | What happens |
|---|---|
| `Pass` | the real kernel does it inside the sandbox |
| `Virt` | answered without the kernel: clocks, randomness, futex, signals |
| `Attempt` | a non-blocking try; if it would wait, the thread parks until something changes |
| `Rewrite` | passed, then host-dependent fields rewritten (`stat`, `/proc` reads) |
| `Place` | the runtime chooses every address the kernel would have chosen |
| `Deny(errno)` | refused with an errno and recorded in `result.json`'s `refused` |
| `Stop` | the run ends `unsupported` |

A number without a row is `Stop`. Open-ended interfaces (`ioctl`, `fcntl`, `prctl`, socket
options, paths under `/proc`, `/sys`, `/dev`) are refused unless listed; the commands of
`ioctl`, `fcntl`, `prctl` and `arch_prctl` are listed with the arguments each reads
(`proto::table::cmds`), so none is let through without saying what it reads. Path arguments are
checked against that policy before any handler runs (`resolve.rs`, `path.rs`). Host values
are replaced: inode numbers, file times, `/proc` contents, the CPU count (`[run] cpus`), the
sizes `statfs` reports (every sandbox tmpfs reports the configured tmpfs size, also `/` and
`/dev`, which the host's RAM sizes).

Blocking calls are a non-blocking attempt plus a park on an I/O generation counter that the
runtime bumps after any call that can change readiness (`sys/io.rs`, `sys/poll.rs`). Pipe and
socket buffer sizes are fixed at creation, so readiness is a function of the calls made.

No thread parks while a signal it does not block is pending for it: the supervisor's park takes
a `MayPark` that only `Sup::may_block` makes (`sup/signal.rs`), so a wait a signal reached
while the thread was runnable (woken to check again, between two attempts) answers `EINTR` at
once and the runtime's restart rules for that call apply, as the kernel checks
`signal_pending` before each sleep. A signal sent later finds the thread parked and wakes it. A
process-directed signal goes to the lowest thread that does not block it and is not a `vfork`
parent (whose wait a signal does not end); when that thread
blocks it or exits before taking it, the supervisor passes it on to a parked thread that can
(`retarget`, as the kernel's `retarget_shared_pending`). `ppoll`, `pselect6` and
`epoll_pwait(2)` wait under their own mask, restored at once unless the wait was interrupted
(`ppoll` and `pselect6` answer `EINTR` instead of 0 when the mask let a pending signal in, even
with a zero timeout).
A detector checks the rule whenever nothing is runnable: a parked thread with a signal it would
take ends the run `internal`, naming it.

A signalfd is an eventfd the runtime makes and uses as a readiness flag (`sys/signalfd.rs`):
signals stay in the supervisor's pending sets. Before each poll, select and epoll attempt the
runtime makes every signalfd of the process readable exactly while a signal of its mask is
pending for the calling thread, writing it again when one became pending since the last look
(the edge `EPOLLET` reports). A read dequeues with `SigWait` and a passed deadline; the
supervisor moves the I/O generation when a signal of a mask the process holds becomes pending
(`Op::SigFd` carries the union of the masks), so a waiter checks again. Every eventfd has
one inode, so which descriptors name one signalfd (for a mask update) or one timerfd (across an
`execve`) is asked of the kernel with `kcmp`, its equality only (its order compares
kernel addresses); on a host where `kcmp` fails (a kernel built without it, a container's
seccomp profile) such a run ends `internal`, naming it.

System V shared memory is one table for the run in the supervisor (`sup/shm.rs`), with ids as
a fresh IPC namespace makes them and virtual times. A segment's memory is a memfd the
supervisor holds; `shmat` opens it as `/proc/1/fd/N` and maps it where the runtime chooses
(`sys/shm.rs`), and the futex key of the mapping is the segment's, so every process names one
queue. Attachments follow `fork`, `execve` and exit in the supervisor. At the end of an
incarnation a process crash writes the table and the memory to `FD_SHM`, a memfd the launcher
keeps for the run, and the next supervisor starts from it; any other end leaves it empty.

## The sandbox

Patina makes the sandbox itself (`sandbox.rs`): every namespace but the time namespace
unshared, uid and gid 1000, no capabilities. `/usr` is a read-only bind; `/work` (or the path `--work DIR:GUEST` gives,
`Config::work`) and `/tmp` are tmpfs; `/etc` is generated; the program's directory is a
read-only bind at the path it was given by (`config::program`), and `:copy` mounts are copies
(`sup/mod.rs`). `launch::layout` lists the mounts in order; the order is the guest's mount
table's. A path the guest ran, opened or looked for and found missing is kept in the control
region; the launcher names those the host has (`launch::not_in_sandbox`). The launcher fixes
every piece of process state a child inherits (umask, rlimits, signal dispositions, the CPU it
is pinned to, address randomization off; `sup/inherit.rs` lists each).

Three processes make it. The launcher's child sets that state, places the descriptors (the
layout as JSON at `FD_SPEC`, each generated file in a memfd), clears the ambient set, sets
`no_new_privs`, drops every capability unless it is root, and executes `patina __sandbox`, the
keeper. In order:

1. The keeper enters a user namespace: a new one mapping uid and gid 0 to the caller's own
   (`setgroups` denied), or, as root, the one the launcher made (`launch::userns`: 0 is the
   user sudo was run by, else `nobody`, and nothing else is mapped), after dropping its
   supplementary groups. It sets its parent-death signal, checking the launcher is still its
   parent, then unshares the mount, PID, network, IPC, UTS and cgroup namespaces, moves to `/`,
   and forks PID 1. A socket pair joins them.
2. PID 1 brings `lo` up (127.0.0.1/8, by netlink) and resolves the bind sources in the host's
   tree. It makes every mount a slave (`MS_SLAVE`, recursive), so nothing it mounts reaches the
   host, mounts a setup tmpfs on `/tmp`, binds a `newroot` directory there to itself and
   pivots the root to the setup tmpfs, the host's tree under `oldroot`.
3. The layout, each step under `newroot` with its parents made 0755 and `umask` 0: binds from
   `oldroot` (recursive; `nosuid`, `nodev` unless a device, `ro` unless writable, set on every
   mount under it with `mount_setattr`), `/dev` (a tmpfs with null, zero, full, random,
   urandom and tty bound from the host, a new devpts instance, `shm`, the usual links),
   `/proc` (mounted by PID 1, so it is the new PID namespace's, while the host's `/proc` is
   still attached, as the kernel requires; `sys`, `sysrq-trigger`, `irq`, `bus` bound
   read-only over themselves when writable), tmpfs (mode 0755, the size given), directories,
   links, and generated files (written 0600 on the setup tmpfs, bound read-only, unlinked).
4. The host's tree is made private, then detached (`MNT_DETACH`); the root pivots onto
   `newroot` and the setup tmpfs is detached from under it, and every mount is made private.
   No process of the sandbox has a path back to the host's tree, and nothing the host mounts
   later arrives. The generated files' descriptors are closed.
5. PID 1 makes the guests' user namespace, nested in the keeper's, uid and gid 1000 mapping 0
   (written while PID 1 is dumpable: as root, the keeper's change of uid left it not),
   drops the bounding set and sends the keeper a descriptor of it. Nothing in it owns a
   namespace: a guest cannot mount, change the hostname or the network, or make a namespace
   that does.
6. PID 1 drops every capability (`capset` 0, ambient cleared, `no_new_privs`) and checks that
   none is left, in any set or the bounding set. It restores the umask, moves to the work path,
   starts a session, sets its parent-death signal (last, since a change of credentials clears
   it), checking the keeper is still there, and executes the supervisor with `PWD` set.
7. The keeper waits for PID 1 and exits with its status. Ending PID 1 ends every process of
   the PID namespace (`launch::end_sandbox`).

What holds, and the tests that check it:

- No process of the sandbox other than the keeper has a capability, in any user namespace,
  after step 6, and none can gain one: the bounding set is empty, `no_new_privs` is set, and
  its uid is not 0 in its own namespace (`sandbox/14-views.sh` reads PID 1's sets as it
  executes the supervisor, and each view's). The keeper holds the capabilities of the outer
  user namespace only: it starts with none in the host's namespaces unless it is root, and a
  user namespace grants capabilities only in itself and the namespaces it owns, so once in
  one (step 1) it has none in the host's.
- No mount, unmount or remount made in the sandbox propagates to the host: every mount is a
  slave or private before the first is made, and private once the layout is done.
- The sandbox has no reference to the host's tree once step 4 is done: the old root is
  detached, the keeper's root and working directory moved with the pivots, and bind sources
  are resolved before it.
- A file the host offers only through a bind or generated file is read-only to the guest
  unless the layout says writable; the only device nodes are the six named and the sandbox's
  own devpts instance.
- The sandbox dies with its parent: the keeper with the launcher, PID 1 with the keeper (a
  parent-death signal each, checked after it is set), and every guest with PID 1.
- The order of the mounts is the order of the layout, so the guest's mount table, and every
  digest that reads it, is what it was before Patina made its own sandbox: the guest ledger
  gives identical digests.
- Nothing is admitted by joining a user namespace another program made: the keeper either
  makes its own or, as root, joins the one its launcher made (it refuses to make one as root,
  which would map the guests' user to the host's root).
- A guest cannot make a namespace: the runtime answers `unshare` and namespace `clone` flags
  with `EPERM` (`patina-rt` `sys/sched.rs`). The root of the tree and `/dev` are writable
  tmpfs with no size limit, as they were before: a limit would change the guest's mount table,
  and so every digest.

Not covered, as before: bind sources are resolved by path once and bound by path, so a
process of the host that can change a source between the two can redirect it (only the user
or root can).

Where AppArmor restricts unprivileged user namespaces (Ubuntu 24.04 and later), the kernel
admits the keeper's and PID 1's namespaces only for an executable with a profile that allows
`userns` (`patina doctor --print-apparmor-profile`); root, and an unrestricted host, need none.
The profile admits whatever file is at its path, so it belongs on a path only root can write
(`install.sh` says so when the path or a directory above it is the user's). Every process of
the sandbox runs under it, guests too: a guest's `unshare` is refused by the runtime, and a
namespace a native command (`patina __native`) makes is nested in the guests' user namespace
and owns nothing outside it.

Another view (`Keeper::view`): the part a node of a multi-machine run builds on. From the
keeper, a helper unshares a mount, UTS and IPC namespace, makes every mount private, mounts a
new tmpfs (`fsopen`, onto a directory opened without following links) on each path given (the
work path, `/tmp`, `/dev/shm`) and sets the hostname; its child joins the guests' user
namespace, drops every capability, closes every descriptor but 0, 1, 2 and those the caller
names, and runs the caller's function, in the sandbox's PID and network namespaces, adopted by
PID 1 when the helper exits. The helper, while it makes the view, is the one process of the
sandbox's PID namespace other than the keeper with capabilities (the keeper's, in the outer
user namespace); it executes nothing of the guest's. The helper and the process are not dumpable (a
node's first process makes itself dumpable, without capabilities, to set its own process state
just before it executes the runtime, as an exec would) and hold only the
descriptors the view needs; the process gets a new session (no terminal), `/dev/null` for any
standard descriptor not passed. The keeper must have one thread: the helper forks without
executing. `patina __sandbox-views` checks it
(`sandbox/14-views.sh`): two views, each with its own mounts, hostname, IPC, work tree and
`/tmp`, none seeing another's files, sharing the PID, network and user namespaces, with no
capability.

### Host-provided files

A host-provided file is any file not on a sandbox tmpfs: `/usr` and the host libraries, the
program's directory, `--mount` binds. Invariant: nothing about a host-provided file reaches the
guest except its path, type, mode, size, content, inode number and modification time. The
modification time stands for the content: it changes when the content does, and programs
depend on it (Python takes a cached `.pyc` only when its source's time matches the one it
recorded; a fixed time would make every run compile the standard library again). The rest of
its metadata is the host's history (a hard link made elsewhere, a `chmod`, a read, the
filesystem's allocation), so `stat`, `fstat`, `newfstatat` and `statx` report
(`sys/fs.rs::rewrite_stat`, `rewrite_statx`):

| Field | Reported |
|---|---|
| type, permission bits, size of a non-directory, `rdev` | the host's |
| inode number | the host's: the file's identity (the dynamic loader and `find` compare it), unchanged by a touch or a link; it changes when the file is replaced |
| device | the mount's index (`makedev(0, VDEV_MOUNT_BASE + i)`) |
| mtime | the host's |
| atime, ctime, btime | the mtime; `statx` always reports btime |
| link count | 1, directories too (what a filesystem that does not count subdirectories reports) |
| size of a directory | 4096 |
| block size, blocks | 4096, the size in whole 4 KiB blocks |
| owner | the overflow id (65534), whoever launched the run |
| `statx` attributes, direct-I/O alignment, subvolume | not reported (mount root kept) |

A program comparing the times of host files (`make`, a cache) compares their modification
times, as natively. A `touch` of a host file the program reads, or a file added to or removed
from a directory it lists (which moves the directory's modification time), is a change of the
program's inputs, as an edit is; a hard link made elsewhere, a `chmod`, or a read is not.
`patina replay` tells the two apart for `--mount` sources (`inputs.rs`).

`getdents` on a host directory is the kernel's: the order and offsets are the filesystem's,
the same for an unchanged directory on one host, not across hosts. `statfs` reports fixed
free counts for host filesystems.

## The supervisor

One sequential program that owns the turn: exactly one guest thread runs at a time, until it
asks the supervisor for something through its slot in the control region (`proto::ctl`). The
scheduler (`sup/sched.rs`) picks the next runnable thread with a draw from the seed. Futex
queues, the virtual clock and its timers, virtual signals, processes, parked I/O, the network
wire and crash points are all supervisor state (`sup/`).

Virtual time advances only by what the program does: each trap charges a fixed amount, and
when every thread sleeps the clock jumps to the next deadline (`sup/time.rs`). A run of a
program that sleeps an hour takes milliseconds.

## Nodes

A run with nodes (`[node.NAME]`, `patina guide nodes`) is still one sandbox, one
supervisor, one virtual clock, one log and one seed; the nodes are views inside it. Node 0 is
the driver, the command after `--`, started as in a run without nodes; nodes 1 upward are the
declared ones, in file order. A run without nodes takes the same path as before: no node table
is written (`n == 0`), no record of any node is made, and its seeds and digests are unchanged.

- **Start.** The launcher writes the node table (`proto::node::NodeTab`, after the scan
  table in the control region: names; the supervisor's first pids, statuses and cut counters)
  and passes each node's starting tree, program and environment to the keeper in the layout
  (`sandbox::Nodes`), with each node's stdio memfds at `3030 + 3(k-1)`. PID 1 keeps a socket to
  the keeper at `FD_NODES` (3024) and hands it to the supervisor. Boot is sequential and before
  any guest runs: the driver says `Hello` and waits; for each node in order the supervisor
  reserves the next slot, marks it with the node, asks the keeper to start the node
  (`Keeper::view`: its own mount, UTS and IPC namespaces, tmpfs on its work tree, `/tmp` and
  `/dev/shm`, the shared trees read-only, its hostname), and waits for its first process's
  `Hello` from that slot (`DEC_NODE_START`). The process copies its starting tree in, takes its
  stdio, sets the process state every guest inherits (`sup/inherit.rs`, as the supervisor's own
  child does) and executes the runtime, which starts as for any program. One process is
  starting at a time, so slots, pids and records come in one order. The shared trees (`/`,
  `/guest`, `:copy` mounts) are the driver's: what the driver writes there a node sees (a file,
  a path socket), read-only. That is a deliberate channel the driver has and nodes do not, as a
  shared disk would be. A node whose first process fails before its `Hello` ends the run as
  `infra` after the stall limit; one whose command cannot be loaded ends it as `exec`, naming
  the node (the runtime's host error, `HE_EXEC`, from a process that has not executed: the
  supervisor keeps the pids that have, `execed`).
- **Which node.** Every slot carries its node (`Slot::node`), set when the slot is reserved and
  inherited by threads and children; the runtime installs its filter once per node
  (`filter_installed` holds a bit per node). The supervisor writes `DEC_NODE_SLOT` when a slot
  changes node, so a reader of the log knows each record's node. The runtime reads its node in
  one place (`state::node()`, from the slot at each image start). A process's view of other
  processes is its node's: `kill`, `tgkill`, `setpgid`, `getpgid`, `getsid` and `capget` of
  another node's process answer `ESRCH`, as do process groups and `kill(-1)` (the supervisor's
  process table answers which node a pid is on, zombies included: `Op::PidNode`), and `sched_*`
  see only the node's threads. System V shared memory is one table per node (each node is its own IPC namespace).
- **Addresses and ports.** A node's address is the wire's address kind `0x10 + k`
  (`10.0.0.(k+1)`; the driver keeps `HOST4`, `10.0.0.1`). The wire keys ports, listeners and
  connections by `(node, port)`: the listener's abstract name is `@patina-l-<node << 16 | port>`;
  loopback is per node; a connection to another node's address is routed to that node. UDP
  ports are per node; in UDP's address kinds a node's own address is `HOST4` and another
  node `j`'s `0x10 + j` (the driver's `0x10`), which the supervisor routes to node `j`'s `HOST4`
  from `0x10 + sender` (`sup/udp.rs`, `rt::sys::udp`). Abstract `AF_UNIX` names live in the
  kernel's one network namespace, which every node shares: the runtime gives the kernel each
  name a node binds, connects or sends to under the node's prefix `patina-n<k>-` (under the
  reserved `patina-` names, which a guest cannot give) and takes it off every name read back
  (`rt::sys::unixname`), so a node's names are its own. Message headers are copied to runtime
  memory with the name replaced, never written in place: a guest's header may be read-only or
  shared by threads. An autobind, and the kernel's random one for an unbound socket with
  `SO_PASSCRED` (made explicit before a connect, or a datagram socket's send), is the runtime's
  counter name under the prefix. Without nodes none of this runs.
- **Control calls.** `sdk::OP_CONTROL` carries words. The runtime parses them against the node
  table (`proto::node::parse`; the supervisor cannot read a node process's memory, which is not
  its descendant), refuses `net` and `node` outside the driver's node (`EPERM`), and sends
  `Op::Net` [verb, from set, to set, both] or `Op::Node` [verb, node]; the call is logged with
  its words as an SDK call is.
- **Cuts.** The supervisor keeps two matrices of cut links (`sup/link.rs`): the script's
  (`net cut`) and the seed's (partitions); a link is cut while either says so, and `net heal`
  clears the script's only. The wire consults them when it stamps a delivery: an item on a cut
  direction is queued with no time (`HELD`) and the direction is held; when a layer opens a
  link, held items are re-stamped from that time in order (`DEC_WIRE_HEAL`). A direction held
  for Linux's give-up time (924.6 s; the sender's `TCP_USER_TIMEOUT` if set) resets its sender
  with `ETIMEDOUT`; a connect across a cut retries on the kernel's SYN schedule (`syn_retry_s`,
  for 6 retries or the socket's `TCP_SYNCNT`) and fails after the last retry (the cut is
  looked at when the SYN is sent and retried; a cut made inside a handshake's delay does not
  stop it). A datagram sent on a cut link is lost (`UF_CUT`). No fault is drawn for a cut.
- **Link faults.** A link fault (`net-*`) is drawn only on the links `net-links` names
  (`Sup::link_faulted`: between nodes other than the driver, by default); on the others an item
  gets the default delay range and no draw at all, so turning a class on draws nothing on
  them. The draws are keyed by connection or datagram as without nodes, so each direction of a
  pair of nodes has its own. With nodes an injection's record names its link (`args[1]`,
  `proto::wire::inj_link`) and its eligible counts are those of the faulted links
  (`NodeTab::elig`, `result.json`'s `nodes.faulted_links`).
- **Partitions.** `partition-gap-ms` starts a chain of node events (`Event::Node`): a start
  draws a shape and two sides of the nodes the link faults act on (`proto::node::sides`, a
  keyed shuffle), sets the seed's matrix (one direction for `oneway`; `bridge` keeps one node's
  links), records `DEC_NET_PART` and an `Injected` record (`INJ_NET_CUT`), and schedules its end
  after a drawn length; the end opens the links the script does not cut, records
  `DEC_NET_PART_END`, re-stamps what was held and schedules the next start. Every draw is on
  `Stream::Partition`, keyed by the partition's ordinal and a sub-key, so turning partitions on
  moves no other decision and no draw depends on traffic. A start does not keep a run alive
  (`sched::Live::No`): a run whose threads all wait and that has only a partition start ahead
  is deadlocked, as it would be without partitions (nothing is in flight, so the cut holds
  nothing and its heal changes nothing); an end does (`Live::Yes`), since it may release held
  traffic. A start that falls
  while faults are off makes no partition. The node table keeps the first 64 partitions (shape,
  sides, times, whether a cut link held, lost or kept back anything) for `result.json`.
- **Kill and restart.** A node is up from its first process's `Hello` until it goes down
  (`DEC_NODE_DOWN` [node, incarnation, how, status, processes killed, down time]): the seed
  kills it (`--faults kill`: a node event `crash-gap-ms` after each start that keeps a run
  alive while faults may act (`Live::AfterSetup`; outside the fault window it is only drawn
  again, and after `faults-done` it does nothing), keyed on
  `Stream::Node` by node, incarnation and try, with an `Injected` record `INJ_NODE_KILL`
  counted as `crash`), the driver does (`node kill NAME`, `Op::Node`), or its first
  process ends by itself. A kill `SIGKILL`s every live process of the node through the
  supervisor's own kill (`kill_now`, with its exit barrier: the kernel has closed every
  descriptor before anything else happens); a socket's end is then
  the kernel's and the wire's ordinary one (FIN or RST to its peers, a listener whose name the
  next connect finds gone, `ECONNREFUSED`). A first process's own end kills the node's others
  the same way and classifies the end: an exit within `ok-exit` (`NodeConf`) stops the node;
  another exit ends the run (`node-failed`, outcome `failure`), a signal Patina did not send
  too (`node-crash`, outcome `crash`). The node table keeps each incarnation's pid, times, how
  it ended and the stdio offsets where its output starts (`Boot`, at most 64 incarnations).
  Node events act only where no request is in flight that they could disturb (`node_actions`:
  before the turn holder's request is handled, or at an idle jump, after which the wire is
  stepped and I/O waiters woken, so peers see a kill at once); a kill that ends the turn
  holder's process leaves its request unserved, and a turn holder ending its own process
  (`ProcExit`) ends first. A kill or a restart waits while any slot is reserved for a process
  or thread the runtime is creating (its `Forked` not yet served) or a vfork child has not
  said `Hello`: until then the new task is in no table, and a kill would miss it. A restart (an
  event that keeps a run alive, `down-ms` after a down its `restart` policy follows, or the
  driver's `node start`) waits for the next such point after a kill in the same one (with
  nothing runnable, at once: `node_actions_idle`), takes the lowest free slot (one an exited
  thread left is replaced), clears the node's `filter_installed` bit (a new process tree needs
  the filter) and asks the keeper for incarnation K: the keeper keeps every node's mount, UTS
  and IPC namespaces from its first start (`sandbox::Saved`, received from the view's helper)
  and starts the new process in them (`Place::Again`), without the starting tree's copy and with
  `PATINA_INCARNATION=K`; its memfd stdio continues where the last left off, and the launcher
  splits it per incarnation by the offsets the keeper reported. Everything is in the turn's
  order, so kills, restarts and their records are the same in every run of a seed. The work
  tree, `/tmp` and `/dev/shm` are kept whole across a kill, as a process kill keeps the page
  cache: what a node's processes stored through a shared mapping is in the tmpfs pages and,
  through the kill's own flush, in its disk's log.
- **Disks.** Each node's work tree is a disk: the runtime marks a node's own work mount as
  the work tree (`state::work_path`, from `NodeTab::work`), so everything the crash model
  records for the driver's tree it records for a node's, in the one shared operation log,
  each record's kind tagged with its node (`proto::oplog::tag_kind`; node 0's kinds are plain,
  so a run without nodes writes the same bytes). The shadow table and the writeback-error
  generations are shared, keyed by node and inode (`node_key`); the 64 shadow memfds go to the
  keeper once (`SHADOWS_MSG`) and every node process inherits them at `FD_SHADOWS`. The
  supervisor reaches a node's tree through its first process's root (`sup/disks.rs`, an
  `O_PATH` descriptor of `/proc/PID/root/WORK` opened at that process's `Hello`) and writes
  its base records there, before it runs; reclaim and the mapping flush find each mapping's
  node by its device, and a `sync` flushes the caller's node's mappings only. At the end of the
  run every node's live tree is a record of the log (`KIND_LIVE_TREE`), and the launcher splits
  the log into one plain log per disk (`durability::log::split_nodes`: `node/NAME/inc-K/`, K
  the boot the disk began with), which `patina log ops`, the self-check (`check::disks`, run
  for every run with nodes) and `materialise` read as a single machine's.
- **Machine crash.** `node crash NAME` (`NODE_CRASH`) or the seed under `--faults crash`
  (`NodeConf::crash` `CRASH_NODE_MACHINE`, drawn as the process kills are) runs
  `nodes::node_crash` at a node action point: the node's mappings are flushed and a `Crash`
  record (`[CRASH_MACHINE, boot, point]`, tagged; point 0 for a crash at a drawn time or a
  script's) ends its disk's log; its links are cut by a third
  layer (`Links::down`) until it is back; the wire forgets its ends (`wire_machine_down`:
  their descriptors closed without a FIN or RST, `End::dead`, a `DEC_WIRE_DEAD` record), holds
  what was in flight to them so the senders' give-up clocks run, drops what the node itself
  held, frees connections within the node and connects from it, and sends a connect to it
  into SYN retries; then its processes are killed as above (their ends reach no peer). Its
  live tree is logged, its disk closed, and the tree of its next boot materialised in the
  supervisor from its disk's records in the shared log (`crash::disk_log`, `materialise` with
  the run's seed, the crash's sequence number as the key and `NodeTab::fs_model`), a pure
  function of the log as for a single machine; its System V shared memory goes. Its restart
  sends the keeper that tree (`[node, boot, 1]` and a memfd): the keeper makes a new view
  (`Place::New`: new tmpfs work tree, `/tmp`, `/dev/shm`, IPC namespace) and fills the work
  tree from it before the runtime starts, and the first `Hello` of the new boot opens the new
  disk. The links open again then (`wire_heal`), and an item that reaches a dead end resets its
  sender (`RST_UNKNOWN`), as a rebooted host answers a segment of a connection it does not
  know.
- **Faults per node.** The node classes (`disk`, `mem`, `buggify`, `crash`, `kill`, `pause`,
  `clock`) and their keys are each node's: the config resolves each node's classes and
  settings (the run's unscoped ones for every node but the driver and a node with `faults =
  false`, `@NODE` scopes) with a seed of its own (`Config::node_plan`), the driver's into the
  run's `FaultCfg` and `SdkCfg` and the others' into `NodeTab::faults` (a `FaultCtl`, settings
  and counters, per node) and `NodeTab::sdk`. The runtime reaches its node's through
  `state::faults()` and `sys::sdk::cfg()`; a fault point's site row is per node
  (`SdkTab::site_on`), its draws keyed by the node's seed. Draws stay keyed by sequence
  number; the fault window (`FaultCfg::in_window`) stays the run's.
- **Crash points per node.** The runtime's crash point (`inject::crash_point`) reads its own
  node's `FaultCtl`: each node counts its points in its own `crash_points`, and `--fault
  crash-at=N@NODE` or `crash-permille=P@NODE` (`Config::node_plan`, resolved with the node's
  seed) sets that node's `crash_at` or `crash_permille`; in such a run only the nodes a crash
  key names crash, and none at drawn times. At each start of a
  boot the supervisor arms the node's points (`Nodes::arm_points`: the counter from 0,
  `crash_enabled` while the node has boots left, `incarnation` the boot), so the N-th point is
  of that boot. A point that fires is the runtime's `CrashPoint` request; for a node the
  supervisor answers it with `node_point_crash`, the same `node_crash` as above with the point
  in its `Crash` record and its `INJ_NODE_KILL` (`crash-at` then turns itself off: it fires
  once, in the node's first boot); under `kill` (`CRASH_PROCESS`) it answers with
  `node_kill` instead, the seed's process kill, the point in its `INJ_NODE_KILL`, the disk going
  on. A point's per-mille draw is the runtime's, keyed by the
  record's sequence number as for one machine; the node's seed resolves only a range. A
  process or thread of the node being created when its point fires ends the run
  `unsupported` (a crash could not kill it); another node's creations do not matter. The node's boot table keeps each boot's point count and the
  point it crashed at (`Boot::points`, `Boot::point`), which `result.json` shows
  (`crash_points`, `downs[].point`) and `sweep --crash-points` reads to make one child per point of
  each node (`seed-S@NODE.P`, `crash-at=P@NODE`). A pair is two scoped keys
  (`crash-at=I@A`, `crash-at=J@B`). Under `[sweep] crash-pairs = K` a
  first crash's child also counts the other nodes' points (`crash-permille=0@B,...`), and one that
  ended ok gives each other node's next K points after A's `Crash` record by sequence number
  (`branch::window`, each with the number of B's records before it); each is a pair's child
  (`seed-S@A.I+B.J`), the first child's run up to B's J-th point, which B counts from its first
  boot as before, so B crashes where the first child reached that point. A pair whose B
  crashed after another number of its records is `nondeterministic`. After the run the
  launcher writes each
  crashed disk's materialised tree to `node/NAME/inc-K/post-crash/`, checks it is the base of
  the next disk, and counts what it lost against the disk's live tree (`downs[].lost`, the
  `crash` event). A node's points count only its own disk's changes and syncs, so its N-th
  point stays at the same place in its own work when another node's crashes change.
- **Pause.** `node pause NAME` / `node resume NAME` (`Op::Node`, `NODE_PAUSE`,
  `NODE_RESUME`) and the seed's pauses (`pause-gap-ms`, `pause-ms`, each node's own:
  `NodeConf::pause_*`) freeze a node's machine (`sup/pause.rs`). The scheduler keeps a set of
  frozen slots beside the runnable one (`Sched::frozen`); a frozen slot keeps its state, its
  wake and its place in the event queue but is never picked, and the idle jump and the
  deadlock check count only eligible slots, so with nothing frozen the picks and their draws
  are those of a run without pauses. Every slot whose `Slot::node` is paused is frozen
  (`refreeze`; a slot a paused node gains, `slot_node`); a turn holder of a paused node has
  its request served as at the pause and is frozen before its reply is read (`serve`, a
  `Continue` of a frozen slot chooses another). Clocks are not stopped: deadlines fall due as
  they would, and the threads they wake run at the resume. A fourth link layer
  (`Links::paused`) cuts every link to and from the node, so the wire holds what a peer sends
  (its give-up clock runs); `wire_pause` re-holds what was in flight to the node with the rest
  of its delay and sends handshakes either way into SYN retries; a datagram arriving at a
  paused node is lost (`UD_PAUSED`); keepalive timers are re-armed (`ka_arm_all`), so probes
  either way go unanswered. A resume opens the links nothing else cuts
  (`wire_heal`). A pause takes effect at a node action point, as kills do; a kill or machine
  crash of a paused node ends the pause first (`pause_down`). The seed's chain is node events
  (`EVK_PAUSE_START`, `Live::No`; `EVK_PAUSE_END`, `Live::Yes`) drawn on `Stream::Node` keyed
  by node, the pause's ordinal and a sub-key (`NSUB_PAUSE_*`), with an `Injected` record
  `INJ_NODE_PAUSE` counted as `pause`; a start skips while faults may not act, while the node
  is down or while a script has paused it. Each pause and resume is a decision record
  (`DEC_NODE_PAUSE` [node, boot, by, ordinal, length], `DEC_NODE_RESUME` [node, boot, how,
  ordinal, ns paused]); the node table keeps the first 32 of each node for `result.json`. With
  no eligible slot, a pending event that can only wake a frozen slot (its sleep's end, a
  paused node's timerfd or signal timer) keeps nothing alive (`only_frozen`): a paused node's
  interval timer would otherwise fire forever. The lost-signal check skips frozen slots (a
  process-directed signal waits for a runnable thread of the process that is frozen too). A
  deadlock's detail names the paused nodes.
- **Clocks.** One virtual time serves every node; a node's realtime clock is it plus the
  node's offset (`NodeTab::clock_off`, `sup/clock.rs`), which the runtime adds wherever it
  answers a realtime time (`sys::time`'s clocks, `vtime::now` for the times a node stamps on
  its files, System V shared memory times, `/proc/stat`'s `btime`) and subtracts where it
  converts an absolute realtime deadline to virtual time (`realtime_to_vclock`). The driver's
  offset is 0. Monotonic and boot-time clocks have none, and no clock has a rate of its own.
  The offset is each boot's skew (`clock-skew-ms`, drawn when the boot starts on
  `Stream::Node` keyed by node, boot and `NSUB_SKEW`) plus the driver's steps (`clock step`,
  `Op::Node` `CLOCK_STEP` with the change as its third argument), each a decision record
  (`DEC_NODE_CLOCK` [node, boot, how, change, offset]); a node without either writes none. A
  step moves the node's absolute realtime deadlines: the runtime says which deadline is one in
  `Slot::clock_flags` before a `Sleep`, `FutexWait` or `TimerFdSet` (outside the request, so
  the log does not change; the supervisor clears it as it reads it), the scheduler keeps it (`Entry::rt_abs`) and `retime` moves it
  (one now past wakes as a timeout), and a timerfd armed so moves too (`timers_clock_set`);
  one armed with `TFD_TIMER_CANCEL_ON_SET` gets a count written so it is readable, and the
  runtime answers its next read `ECANCELED` when its node's step count (`NodeTab::clock_sets`)
  moved since it was armed. Relative deadlines, on any clock, are virtual times and do not
  move, as the kernel keeps relative realtime timers on the monotonic base. Not modelled: a
  realtime futex wait that a stop signal interrupted resumes (`restart_syscall`) with its
  virtual deadline, so a step while it was stopped does not move it; a timerfd's
  `ECANCELED` is kept per process, not per open file, so after a fork each process holding it
  reads it once. On a node with a
  skew the runtime counts its realtime reads, and those under an offset, for the `clock`
  class (`NodeTab::clock_reads`).
- **End.** The driver's exit ends the run; the supervisor records each node that still has
  processes (`DEC_NODE_STOP`) and the launcher copies each node's stdio to
  `node/NAME/inc-K/` and the node table to `result.json`'s `nodes`.

## The boundary log

Every boundary event (a trap, a scheduling decision, an injected fault, a preemption) appends
one fixed-size record under the turn: the call, its arguments, its result and a hash of what
it wrote (`patina-proto/src/rec.rs`, `patina-rt/src/log.rs`). A record holds the arguments as
the program passed them (`Call::guest_args`), not a buffer of the runtime's that a handler
passed on instead (a resolved path, a shortened count), so no runtime address enters the log
and a change to the runtime's own layout does not move a digest. It holds only the arguments
the call reads, given the values of the others (`proto::table::nargs::live`): the count from
the kernel's trace events, less those a flag, a command or a NULL pointer leaves unread
(`mremap`'s new address without `MREMAP_FIXED` or `MREMAP_DONTUNMAP`, an anonymous `mmap`'s
descriptor, `open`'s mode without `O_CREAT` or `O_TMPFILE`, `mknod`'s device for anything but
a device node, `futex`'s by operation, `clone`'s tid words and TLS by flag, `epoll_ctl`'s event
for `EPOLL_CTL_DEL`, a signal set's size or an address length with no set or address, an
absolute `clock_nanosleep`'s remainder, the high half of `preadv`'s offset, `getcpu`'s unused
third, and for `fcntl`, `ioctl`, `prctl` and `arch_prctl` what the command's entry in
`proto::table::cmds` names). An unread register holds whatever the program's code left there,
which can differ between hosts where the program's behaviour does not (static glibc's
`memcpy` leaves another value in `x4` on an arm64 CPU with SVE than on one without). The run's digest is the hash
chain over the records.

A string the program passed that a checker needs in clear (an SDK call's label, a mark's text)
follows its call's record as `Str` records (`proto::RecKind::Str`): which string, its length,
the process, and 64 of its bytes per record, as many records as the string needs, appended
under the same turn right after the trap record, so they are in the digest and in replay's
comparison. The bytes are a copy of what the handler already read through the checked guest
copy (`sys/sdk.rs` keeps the label it was given until `log::trap` writes it), never a second
read of the program's memory. A call whose payload could not be read has none.

A call's C-string arguments follow its record the same way: each as the program passed it, read once (the bytes the input hash reads,
`log::trap_paths`), and the absolute path each walked argument resolved to, kept by the path
resolver (`resolve::prepare`) in the call's path buffers, which live in the trap entry's frame
until the record is written; `execve`'s arguments are read from the program's array, bounded
(`proto::rec::ARGV_MAX`, `ARGV_BYTES`, `PATH_BYTES`). The resolver's walk is in the
program's view of the file system, so no host path enters.

Replay runs the program again and compares record by record
(`replay.rs`); `patina log diff` names the first difference; `patina verify` repeats a seed
while changing the host and compares (`verify.rs`). A run a sweep pruned kept no logs: its
replay is compared by digest and outcome alone.

Observation (`Config::observe`, set only by `patina explain` on its replay, never in
`run.json`) keeps the first `proto::rec::OBS_BYTES` (128) bytes of each data call that moved
any (read, write, their `p` and `v` forms, send, receive) for the story `explain.rs` tells.
After the call's record is written and chained, `log::observe` appends `Observe` records
(`proto::rec::observed`: a head with the descriptor, its file type, and for a socket the
connection and addresses, then the bytes 64 per record) with `log::append_unchained`: not in
the hash chain and counted in `log_exempt`, so neither the digest nor the log limit sees them.
The bytes come from the buffer the call's own record hashed, within the length the program
gave, read through the same checked copy (`guest::read`: a page the program unmapped is a short read, never a fault), from memory
the call has already read or written; nothing about the program's state changes and no draw
is taken. An observation is written only while the log's mapping (`LOG_MAX`) keeps room for the
whole log limit and 1 MiB (what a run's last trap and the supervisor write past the limit)
besides it, so the observations never take the place of a record and a run
that ends on its limit ends at the same record (with `[run] log-limit` at its maximum there is no
room, and the story shows sizes without bytes). The runtime code that observes runs between
two segments of program code. When an incarnation ends
the launcher moves the `Observe` records out of `boundary.log` into `inc-K/observe.log`
(`log::take_observations`), outside the sandbox, so the stored log is the run's byte for byte;
`explain` then compares the replay with the run as `replay` does (records, digest, outcome)
and tells nothing when they differ. Proof that observation changes nothing is that comparison
on every replay, and `tests/cli/14-explain-cases.sh` runs it over every run of three sweeps.
`explain.rs` reads `observe.log` as untrusted: a record that does not parse is skipped, a
length is capped at what the head says and at `OBS_BYTES`, the records read are bounded, and
every payload byte is shown escaped; names, paths and labels from the program reach the
terminal with control and direction-changing characters escaped. It reuses an earlier replay
only when its marker and its own `result.json` both carry the run's digest, and refuses an
`explain` entry that is not a directory (a link would put the replay elsewhere).

A `--check` command (`check.rs`) runs after a run that ended ok, on the host and outside the
sandbox, with the run directory as its argument; it is never part of the run. `run.json`
records its words, working directory, program and SHA-256 (`Config::check`); `result.json`
records its verdict (`check`), which can turn an ok run into a `violation` (stop `check`,
signed as an `always` is) or an `error`. Its output is not in the logs or the digest. A
replay whose logs equal the run's while the verdict differs ends `error`, stop
`check-unstable`, not `nondeterministic`.
A serving checker (one whose file names `PATINA_CHECK_SERVE`, `check::serves`;
`check::Server`) is started once per sweep job by the sweep's worker thread, which lends its pipes to each `patina run` it starts (`PATINA_CHECK_SERVER`:
descriptors kept across that one exec, close-on-exec again at once in the child); the run
writes one request line and reads one verdict line, so the verdict is still made, recorded and
replayed by the run, as a per-run checker's is. A server that wrote out of turn, answered with
anything but one verdict line, or not within `[run] check-timeout`, is killed and the run is an
`error`; the worker starts another for its next run. A run with no lent server (`patina run`,
a replay, minimize), or whose server ended after its last answer, starts one for itself. Sending each run's verdict through its own `patina
run`, rather than judging in the sweep, keeps one code path for verdicts, `check.out` and
`pending`. Its cost decided the design: a Python checker started per run costs 2 to 4 times
the unchecked sweep, a server 1.0 to 1.2 times.
Judging again (`recheck.rs`) is the one exception: `recheck::rejudge` runs the checker on a
kept run directory (`check::run_on`, with a worker's server or none) and rewrites only what
follows from the verdict (`result::with_check` over the run's own end, `outcome::ok_end`),
writing `pending` first so an interrupted recheck never leaves the old verdict under the new
checker. `patina report --recheck` and a resumed sweep share it: the checker is not part of a sweep's
identity (`sweep::identity`); a run whose recorded checker differs (`recheck::same_checker`) or
whose verdict is `pending` is judged again from its logs, or run again when they were pruned
(`sweep::have`). The case (`Config::case`: id and line) is in `run.json`, so a replay and
`--config run.json` keep `PATINA_CASE_ID`.
A `--cases` line may give its own run settings before `--` (`sweep::case_line`, the flags of
`CASE_FLAGS` parsed by `patina run`'s parser); they follow the sweep's on the run's command
line. The whole line is the case's identity on resume (the `case` file); its id (its `--name`
or line number) names its directory; a checker, the report
and a known pattern see the line after its settings (`sweep::case_shown`), so a pattern
written for a case still matches once its line gains settings.
`--ok-exit` (`Config::ok_exit`, in `run.json`) is an input of `outcome::classify`: a guest
that exited with a listed status, not on a signal, ends `ok`, stop `ok-exit`, and the checker
judges it; the logs and digest are those of the run without the flag. Each incarnation's
final work tree is `inc-K/live.tree` (`durability::tree`); `patina log tree` writes it out.
A sweep keeps a run's trees compressed (`durability::kept`, from `sweep::cut`, after the run
and its checker are done with them): `live.tree.zst`, and `post-crash.tree.zst` in a run no
checker reads (`recheck::checkable`: a checker's input stays as the checker saw it, for
`recheck` and for a checker run by hand), zstd frames of the archive (`ruzstd`: pure Rust, as
the static release binary needs), checked to read back before the original goes. Every
reader takes either form (`kept::live`, `kept::post_crash`). `patina run` and `--keep all`
keep the trees whole.

`patina log events RUNDIR` (`events.rs`) is the stable export of a run directory for checkers:
one JSON line per boundary record, with each operation-log record after its call (same
`seq`; an operation whose call has no record, as when a crash point fired between the two,
goes before the first record later in virtual time) and named by replaying the namespace
(create, link, rename, unlink) as the operations go by, so a path is the one the file had at
that moment. An `Injected` record and its `Name` records become one `fault` event with the
fields `faults.recent` shows (`launcher::attribution::injected`, shared); a call's `Str`
records become fields of its event. It streams both
logs and keeps only the live names. Its fields are versioned (`v` in the header) and only
added to; `log dump` and `log ops` stay the text forms.

The logs of a run (this one and the operation log) are limited (`Config::log_limit`,
`[run] log-limit`): the append that would pass the limit ends the run instead, so the cut depends
on records, not time. The log file grows by `fallocate`, so a full host filesystem is a failed
call (`disk-full`), never a fault on a store through the mapping.

## Scheduling points

The scheduler can switch threads only where a thread enters the runtime. Those points are:

- **System calls.** Every trap is a point.
- **Pause points.** Every spin hint is patched to trap and yields (`insn/`): `pause` on
  x86_64 (glibc's spin lock, Rust's `spin_loop`, Go's spinning); on arm64 `yield`, `isb`
  (Rust's `spin_loop`, Go's `procyield`), `wfe` and `wfi`. glibc's arm64 spin lock has no hint.
- **Spin probes.** A thread that runs 20 ms of CPU time without a point is single-stepped
  until its loop repeats with nothing changed (registers, vector state, written pages). Such
  a loop waits for another thread, and its state there is the same in every run, so it
  yields there, and at each later arrival (`spin.rs`, `sup/stall.rs`). What a probe decides
  does not depend on the instruction it arrived at, which host timing picks
  (`proto::spin`): candidate loops come shortest first, and one whose state keeps changing
  (a bounded delay loop inside the wait) gives way to the loop around it; a loop is found
  when one pass is at most 13,107 steps and leaves the state as it was, never when it is
  longer. x86_64 steps with the
  trap flag, plants `int3` and finds written pages by soft-dirty bits. arm64 has neither a
  step bit a program may set nor soft-dirty bits: its stepper decodes the instruction's
  successor (the branches, with their conditions on the frame) and plants a `brk` there
  (`proto::step`, `arch/aarch64/step.rs`); an exclusive pair (`ldxr` to `stxr`) is stepped
  whole, as a stop inside it would fail the store every time; written pages are found by
  userfaultfd's asynchronous write-protection, set up when a probe starts and closed when it
  ends. A breakpoint goes only into private, read-only code: in writable code (a JIT) the
  program's own patch would be undone when the old word goes back. Where the host cannot make
  probes work (`patina doctor`, "spin probes": a container's seccomp profile, a kernel
  without userfaultfd or soft-dirty bits, `/proc/self/mem` closed to code writes), they are
  off, and a `compute-stall` says so.
- **Compute points**, in code rebuilt with the compilers' coverage flags: the hooks count
  events and enter the runtime when a seeded number has run (below).

`rdtsc`, `rdrand` and `rdseed` (arm64: the counter-timer reads, `RNDR` and `RNDRRS`) are
answered from virtual time and the seed. The counter faults wherever the code came from;
code generated at run time (a JIT) is not scanned for the others, and such mappings are
counted in `result.json` (`unscanned_exec_mappings`). A mapping of a file on a read-only mount
is scanned once per run: its verdicts are kept in the control region (`proto::ctl::ScanTab`),
and another process that maps the same bytes the same way applies them, in the same order,
without scanning (`insn/scan.rs`; counted in `result.json` as `scan.reused_mappings`).
`MADV_DONTNEED` over patched code drops
the patched copy of the page; the runtime patches its sites again. Execute-only code (a segment
or mapping with `PROT_EXEC` alone) that holds a patched site is left readable: the trap entry
reads the patched instruction to emulate it.

On arm64 the scan is a compare under a mask of each aligned word of a file's executable
sections (`proto/src/insn/aarch64.rs`), and a site becomes `udf #0x7061`. A word that a
literal load of the same code reads is data and is left alone (`rejected_sites`); data in text
reached otherwise (a table addressed by `adr` in a stripped file) cannot be told from code,
and the census of every executable file on the dev VM and the CI runner found none that
matches (`tests/insn/evidence-census.sh`). `RNDR` is answered only where the host has it (`HWCAP2_RNG`);
elsewhere it raises `SIGILL` as it would without Patina (a test input answers and
advertises it anyway, to test that path). `PACGA` is counted and labelled (`labels.pacga_sites`), not patched. An
`isb` that is not a spin hint loses nothing to the patch (the fault and the return from it
synchronize the context as `isb` does). No landing pad is ever patched and `udf` is not one,
so BTI checks fall where they would; an indirect branch to a site in a guarded page is the
program's fault, not emulated.

**compute-stall.** A thread that computes for 10 s of its own CPU time without a point,
while another thread could run, ends the run `unsupported` with stop `compute-stall` and
names the thread. The cause is a loop that changes state on each pass (a counter, a
timestamp it computes) and contains no system call or spin hint, in code without load-time
points (JIT output, text the rewriter leaves dark). The fix is rebuilding that code with
compute points (its message says so: the supervisor does not know whether the code is
rebuilt). Rebuilt code does not
reach it while it stays in instrumented code: it yields at least every 2^22 events. A thread
computing alone is left to finish.

## Compute points

Code rebuilt with the compilers' coverage flags calls a hook at each edge, and with clang and
Rust at each load and store; Go's `-d=libfuzzer` calls one at each comparison. The hooks are
`sdk/c/patina_compute.c` (C, C++, and Rust through the SDK's feature `compute`) and
`go/patina/compute`. Each call is an event. Stock code makes none of these calls and is not
touched.

- **The cell**: one word of the program's own memory per address space, at
  `proto::layout::COMPUTE_CELL`. Each event decrements it; at 0 the hook makes the SDK call
  `COMPUTE_POINT` (op 9).
- **Hello**: a hook's first event makes `COMPUTE_HELLO` (op 8), which maps the cell. The hooks
  are hidden symbols, so each executable and shared library keeps its own copy and says hello
  itself; all get the one cell. Each hello notes the image that made it (the file the kernel
  maps at its system call; the program's own path when that is the executable) in the control
  region's image table (`proto::ctl::ComputeTab`, 32 entries, `starts` counting each process's
  first hello, and a count of starts that did not fit), which `result.json`'s `compute`
  reports. Op 9 before any hello gets
  `EINVAL`. A fork child keeps its parent's cell; an exec starts without one.
- **Arming**: at every return to program code the runtime writes into the cell the smallest
  of a seeded gap (uniform in `1..2G-1`, G the run's mean: by default drawn log-uniformly per seed from 1..16 in half the
  seeds and 16..65536 in the other half, `proto::compute::default_gap`), the
  events until the next deadline is due (a timer, a timeout, the wire, the time limit), and
  2^22 (`proto::compute::arm`). The last is the refill: an instrumented spin-wait yields in
  every setting, `compute-gap=0` included.
- **Charge**: at every runtime entry the runtime reads back how many events ran and charges
  each 1 ns of virtual time, which thread and process CPU clocks count too.
- **The point**: a hook that finds the cell empty enters the runtime, which writes a `preempt`
  record (`nr` 3: the address, the armed value, why it ran out (switch, deadline, refill),
  the process's events, the drawn gap; a hash of the general registers) and yields, so the
  supervisor fires what is due and a pending signal is delivered on the way out
  (`compute.rs`).

There is no other way into the runtime: a point that switches needs a supervisor hand-off
anyway, so a direct call would save nothing. With load-time points (the default) the cell is the plans' (`proto::plan::CELL`,
below), mapped at each image start rather than at a hello, and a rebuilt image's own plan goes
back at its hello (its hooks are its points; "Rebuilt images", below); charging and the point
are the same, and arming skips the points that could not switch (`proto::compute::chain`):

- **Alone**: with no other thread runnable, the cell is armed to the next deadline (or
  2^22): no gap is drawn, as no pick could switch.
- **Stays**: otherwise the runtime draws ahead: each gap in turn, and at its end whether the
  point stays with the thread (one chance in the runnable count, `Stream::Stay`) or switches;
  the cell is armed with the sum up to the first that switches, cut at the deadline and 2^22
  by the same rules. The switch then asks the supervisor for a thread other than the caller
  (`YIELD_OTHER`), picked uniformly among the others by the scheduler's draw: together the
  same chance for each runnable thread as one pick among all.
- **What the runtime reads**: the supervisor publishes, at each hand-over, the record
  sequence number, the slot it handed to, its runnable count and whether that thread's process
  has a signal pending (`Ctl::view`, `proto::ctl::SchedView`). The runtime uses them only when
  the sequence number and slot are its own turn's and no signal is pending, and never in a
  process whose rebuilt code has said hello (`Compute::kinds`); else it draws one gap as for
  rebuilt code: after a record the runtime wrote alone (a call it served, an
  emulated instruction) until the next hand-over, and while a signal is kept blocked and
  pending. They live in the control region (not reachable from the program,
  [Containment](#containment)) and are a function of the supervisor's state at that
  record, so every decision and charge is a function of the seed and the execution. A point
  that stays would change nothing the program or the supervisor sees (no signal, no timer
  due, no other thread), so it records nothing; the switch's record counts the points it
  passed (`args[2]` high half; `stays` in `result.json`), and the log stays complete: replay
  arms the same chain from the same inputs.
- **Budget**: with the gap drawn by default (`Config::compute_budget`; a gap the fault plan
  names is exempt, and so is a process once its rebuilt code has said hello: `Compute::kinds`),
  once a run has taken 2048 switches plus one per 8192 events charged, its gaps are drawn with
  a mean of at least 8192 until it is back within (`proto::compute::budget`). The counts are
  the control region's, written under the turn.

A point the program takes is a trap and a hand-over through the supervisor; skipping those
that cannot switch is what keeps a long program at a small gap within a few times its run
without points.

**Python** (3.12 and later) needs no rebuild: `python3 -m patina SCRIPT` runs the script with
the SDK file's hook (`sdk/python/patina.py`, `compute()`) registered through `sys.monitoring`.

- **Events**: `LINE` and `JUMP`. A line start is a point between any two lines; a jump is
  every pass of a loop, which a one-line loop or a comprehension makes without starting a
  line. Branch events add nothing these do not, and calls and returns would cost more for no
  new place. Each costs one pure-Python call, 50 to 100 ns, against about 13 ns for the work of
  a plain line natively: that call is the cost, not the cell.
- **The cell**: `COMPUTE_HELLO` with kind `COMPUTE_LINE` answers its address; the hook reads
  and writes it through a `memoryview` over that address, and makes `COMPUTE_POINT` through
  ctypes when it reaches 0. The hello comes from libc's `syscall`, so for this kind the image
  table notes the program (the interpreter), not the image at the call.
- **Charge**: each event takes `LINE_EVENTS` = 15 from the cell, so it costs 15 ns of virtual
  time and a gap counts in the same units as for rebuilt code. 15 is a fixed constant, about
  what a line of plain Python takes natively; it is not calibrated per host.
- **The GIL**: ctypes releases the GIL around a foreign call, so at a point the other threads
  can take it; when the seed switches, the thread switched to runs Python code, and the one
  that yielded waits for the GIL when it runs again. Releasing the GIL may wake a waiter with
  a system call before the point; that call is a scheduling point of its own, which charges
  and re-arms the cell, and the point after it then finds the cell full and does nothing. CPython's own switch request (a thread
  waiting for the GIL longer than the switch interval, 5 ms) is a timed wait in virtual time:
  stock, a CPU-bound thread never makes time pass, so the waiter never asks and the holder
  runs to its end or to `compute-stall`; with points it asks after 5 ms of events, as
  natively, at a time the seed decides.
- **Signals**: a signal due at a point runs its Python handler inside the hook. An exception
  it raises from a line's hook reaches the program at that line; from a jump's hook CPython
  3.12 and 3.14 would let it skip the frame's handlers, so the hook keeps it and raises it from
  the next instruction of that code (local `INSTRUCTION` events) in that thread.
- **Inert**: outside Patina the hello fails and nothing is registered.

A generator or coroutine resuming gets no point of its own: its next line or jump has one, and
the order of asyncio tasks is the event loop's, which a point in one thread does not change.

## Load-time rewriting

Stock binaries get compute points without a rebuild (the default, x86_64 and arm64): a
plan, made on the host from the file alone, rewrites single instructions, or short runs of
them, to jump to trampolines that count, and the runtime maps it over the file's text as the
file is mapped. With `[sched] preempt = "traps"` nothing below runs, and a
traps run's digest is the one the same seed had before points were the default. The host side is `crates/patina-cli/src/rewrite/` (x86_64 files through the
`iced-x86` decoder, built on x86_64 hosts only; arm64 files through `a64/`, below; also
reachable through the hidden `patina __rewrite`); the runtime side is `crates/patina-rt/src/plans.rs`,
which decodes no instruction.

- **What is code** (`code.rs`): *proven* code is what control flow reaches from function starts
  (the entry, function symbols, unwind entries, relocated pointers into text unless the file
  has no section headers, direct call targets); *extent* code is the rest of an unwind entry's
  or sized symbol's range, decoded linearly up to any byte code reads or takes the address of
  (RIP-relative, or in a non-PIE file also an absolute operand or immediate). A refusal (an undecodable or
  privileged instruction, two decodes that overlap, an extent branch that misses an
  instruction, code that reads instruction bytes) taints the span between the neighbouring
  function starts. `int3` (`cd 03`, Go's breakpoint) is not a refusal: it traps as natively. Everything else is *dark*: counted, never patched. Jump tables are not
  followed and data is not scanned for code pointers: both found code that was not.
- **Sites and counts** (`points.rs`, `flags.rs`): backward branches, backward calls, indirect
  jumps and atomic instructions. Each patch replaces one whole instruction of 5 bytes or more,
  so no address but its first byte changes meaning: `call f` becomes `call T` (the return
  address stays the program's), a backward `jmp`/`jcc` (rel32) is aimed at T, any other
  instruction becomes `jmp T` and runs as a copy in T. T is `dec qword [cell]; jz trap`, the
  row, then `trap: hlt; jmp row`; it uses no register, stack or scratch memory. A short site's
  count goes before a 5-byte instruction of its block, or for a loop of the loop head. The
  count writes OF, SF, ZF, AF and PF, so it goes only where a forward scan proves those dead
  (a return or a direct call of a function ends a path; a shift by `cl` and a `rep` compare
  write nothing for certain).
- **Group patches** (`points.rs`), only where no single instruction can carry a site's count:
  a run of 5 bytes or more of straight-line instructions (the shortest that ends the site's
  block, else the loop head's run, or the run after an atomic), only the last of which may be
  a direct `jmp`/`jcc`, becomes `2e`×p `jmp T` and `int3` filler, with the count at its start
  and every instruction copied into T at its own offset (a short branch as rel32). No known
  branch target, taken address or read byte is inside it, and it copies no `endbr`,
  `cpuid`, `hlt`, `pause`, x87 instruction (it records its own address, which `fnstenv` and a
  signal frame show), or instruction that reads a clock or random numbers. A jump the rewriter cannot see (a jump table,
  a computed goto, a handler that returns there) can still land on an *interior boundary*,
  the start of an instruction of the run other than its first, so each holds a byte that
  faults in user mode whatever follows it: `int3`, or `hlt`, `cli`, `sti` or port I/O (a
  general protection fault: the runtime drops any I/O permission inherited across `execve`
  and the sandbox refuses `iopl` and `ioperm`). A group is the shortest run that reaches 5
  bytes, so each boundary is 1 to 4 bytes in, on the jump: one at 4 (the displacement's high
  byte, zero) is moved off by `2e` prefixes; the others are on its low bytes, so the trampoline
  is placed where those bytes are such bytes (each is 0x6c or more: several MiB past the
  image, which is why the trampolines' span is sparse). The plan lists each interior boundary with its copy, where the runtime
  resumes (below); natively the program would have run the same instruction there.
- **`cpuid`** in found, untainted code that nothing reads or branches into is a site of its
  own: its two bytes become `ud2` in place, no trampoline. The runtime answers it from the host
  CPU with the fields that name a core set to core 0's (leaf 1 `EBX[31:24]`, the APIC id; the
  x2APIC id of leaves 0xB and 0x1F; leaf 0x1A's core type; leaf 0x8000001E's APIC, compute
  unit and node ids; leaf 0x80000026's): a thread placed on another core reads the same
  values, which a Go program keeps in registers a point records. Natively those differ by core;
  the rest is the host's, as without points. A `cpuid` the plan does not cover (dark, tainted,
  JIT) answers the core's own (`cpuid_unpatched` counts the `0f a2` pairs left, an upper
  bound). Hosts with `cpuid` faulting are not used for this: one mechanism on every x86_64
  host.
- **The plan** (`plan.rs`): the patched text pages, the trampolines (a span after the image, of
  which only the pages holding a trampoline are stored and mapped), a row per patch (its
  address and length, its trampoline, the trap's offset, the copies' offset), a row per
  address the runtime answers in place (a `cpuid`, an interior boundary and its copy); counts
  for a report. It records the file's SHA-256, the
  patina build and the cell address (`0x7fff0000`, reachable from any image by a 32-bit
  absolute operand). It is a pure function of the file and the build: ordered maps, no host
  input, and the same bytes on any number of threads (`par.rs`: the work is cut into parts of
  the input whose results merge in input order; one thread runs the parts in order, the
  sequential algorithm itself). Greedy site selection, where each choice depends on the patches
  before it, is chosen for each part from no patches and then checked in order: a part's choice
  stands while every earlier choice of that part stood and the lowest address it looked at is
  past the end of every patch of the parts before it; otherwise it is chosen again on the real
  state. `rewrite/01-differential` compares 8 threads with one.
- **The verifier** (`verify.rs`) checks a plan against its file without the rewriter's
  decisions: its own control flow and linear decodes, then that every changed byte is in a
  patched instruction that is one whole instruction of found code, that no known branch enters
  and no code reads, and that each trampoline counts, traps to its own `hlt` and goes on to
  the original target or returns right after an exact copy; a group is straight-line found
  code ending at most in a direct branch, copied at the same offsets, each interior boundary a
  faulting byte that is no known target, and the plan's interior rows are exactly its groups'
  boundaries, each naming its own copy; a `cpuid` row is a `ud2` over a `cpuid`, with no
  trampoline. Its decodes need no plan, so they run while the plan is made; the checks of
  sites and pages run in parts, their findings in address order.
- **The differential** (`standalone.rs`, `tests/rewrite`): `__rewrite --standalone` writes a
  copy of the file with the plan applied that runs natively (its counts address a private cell
  in an added segment; when it has groups, a stub before its entry installs `SIGTRAP` and
  `SIGSEGV` handlers that resume interior entries from the plan's rows, so a program with
  handlers of its own, or a library, is checked under Patina instead); its output is compared
  with the original's.
- **arm64** (`a64/`): every instruction is one 4-byte word, so the words are told apart by
  their encoding masks (`a64/insn.rs`, no decoder crate; it is compiled on every host, so an
  arm64 file can be planned and verified anywhere) and every patch is the one word of its site:
  no group, no interior boundary, no entry row. Only proven code is patched (the assembler's
  `$d` marks, literal loads and `adrp` pairs that read a found word are refusals that taint as
  above), and no word whose address code takes (`adr`, an `adrp` pair), which it may read. A backward `b`/`bl` becomes `b T`/`bl T` (the call's link register is the program's
  own return address); a backward `b.cond`, `cbz`, `cbnz`, `tbz` or `tbnz` becomes `b T`, where
  T tests the same condition first (re-aimed; the untaken path is a `b` back to the next word,
  uncounted); an indirect `br` (and its authenticating forms) or an LSE atomic (`cas`, `casp`,
  `swp`, `ld<op>`) becomes `b T` and runs as a copy. No other word is copied, so no copy is
  PC-relative. The count is `stp x16, x17, [sp, #-32]!; movz x16, #cell>>16, lsl 16;
  ldr x17, [x16]; sub x17, x17, #1; str x17, [x16]; cbz x17, trap; ldp x16, x17, [sp], #32`,
  then the row; `trap:` restores x16 and x17, then `udf #0x7074; b row`, so a point sees the
  program's registers exactly. `sub` and `cbz` write no flags (no liveness rule); the save slot
  is 32 to 16 bytes below the stack pointer (Linux arm64 has no red zone: the kernel writes a
  signal frame there, so a handler sees the same; Go keeps a frame pointer in the 8 bytes just
  below, which the slot leaves alone); the cell (`0x7fff0000`) is one `movz`. A `b` reaches
  ±128 MiB. Trampolines go after the image, past `ld.so`'s reservation where segments are
  aligned to more than a page (`ld.so` reserves the span with an anonymous `PROT_NONE`
  mapping, maps the file inside it and unmaps the rest; under points the runtime leaves 128 MiB
  of address space free after every anonymous `PROT_NONE` mapping it places, as it cannot tell
  that one from a thread stack's or an allocator's reservation). In a file placed at load time whose sites are not all in reach
  that way, those in the image's lower half get theirs below the image instead (the span
  wraps around the image; its pages there are empty and not mapped). A backward call or jump
  to another function's start (an anchor or a call's target, outside the site's function),
  whose trampoline is in reach but whose target is not from it, ends `adrp x16; add x16; br x16` (`KIND_FAR`):
  the procedure call standard lets a linker's veneer overwrite `x16` there; to a label inside a
  function no veneer could stand, and `x16` may be live. In a file marked for BTI the target
  must be a landing pad that accepts `br x16`. A site still out of reach is left (`far`). A
  standalone copy is planned with its trampolines after the image only: no load segment lies
  below an image's first, and a program's code runs before its entry (a library's
  constructor calls `malloc`, which Chromium's executable exports). No landing pad (`bti`,
  `paciasp`) is ever a site and none moves; a trampoline is entered by direct branches only,
  so BTI never checks it, and its pages keep the text's `PROT_BTI`, so a copied `br` sets the
  branch type it sets natively. Two limits of the save slot, in code no compiler emits: code
  that keeps data below the stack pointer, which a signal frame overwrites natively too, can
  lose the 16 bytes from 32 below it at a site; a loop that runs with the stack pointer not
  16-byte aligned gets `SIGBUS` at a site (Linux checks its alignment on every access through
  it). No site is inside an exclusive pair (from a load-exclusive along every path up to its
  store-exclusive, a call's return included, at most 32 words, `proto::step`'s pair rule) or
  branches into one: the count's stores would clear the monitor and the pair would fail on
  every try. Nor is any site on the way from a failed store-exclusive back to its load (from
  where its retry branch goes on failure, or the word after a store whose status is tested
  later, every word within 512 that leads back to the load): a store-exclusive natively fails
  now and then with no other writer (the host clears the monitor), so a retry, or the loop
  around a weak compare-and-swap, goes round once more by run, which a count there would turn
  into a different schedule for the same seed (ripgrep's musl build, inline exclusive pairs,
  showed it under `verify`). The callee of a call on either is not looked into. The verifier
  finds code, its own refusals and their spans, pairs (in order along fall-through, `b` and
  calls) and the way back by its own rules, and spells the count's words itself.

In a run (the default):
- **The broker** (`launcher/plans.rs`) runs in the launcher, outside the sandbox, on a thread
  pinned to the run's CPU. Only a 64-bit ELF file with executable segments, of at most 1 GiB,
  is read whole; the stall watchdog counts the time a thread waits for a plan as progress, for
  a budget the broker gives each request (`launcher/plans.rs` writes it to
  `ctl.compute.planning`: `rewrite::cache::planning_budget`, from the file's size; `sup/stall.rs`
  `Planning`), after which its backstop applies again and its verdict says the thread was
  waiting for a plan. The runtime sends it a descriptor of a file it is about to map
  executable and the file offset, on a socket the program cannot see (`FD_PLAN`, a hidden
  descriptor); it answers the plan's placement and run table and one read-only descriptor of
  the plan file, or that the file has none (not ELF of the host's machine, no executable segment, refused by
  the verifier: the file runs unpatched and the report names why). Before the program starts,
  the launcher plans the program and the libraries it names (in parallel); anything else (a
  `dlopen`, an `execve`) is planned when it is first mapped, while the asking thread holds the
  turn: wall time, never virtual time.
- **The plan cache** (`rewrite/cache.rs`): `$XDG_CACHE_HOME/patina/plans/`, keyed by the file's
  SHA-256 and the patina build, on the host only. A hit checks the header and the plan file's
  identity (inode, size, change time) against the record written after it was verified; a
  changed identity rehashes it, and bytes that are not the verified ones make the plan again.
  At most 4 GiB, least recently used removed first. A miss is made under an exclusive
  `flock` on the entry's `.lock` file and looked up again once the lock is held, so processes
  that meet one file at once make it once; a sweep makes its programs'
  plans before its runs start (each run is pinned to one CPU, the sweep has the job count).
  The wait for a lock is bounded (`wait_bound`: 5 s and a second per 2 MiB of the file, several
  times what planning it takes): a holder that is stopped (it keeps its lock), stuck or starved
  is named on stderr with the lock, and the waiter makes the plan itself without the cache
  (`bypassed` in the report): the same bytes, in a sealed memory file, with no entry written,
  so an entry only ever has its lock's holder as writer. Which process made a plan, and how
  long it took, reaches no record: the bytes are the same, the plan file's lines in
  `/proc/self/maps` are the original file's (`plans::Maps`), and planning is wall time only.
  Planning that takes longer than a second (ten when stderr is not a terminal) prints one line
  on stderr; `patina doctor` shows the directory and its size, and deleting it costs only
  the time to plan again.
- **Applying** (`plans.rs`): when the loader or `mmap` maps a private, read-only executable
  file mapping, the runtime asks for its plan, maps the trampolines after the image
  (`MAP_FIXED_NOREPLACE`; `ld.so`'s first mapping of a library is given that much room after
  it, so libraries sit at other addresses than without points) and the patched pages over the
  text, both private and read-execute from the plan file; the plan's site rows are mapped
  read-only in the runtime's region. Anonymous or shared executable memory, and memory made
  executable later (`mprotect`, `pkey_mprotect`), gets no plan and is counted `unplanned`.
- **A point**: a trampoline's `hlt` is a general-protection fault in user mode, a `SIGSEGV` with
  `SI_KERNEL` and no address (arm64: `udf #0x7074`, a `SIGILL`), in the runtime's fault entry,
  which finds the site by address and makes it a compute point (the record names the original
  address), then resumes after it. Any other such fault (a program's own `hlt` or privileged
  instruction) is not at a trampoline's trap and goes on as natively. `hlt` rather than `ud2`:
  under a hypervisor that intercepts invalid-opcode exceptions (KVM on AMD) a `ud2` costs
  several times a `hlt`. A `ud2` at a `cpuid` row is answered as above, with
  no record and no virtual time. A fault at an interior row's address (`SIGTRAP` just after its
  `int3`, or `SIGSEGV` from the kernel with no address at its other byte) resumes at the copy of
  that instruction with every register as it was: no record, no virtual time and no count (the
  group's count is at its start), counted `interior`, the same in every run. A count that faults
  on the cell is `compute-cell`, as for rebuilt code. Plans are mapped before any of their code
  runs and never written while a thread may run it, so no thread sees a half-made patch.
- **Walks** (`spin.rs`): a point whose drawn gap ran out (a switch, not a deadline or a
  refill) draws a walk from its segment key (`proto::compute::walk`, `Stream::Walk`): 2
  switches in W (W drawn per seed; 2 in 4 below 4) go on 1 to W of the program's
  instructions, the rest switch at the point. The thread returns to the program single-stepped
  by the spin probes' stepper (x86_64 trap flag; arm64 a `brk` written past the next
  instruction), one instruction a trap, and switches where the count reaches 0 (the record
  carries the instructions walked). Instructions are counted, never time, and instructions in
  trampolines are not counted, so a seed's walks are the same on every host and layout. A walk
  never stops in a trampoline: one whose count runs out there steps on to the next original
  instruction, so the switch's address is always an original one. It switches early, before an
  instruction that would save the stepper's state where the program can read it: x86_64
  `pushf` (a copy of the trap flag, which a later `popf` would set again; the bytes are read
  with `process_vm_readv`, which fails cleanly where the program could not read either), and
  arm64 an exclusive load (a step inside a pair would make its store fail). Any runtime entry
  during a walk (a system call, a fault, a spin hint, a point) ends it without its switch
  (counted `walks_cut`): the entry is a scheduling point of its own, so no signal is delivered
  and no fault taken inside a walk that the program would not see natively; a system call made
  while stepping gets its saved flags (x86_64 r11) without the trap flag. A host where the
  stepper cannot work (arm64: `/proc/self/mem` cannot be opened or written) ends the run
  `infra` (`HE_WALK`) rather than walk differently from another host. A walk never runs in the
  runtime's code, and a `vfork` child (running on its parent's memory) draws none. As with
  spin probes, a stall probe (a `SIGTRAP` sent by the supervisor) that is pending at the very
  moment of an x86_64 step's trap merges with it, and that one step goes uncounted; walks are
  short (the default W is at most 64, well under a ms of steps) and probes come only after 20 ms of
  CPU time without a scheduling point, so the window is narrow.
- **Changes** (`changing`): before the program unmaps, maps over, moves (`mremap`) or
  reprotects part of an image's patched text, the patched pages in that range are mapped back
  from the original file, with the instruction channels' patches written again, and leave the
  plan: nothing else is mapped, so a page that was not patched (or was put back before, and
  may hold anything since) is never mapped over. On arm64 every patch is one aligned word, so
  the range's pages are exactly what goes back. On x86_64 a patch can cross a page, so the
  range grows to whole patches: a site or `cpuid` patch that crosses its edge takes the page
  beyond too. The pages put back go first, so a moved copy is original code. The rest of the
  image keeps its points (counted `restored`; `dropped` when nothing of the plan is left). Its
  entries (the `cpuid` and interior rows) stop answering in the ranges put back and still
  answer elsewhere; its trampolines stay mapped, for a thread stopped in one, and a stop there
  is still shown at its original address. A change that touches a mapped trampoline page puts
  every patched page back; trampolines the program changed are never the plan's again (no
  address there is translated or taken as a point). A later mapping of the file at the same
  load bias takes the plan again for what it covers, shrunk so that no patch is left half on
  a page that stays original. An image tracks at most 16 ranges put back; past that, all of
  it goes back. Trampolines are never placed in the runtime's region.
- **Rebuilt images** (`plans::rebuilt`): when an image's code rebuilt with compute points says
  hello (edges or comparisons), its patched pages go back as for a change, all of them, so in
  that image the cell counts the hooks' events alone, as under traps; other images, stock
  libraries among them, keep their plans (counted `rebuilt`). Code in the image that was not
  rebuilt (a static libc, Rust's prebuilt `std`) loses its load-time points with it, as under
  traps; a vfork child, on its parent's memory, puts nothing back. Kept, each place counted twice
  (a hook and the planned site beside it) and half the points were a trampoline's trap and
  walk, unbudgeted in a rebuilt process: a sweep of `examples/stats-c` rebuilt took 5 to 6
  times its time under traps. An interpreter's line points
  (`python3 -m patina`) put back every plan of the process the same way (`lines`).
- **What the program sees**: a signal frame, a fault record and a backtrace through a
  trampoline name the original instruction (`proto::plan::shown`: a stop in a copy maps to
  the same offset of the original, a stop at a count to the instruction it precedes), so
  unwinding works from the original addresses; a handler that returns to an instruction inside
  a group enters it as an interior entry. `/proc/self/maps` (`plans::Maps`) shows the
  original file for patched pages, joins them to its lines and leaves out trampolines and the
  plan file. A read of the program's own text reads the patched bytes; `cpuid` in planned code
  answers as above. A fork child inherits the mappings and the plan table; an `execve` starts
  over with the new image's plans.

Not covered: code made at run time (JIT), dark code and pages put back keep today's behaviour
(spin probes, `compute-stall`). Inside a hardware transaction (`xbegin`), an interior entry,
like a point, aborts it (the program's fallback path runs). A loop back-edge still has no point when the flags stay live
across every run that could carry its count, or its block holds a refusal (`tests/rewrite/evidence-corpus.sh`
measures the coverage per program).

## The fault plan

`--faults` (classes, each a set of keys) and `--fault` (one key) give the plan (`faults.rs`:
`CLASSES`, `KEYS`, `resolve`). A value given as a range is resolved from the seed by a draw
keyed by the setting's name, so adding one setting never moves another's value. The resolved
plan is in `run.json`.

The fault window is two sequence numbers in the run's `FaultCfg`: `fault_after_seq` and
`fault_until_seq` (`FaultCfg::in_window`). Every runtime injection, crash point and fault
point, and every supervisor fault (link faults through `link_faulted`, partition and pause
draws, the seed's node kills, clock skew at boot) asks it. The runtime's `mark`
(`sys/sdk.rs`) sets them: `faults-done` writes `fault_until_seq` and tells the supervisor
(`Op::Lifecycle`, `LIFE_FAULTS_DONE`), which heals a seed partition in force, ends seed
pauses (`PEND_DONE`) and cancels their next draws.

A run is told that the program marks `setup-complete` (`Config::faults_held`: `--faults-held`,
`[run] faults-held`) or not. Told, `fault_after_seq` starts at the maximum for the mark to
lower to its own sequence number. A run not told whose plan injects anything ends at the mark if
it comes (`restart_at_setup`, `LIFE_RESTART`, verdict `setup-restart`) and starts again told
(`launch::run_one`; `result.json`'s `faults.window.restarted`). Being told is an input like the
seed: `run.json` records it, and a replay and the rerun line run it as recorded; nothing on the
host decides it. A sweep without cases tells the runs of seeds above the lowest seed whose run
met the mark (each worker learns it before taking its next job). A run without the hold that
ended without the mark waits uncounted until no lower seed can still meet it, then is
counted, or run again told if a lower seed met it: which runs are told follows seed order, not
which run finished first, so a sweep's runs are the same at any width. `sweep.json`'s
`faults_held_from` keeps the answer for a resumed sweep, which runs again told a kept run it
now tells; a stopped sweep deletes the runs still waiting. While the waiting findings would reach
`--max-findings`, no job of a higher seed starts (`Then::Hold`). A crash point's child is told as its
base was. With cases, each run finds out for itself. Both marks carry over to later incarnations (`launcher::incarnations`).

Each fault decision is a draw keyed by the call's sequence number and the fault class, made
before the call (`patina-rt/src/inject.rs`). Turning one class on does not move another's
draws. An injected errno is one Linux returns for that call on that object
(`faults::errnos`). Every injected fault is a boundary record naming its object, and
`result.json`'s `faults` counts per class the calls it could act on and the faults injected.

Path swaps (`path-swap-permille`; `patina-rt/src/swap.rs`,
`proto::swap`) stand in for another process of the same uid that changes the work tree
between a program's check of a path and its use. Each process keeps the hashes of the work-tree
paths named by its last 16 checks (`stat`, `lstat`, `access`, `readlink`, `open`). A use (`open`,
`exec`, `chdir`, a creation, removal, rename, link or attribute change by name) whose path is a
checked path or lies below one is eligible; the decision is drawn, keyed by its seq, before the
use's paths are resolved, so the kernel's walk and the policy see the swap. The draws pick a
component of the checked path below the work root and one of three mutations: it becomes a
symlink (to `/etc/passwd` or the work root's parent, to another entry of its directory, or to
nothing), another entry of its directory is renamed into its place, or it is renamed away. A
displaced original goes to `.patina-swap-SEQ` in its directory. Half the swaps (none
before an `exec`) are put back right after the call, as far as the call left the entries the
swap made. A path with a `..` component is not eligible: the kernel resolves it through what
precedes it, which the swap does not follow. The runtime makes each
step with its own calls in the guest process, relative to the component's directory opened with
`RESOLVE_NO_SYMLINKS` and checked to be on the work tree: the kernel applies the guest's
permissions and the sticky bit, a mount point refuses, nothing outside the work tree changes,
and a target outside is only a name. Each step is recorded like the program's own name change
(virtual times, an operation record, a crash point after it), so inode numbers and times are
the run's, a machine crash may lose part of a swap like any unsynced rename, and replay is
exact. The swap is an `Injected` record (`INJ_PATH_SWAP`: the mutation, the checking call and
its seq) followed by `Name` records for the path and the target, written once the swap is made;
a crash between two of its steps leaves those steps in the operation log and no `Injected`
record, and a mutation the kernel refuses falls back to the next (none: no swap, though the use
was counted eligible).
Path swaps are in no class: they model a concurrent writer the program may not be meant to
withstand.

The network wire: a TCP socket in the guest is a real unix socket whose peer the supervisor
holds (`sup/wire.rs`). The supervisor reads what each side sent, stamps it with a seeded
delivery time, and delivers it in virtual time. Delays, splits, resets and refused connects
are draws keyed by the connection and what they act on: a reset is drawn on each piece of
data a guest sends (so a long-lived connection meets one), a refusal or timeout once per
connect, a delay or split per delivery. A partition is one window of virtual time, its start
and length resolved from the seed with the plan, in which deliveries are held.

TCP keepalive (`Sup::ka_fire`, `sup/wire.rs`) follows the kernel's `tcp_keepalive_timer` per
side of a connection. With `SO_KEEPALIVE` on, a side that has heard nothing from its peer for
`TCP_KEEPIDLE` (default 7,200 s) sends a probe, then one every `TCP_KEEPINTVL` (75 s); any
segment delivered to it (and, when the way back is open, any it sent that was delivered)
resets the count. After `TCP_KEEPCNT` (9) unanswered probes, or with `TCP_USER_TIMEOUT` set
once that long has passed since it last heard and a probe went unanswered, it gives up: its
socket reports `ETIMEDOUT`, and its RST reaches the peer if the peer can be reached then (else
the peer's next segment or probe is answered with one). A side with unacknowledged data of
its own sends no probes. Turning keepalive on starts the first probe one idle time later;
changing the idle time counts it from when the side last heard (or now). A probe is a wire
event: it goes unanswered across a cut either way, to a machine that is down, and in a
`net-blackout` window (on loopback too); a peer whose machine came back without the
connection, or whose side gave up across a cut, answers with a RST (`ECONNRESET`); otherwise
it is answered after the link's delay both ways. The options read back as set (the kernel's
ranges, `EINVAL` outside them), and an accepted socket starts with its listener's.

Determinism and cost: the timer is a virtual-clock event that exists only while the peer may
not answer (a cut either way or a machine down when a cut begins or the timer is set, a
blackout window ahead). Answered probes are not modelled one by one: they change only when
the first unanswered one comes ("Limits"). So an idle connection with a reachable peer costs
no event and no record for any length of time (an idle hour at `TCP_KEEPIDLE` 1 s: none).
Each unanswered probe is a `DEC_WIRE_PROBE` record [conn, side, count] (`patina log events`:
`"event":"probe"`), one per `TCP_KEEPINTVL` while an outage lasts, until the side gives up. A
`setsockopt` of one of the options on a connected socket marks it, as a send does, and the
supervisor sets the timer at its next step; nothing is recorded for it, so a run whose probes
are all answered (Go's default keepalive, a database client's) keeps the digest it had before
keepalive was modelled, and only one with an unanswered probe or a keepalive reset has a new
one.

Datagrams (`sup/udp.rs`, `rt/sys/udp.rs`): a UDP socket in the guest is a real unix
`SOCK_SEQPACKET` socket whose peer the supervisor holds, one per socket and never shared
between sockets. Ports, addresses, connection state and options live in the shared socket
table like TCP's; ephemeral ports count up from 32768 in a port space of their own. A send
puts the payload on the socket and then tells the supervisor, which reads exactly that packet,
so a datagram is stamped at the send's virtual time and never waits in a kernel buffer. The
supervisor draws its fate and a delivery time (the `net-delay-ms` range, each datagram on its
own, so datagrams reorder within the jitter), and at that time routes it to the bound socket
that matches best: a connected socket whose peer is the source, then a specific address, then
the socket's own family (a v6 wildcard receives v4 unless `IPV6_V6ONLY`). A `SO_REUSEPORT`
group picks by a hash of the source; otherwise the socket bound last wins. A delivery is a
16-byte header (source, length) and the payload; the runtime reads the header into its own
buffer, so the guest never sees a unix address or credentials. A receiver whose queue is past
its `SO_RCVBUF` (charged per datagram at least what the kernel charges) loses the datagram, as
Linux does; the runtime uncharges as the program reads. A datagram to a port nobody holds is
lost, and a connected sender gets `ECONNREFUSED` on its next call (`SO_ERROR` reports it),
as the kernel's ICMP handling gives on loopback. Drop, duplicate, reorder (an extra hold beyond
the jitter) and partition (a datagram due inside a partition window is lost) are draws on
their own stream keyed by the datagram's id and the class, so enabling one class moves no
other draw. Every send, delivery and close is a decision record; replay compares them.
Multicast and broadcast destinations fail with `ENETUNREACH` (`udp:multicast-or-broadcast`
in `refused`), as do addresses outside the run. Names resolve from the sandbox's `/etc/hosts`
only (`hosts: files`, no `resolv.conf`): glibc and Python answer `EAI_NONAME` for an unknown
name, Go's pure resolver "no such host"; no resolver sends a datagram.

## The crash model

The runtime records every change to `/work` with its data in an operation log, along with
every sync (`patina-proto/src/oplog.rs`). Crash points follow each change and precede each
sync; each is counted inside the fault window (its ordinal is what `crash-at=N` names and
what `crashes[].point` reports) and the crash draw is used only when it fires, so a run is
identical to the run without crashes up to the crash. With nodes each node counts its own, on its own disk ([Nodes](#nodes),
"Crash points per node").

`sweep --crash-points` places each point from a base's operation log (`patina-cli/src/branch.rs`),
written per run as `points.json` before the sweep prunes the run's logs: the runtime's records
in order (not the supervisor's, which offer no point), for each call that recorded a sync a
point before its records, then one after each record. The places are used only when their
number is the runtime's count (`crash_points`); otherwise the sample has one kind per node
(and no pair is taken after the node's points). `--crash-points=N` takes the first N of an order
stratified by node, then by the kind of record at the point (`branch::sample_order`): seeded by
the seed and case, and for the first crashes nested, so a larger N adds children to those run
(the pairs to sample from depend on the first crashes run). No point is left out as the same
as another, even a point before a sync right after the record of the point before (nothing ran
between them, the disk is the same): a crash there takes the next sequence number, so every
draw keyed by one after it differs, including what the crash keeps; stores through a shared
mapping made between the two calls are logged at the later point only; on `ack2.py` such a
pair of points gives different outcomes.

Stores through a `MAP_SHARED` mapping of a work file are in the page cache at once and reach
the log as `MmapDirty` records when their process unmaps, syncs or ends: the runtime
compares each tracked mapping with the file's shadow at `munmap`, `mremap`, `msync`, the sync
calls, `execve`, an `mmap` with `MAP_FIXED` over it, and every way the runtime sees a process
end (`exit`, `exit_group`, a thread's `exit`, a signal's default action), and logs each run of
pages that differ.

The shadows are one store for the whole run (`proto::oplog::Shadows`), with one invariant: a
file's shadow is the replay of the operation log onto that file. A slot is a sparse memfd at a
hidden descriptor (`FD_SHADOWS`, the top 64 numbers below the sandbox's real `RLIMIT_NOFILE`),
made by the supervisor at each incarnation's start and inherited by every guest; the table of
which inode each slot holds is in the control region. The store is kept in one place: every
record appended to the log, by a runtime (`rt::oplog::append`) or by the supervisor
(`sup/crash.rs`), changes its file's shadow as it changes the file, before the crash point
that follows it (a `write` or `MmapDirty` writes its bytes, a truncation, hole punch or zeroed
range zeroes, a new file at the inode empties the slot). A slot is filled when a file is first
mapped shared and writable with no slot, from the file's data runs (`SEEK_DATA`), at the
store's own offsets: a store is never larger than the file, so `RLIMIT_FSIZE` never refuses
one, and a sparse file's shadow is as sparse. So a page another process changed (through its
own mapping or `write`) and this one stored back is compared with the log, not with what this
process last saw, and is logged. A slot is freed when no process maps its inode, as the
kernel reports it (every guest thread's `/proc/PID/task/TID/maps`, read by the supervisor at
a process's death, at the next request after an `munmap`, and when the table is full): the
file then holds what the log holds. Which slots are freed when changes no record, so it moves
no digest. More than 64 files mapped at once end the run `unsupported`, stop `capacity`.
`fork` shares the store; `execve` flushes the image's mappings first. `result.json`'s
`shadow_bytes` is the most the store held at once.

A write-family call (`write`, `pwrite`, `writev`, `copy_file_range`, `sendfile`) to a file
with a shadow first logs whole the pages it writes that differ from the shadow: the page
cache already held those stores, and writeback writes a page with every store on it, so the
crash model never keeps the write without them. Replay matches the live tree without it; the
crash states would not. A `sync` or `syncfs` compares each file the caller maps whole (the
file holds every process's stores), or, while a file the caller does not map has a shadow,
asks the supervisor to log every process's mappings first (`MapsSync`); `fsync` and
`fdatasync` log what the file holds that its shadow lacks, whichever process stored it; `madvise(MADV_REMOVE)` is a
hole punch. An `mremap` of part of a tracked mapping, a copy of one (`old_size` 0) or a
move that keeps it mapped (`MREMAP_DONTUNMAP`) ends the run `unsupported` rather than leave
stores untracked. A process that ends without its runtime, killed by `SIGKILL` from another
guest, still running at the end of the run, or at a crash point, keeps its stores, as Linux
keeps them in the page cache for a later `fsync` to make durable: the supervisor logs them at
that point, before the kill (`sup/maps.rs`), from the table of tracked mappings each runtime
publishes (`proto::oplog::SharedMaps`). It holds the turn, so no guest code runs while it
reads, and the records land at the kill's place in the order, the same in every run (a stall,
the one end while guest code runs, stops that process first). The table is the program's
memory, so it only chooses what is compared: each file is the process's own open file
(`pidfd_getfd`, nothing is reopened) and must be the work file the entry names, and the bytes
logged are the file's. A crash point logs every process's mappings before its `Crash` record,
so the log of every incarnation is complete. The table is read with `process_vm_readv` (the
supervisor is every guest's ancestor, as Yama's `ptrace_scope` 1 asks); a host that refuses it
ends a kill or a crash `internal`, naming it, and at the end of the run leaves the outcome as
it is, with the self-check reporting what the log lacks. The supervisor compares with the
same shadows.

A process crash restarts the program on `/work` as it was. A machine crash restarts it on
what a filesystem would have kept: a pure function of the operation log, the seed and the
model, `ext4-ordered` (the default) or `posix-strict` (`durability/`). Every run with
crashes on ends by replaying its whole operation log against the live tree of each
incarnation, with no exception: a difference is a Patina defect. File times are carried, not
modelled: the virtual time table keys a work tree's inodes by node and inode number with a
fixed minor (`proto::vfs::VT_WORK`), not the mount's index, so the supervisor reads each
file's modification time into the live tree it exports (`sup::crash::live_tree`); a machine
crash's tree takes, per inode, the time the live tree had (`Tree::times_from`). The times go
to the next incarnation as data, never as host file times (a host filesystem may clamp them):
the launcher appends them to the state the shared-memory descriptor carries
(`crash::carry_times`), a node's stay in its supervisor; before the restarted incarnation's or
boot's first guest the supervisor puts them back into the table by path (`seed_times`), after
dropping the node's entries of its earlier disk (the new disk's inode numbers can repeat them).
The digest and the self-check leave times out. The run keeps its own
outcome and reports the failed self-check beside it (`result.json`'s `self_check`, exit
status 2; a sweep counts such runs apart and keeps their logs). `patina log ops` prints the
log.

## The fsync-error model

`fsync-error-permille` and `fsync-error-at` (and `fs-error` at a sync call) fail a write-back
(`patina-rt/src/oplog.rs`, `proto::oplog::Dur`). The model is Linux's `errseq_t` (lib/errseq.c,
mm/filemap.c, fs/sync.c, include/linux/pagemap.h), with one invariant: **a call returns a
write-back error exactly when Linux's would for the same history, and a page whose write-back
failed is durable only once it is written again and synced.** So a program that treats a
clean `fsync` as durable never loses data a crash model did not lose, and one that retries a
failed `fsync` and then trusts it does.

- A failure is drawn at a call that starts write-back (below). The pages the file held
  unsynced fail (`FsyncFail`: the materialiser never makes them durable; a later write of the
  same bytes makes them dirty again), and the error goes into the inode's error sequence and
  its disk's. An injected `syncfs` failure fails every file of the disk (`FsyncFail` of inode
  0) and counts in the sequence of every inode that exists then, so each of those files
  reports it (a file created after it does not).
- Each open file description samples the inode's sequence when it is opened: its current value
  if some description was already told of it, else 0, so an error nobody has seen is reported
  to a later opener too (Linux 4.16 and later). A call that reports compares its description's
  sample with the sequence; if they differ it returns `EIO` once, advances the sample and
  marks the value seen, and a later opener samples it as seen. `syncfs` does the same with the
  disk's sequence (Linux 5.8 and later).
- A description is what `dup`, `fcntl(F_DUPFD)` and `fork` share: the runtime names each one by
  a key given at `open` (`Dur::new_desc`), carried by duplicates, by a fork's copy of the table
  and by the hidden duplicate behind a tracked mapping (so `msync` reports to the mapping's
  description); a description that reported keeps its advanced samples in `Dur::descs` (a
  direct-mapped table), which every descriptor of it reads.
- A failure is never reported by the call that drew it unless that call waits; a pending error
  makes `fsync` write back what it holds and commit nothing (`Fsync` with `FSYNC_NO_COMMIT`).

| call | may be given the failure | reports a pending error | marks it seen |
|---|---|---|---|
| `fsync`, `fdatasync` of a work file or directory | yes (then reports it; a directory's is a model choice: ext4 would shut the filesystem down) | yes | yes |
| `sync_file_range` with `WRITE` | yes, not reported by it (it does not wait) | only with `WAIT_AFTER` | with `WAIT_AFTER` |
| `sync_file_range` with `WAIT_BEFORE` | no | yes, before writing | yes |
| `msync(MS_SYNC)` of a tracked mapping | yes, one draw for the call, to the first description in the order the mappings were made | yes, per description in that order; the first error ends it | yes |
| `write` family through an `O_SYNC`/`O_DSYNC` description, or with `RWF_SYNC`/`RWF_DSYNC` | yes (the write's result is the error) | yes | yes |
| `syncfs` | yes (the whole disk fails) | yes, the disk's sequence | the disk's |
| `sync` | no (it reports nothing) | no | no |
| `close`, `msync(MS_ASYNC)`, `open` | no | no | no |
| any of these on an `O_PATH` descriptor | no: `EBADF` | | |
| `fsync` of a pipe, socket or other non-file; `sync_file_range` of one | no: `EINVAL`; `ESPIPE` | | |
| `fsync` of a block device or of a file outside the work directories (procfs, a mount) | no: 0 | no | no |

Calls are counted for `fsync-error-at` and drawn for `fsync-error-permille` at each "may be
given" cell. Per-node: every key and sequence is the node's (`proto::oplog::node_key`), and a
machine crash of a node forgets its sequences and descriptions' samples with its disk. Where
it differs from Linux: a descriptor the runtime did not see opened (inherited across `execve`,
received over a unix socket) is taken as opened at its first sync call or `dup`;
`sync_file_range` and an `O_DSYNC` write write back the whole file rather than their range; an
injected `syncfs` failure fails every file of the disk, clean or not, where Linux fails only
those with dirty pages; a description pushed out of `Dur::descs` by another with the same slot
may report an error it already reported once more; a write-back the kernel would start by
itself (the flusher, memory pressure) never fails; `msync` of a mapping that is not tracked
(read-only, private) reports nothing; and a process crash (`--faults kill` on one machine, unlike a node's
`kill`) starts its next incarnation with no pending errors, where Linux would keep the page
cache's. Tests: `tests/faults/22-errseq.sh` (each row against the kernel's sources, and the
durability consequence under every crash point), `09-failed-fsync.sh`, `nodes/12-disk-faults.sh`.

## The SDK channel

The SDKs make one reserved system call, `0x7061`. Outside Patina the kernel answers `ENOSYS`
and the SDK goes inert. Under Patina the runtime answers it (`sys/sdk.rs`): assertions count
into a site table shared by every process of the run, and fault points are draws keyed by
the seed and the label. The payload's hash is the trap record's `in_hash`, and its label (a
mark's text too) follows the record in clear. A failed `always`, or a reached `unreachable`,
ends the run `violation`. Sites declared with a literal label are in an ELF section, so a site never reached
is still reported (an `unreachable` never reached is as it should be, and a sweep does not list
it).

## What is deterministic, and how we know

By construction: one thread runs at a time, and every input the program can observe passes
through a trap or an instruction Patina emulates. Time, randomness, scheduling, addresses,
inode numbers and faults come from the seed. Each table row says how its call is made
deterministic.

By test: whether everything observable really passes through the table is checked, not
proved. `patina verify` repeats a seed while moving it across CPUs, under load, with address
randomization on and in another sandbox; a sweep replays the first seed of each finding. `tests/determinism/` keeps a regression for
each difference found and closed, and `tests/determinism/evidence-matrix.sh` reruns the whole
protocol; a difference is a Patina bug to report, not noise.

## Debugging a run

`patina debug` (`cli/src/debug.rs`) is a replay with one more word in the configuration:
`Config::debug`, the sequence number to stop before (0, the default, in every other run). The
gate is where sequence numbers are taken, the runtime's `entry::next_seq` and the
supervisor's `next_seq`: whoever takes that number first parks on `Ctl::debug` (`DebugCtl`):
it publishes its slot and the number in `stopped`, and waits on the futex `go`. Nothing is
recorded at the gate (no record, no sequence number, no virtual time), and every other guest
thread is already parked, waiting for the turn, so the whole world is stopped before the event
and the run goes on from there as recorded. For the supervisor's own events (a fault, a
partition, a crash) it is the supervisor that parks, and `sup` says so; while it is parked its
watchdog's stall backstop is off, since a stopped world makes no progress.

The launcher watches `stopped` (`debug::Watch`). At the stop it finds the processes of the
sandbox on the host (the keeper's child is the pid namespace's init; host pids from `NSpid`),
writes the stop's facts (`RUNDIR/debug/debug.json`) and a gdb helper beside them, and starts gdb
in its own process group, which gets the terminal. The helper loads each image's symbols at its
load address from `/proc/PID/maps` (the kernel's view is of the runtime, which loaded the
program): the first mapping of each file at an offset where one of its segments starts (not
only offset 0, which under load-time points can be a plan's page; where several segments
start in that page, the one whose permissions the mapping has), lets the runtime's signals through (`SIGSYS`, the faulting signals), and opens the
gate (a file the launcher polls) when gdb continues, detaches or exits. The launcher opens it
too when gdb exits by any means, and when the session is interrupted, so no world stays
parked. The x86_64 signal restorer is named `__restore_rt`, the name gdb's signal-frame
unwinder recognises, so a backtrace reaches the program's frames under the runtime's handler.
At the end the replay's boundary logs are compared with the run's as `patina replay` compares
them; the first differing record is where the session left the run. What gdb did that writes
(gdb's `memory_changed`, `register_changed` and `inferior_call` events) is noted by the helper
and named with it.

Debug-only rules, active only while `Config::debug` is nonzero:
- **The debugger's signals.** gdb's `SIGINT` (Ctrl-C), pending at a trap exit, is taken by
  the runtime (`sup::debugger_signals`) and turned into a `SIGTRAP` the thread sends itself,
  which gdb stops on and does not pass on; the `SIGSTOP` of its attach and a `SIGCONT` are its
  own. None reaches the program's virtual signals (in another run, a signal from outside ends
  it `error`). (A stop signal instead of the `SIGTRAP` would outlive gdb's detach and leave
  the process stopped.)
- **No time limit, and the backstop waits.** The run's wall-clock timeout is lifted, and while
  a debugger holds the world (`DebugCtl::held`, the launcher's: from the stop until gdb exits)
  the supervisor's stall backstop does not end the run. After gdb exits, the launcher
  continues any guest process left stopped.
- **A call at the stop.** A function gdb calls in the program at the stop runs with the world
  still held (the helper does not release it for the call) and passes the gate, which parks
  once: its events take the stop's sequence number and those after it, the event at the gate
  takes the next one after them (`entry::next_seq`), and the session has left the run there.

In an ordinary run gdb keeps every `SIGTRAP` it did not cause (the helper's `handle SIGTRAP
nopass`), so the spin probes' steps and breakpoints are not available in a session: a run whose
threads yielded at spin points is refused, and a probe sent during a session is dropped (it
finds nothing in a program that was not spinning, so nothing recorded changes).

A run with load-time points (the default) takes `SIGTRAP` for its scheduling points (a plan's
`int3` or `brk`, a walk's single steps), which gdb cannot tell from its own. There the
helper passes on every `SIGTRAP` gdb did not cause (`handle SIGTRAP pass`), and the runtime
drops one that is neither its own nor a plan's (`fault::debugger_passes`): a trap gdb left
behind (a watchpoint's, after it was deleted) never reaches the program. gdb's own steps would
be among the runtime's, so the helper refuses stepping (`step`, `next`, `stepi`, `nexti`,
`until`, `advance` are errors). A stop gdb reports (a breakpoint's) turns passing off until
the program goes on: gdb steps over a breakpoint with the stop's `SIGTRAP` when it passes it,
which would take the thread into the runtime's handler and back to the breakpoint. A
watchpoint that traps after the access (x86_64) is reported that way; an arm64 one traps
before it and gdb steps over it with no stop in between, so on arm64 the helper refuses
watchpoints (`watch`, `rwatch`, `awatch`) in such a run. For the same reason the helper
disables, with a message, a breakpoint gdb would go on from by itself (a condition, an ignore
count, another thread's, a `dprintf`), a software watchpoint (gdb steps the program), and a
breakpoint in code the plan moved (it runs in a trampoline, so the breakpoint would not be
hit, and on a plan's own trap instruction it would take the scheduling point's place). Ctrl-C's `SIGTRAP` is passed on and
dropped, so it does not interrupt such a run. A breakpoint instruction of the program's own is dropped too: such a
session leaves the run, and its end says where. Code the plan moved runs in trampolines no
symbol file covers: the launcher lists each process's trampolines with the original
instructions each stands for (from the plans the process maps), and the helper's unwinder
gives a trampoline frame the original address, so `bt` and breakpoints read as the program's.
On arm64 the runtime's signal restorer is not the kernel's instruction pair gdb knows, and the
same unwinder reads its signal frame.

The word is the launcher's, set from its own command line: it is in `Config`, which the
runtime reads from the control region, and the program has neither the region's address nor
any call that writes it (Containment). A program cannot turn the gate or the signal rules on.
The user's debugger, which ptrace lets do anything to the program, is outside the sandbox's
guarantees by design: it is the user's own tool on their own replay, and a session that writes
says where it left the run. An ordinary run is unchanged: the gate is one comparison per
sequence number against 0.

## Containment

The runtime shares a process with the program, so program code can reach the runtime's
memory and code. Patina contains an accidental or curious program (a stray store, a corrupted
function pointer, a library poking at addresses it found): such a reach ends the run
`unsupported`, stop `containment`, naming what was reached, the same on every repeat. It does
not contain a program that sets out to defeat the runtime.

Enforced:
- **System calls.** The seccomp filter lets through one instruction address, the `syscall` of
  the runtime's stub (`raw.rs`). A `syscall` anywhere else, the runtime's text included,
  traps; one there reached from program code ends the run.
- **The stub.** It checks after the call that it ran on a runtime stack (every runtime stack
  lies in the runtime's region; a program cannot map there). Program code that jumps to the
  stub runs on its own stack: the call reaches the kernel once, and the stub stops at `ud2`
  (`udf` on arm64) before any program code sees the result; the fault entry ends the run. A
  call that does not return (`exit_group`, a successful `execve`, `rt_sigreturn`) is not
  stopped by the check; an accidental jump makes one of those with the slim chance that `rax`
  (`x8`) holds its number.
- **The control region and the boundary log.** Their published addresses
  (`proto::layout::CTL_ADDR`, `LOG_ADDR`) are inaccessible reservations. The runtime maps them
  read-write at addresses drawn from the host at each image start (`state::map_shared`), which
  nothing reports (`/proc/self/maps` hides the runtime's region). The supervisor and the
  launcher have their own mappings.
- **System call arguments.** To the program the runtime's region (`[RT_BASE, RT_REGION_END)`:
  image, private memory and alternate stacks, both reservations and both drawn windows) is
  address space nothing is mapped in, as above the top of user space, so the kernel never
  reads or writes it on the program's behalf. Before a call the table passes, rewrites or
  answers is served, every pointer the kernel would follow is checked against the region
  (`guest::names_runtime`): each buffer the boundary record hashes (`Row::ins`, `Row::outs`)
  and every other pointer the row lists (`Row::refs`: iovec arrays and segments, a `msghdr`
  and its name, iovecs and control buffer, `mmsghdr` arrays, socket addresses through their
  length pointers, `select` sets and `pselect6`'s mask pair, `futex` words and timeouts,
  `execve`'s vectors and strings, and the arguments of `fcntl`, `ioctl`, `prctl` and
  `arch_prctl` their command reads), with the extent the kernel may touch (the length argument
  for a transfer, clamped to `MAX_RW_COUNT`). Only arguments the call reads are checked, as
  pointers and as descriptors (`nargs::live`, above): a register the call ignores may hold
  anything, an address in the region or a hidden descriptor number included. One that reaches the region answers `EFAULT`, the
  kernel's answer for a hole; the record is the call's as the program made it. A length rule
  without a pre-call extent cannot be written (`Len`), and `ins`/`outs` take only rules the
  log can hash, so a buffer is never logged without being checked. A buffer that starts in
  program memory and runs into the region is refused whole, where the kernel would move the
  first part. The check is made before anything else of the call, so a call the kernel would
  first have failed for another reason (except a hidden descriptor's `EBADF`), waited on, or
  consumed input for (a datagram dequeued before the copy faults) answers `EFAULT` at once and
  consumes nothing. It is made again after a park and after an injected delay, when other
  threads have run and may have rewritten an iovec or `msghdr`; otherwise only one guest
  thread runs and signals arrive at trap exits, so nothing changes between the check and the
  call. Calls on ranges there answer as for unavailable address space: `mmap` with a fixed
  address ENOMEM, `mremap` to it EINVAL and from it EFAULT, `mprotect`, `pkey_mprotect`,
  `madvise`, `msync`, `mlock` and `PR_SET_VMA` ENOMEM, `munmap` EINVAL; `mincore` is refused
  for every range. A parent-tid pointer of `clone` there is ignored, as the kernel ignores
  one it cannot write. The SDK channel's own copies (`process_vm_readv`/`writev` on itself)
  refuse the region the same way; the program's `process_vm_*`, `ptrace`, `userfaultfd`,
  `io_uring`, `shmat` and `rseq` are refused, and no `mem` file under `/proc` is reachable
  (below, "`/proc` directories").
  A signal frame that would land in the region (an alternate stack placed there) is SIGSEGV,
  as for a frame the kernel cannot write. The runtime's own reads and writes of program memory go through its guest
  copy (`guest.rs`), which refuses the region too, except reads of the calling thread's
  runtime stack, where handlers keep arrays they built; a pointer the program passes never
  reaches those, since the check refused the call first. Cost: a few comparisons per pointer,
  and for iovecs and `msghdr`s one fault-safe read per entry; a call with no pointer pays a
  slice-length test (`costs getppid` and `costs pipe` within run-to-run spread).
- **Descriptors.** The invariant: the program's descriptors are the numbers below the soft
  `RLIMIT_NOFILE` it is shown (1024 at the start, raised or lowered as on Linux, never above
  its hard limit of at most 2048), and every descriptor of the runtime, the supervisor and the
  launcher is at 3000 (`FD_HIDDEN_MIN`) or above, so nothing the program sees depends on which
  of them exist. The kernel enforces it (`fdlim.rs`): the process's real soft limit is the
  program's, kept by the kernel across `fork` and `execve`, so every allocation the program
  makes (the open family, `dup`, `F_DUPFD`, sockets, pipes, `SCM_RIGHTS`) and every target it
  names (`dup2`, `dup3`) answers `EMFILE`, `EBADF` or `EINVAL` exactly where Linux would. The
  real hard limit is the sandbox's 4096; the runtime lifts the soft limit to it around its own
  allocations and puts it back, and retries a descriptor it holds for a moment with the range
  open when the program's table is full, so the program's count never makes a runtime step
  fail. A hidden number the program names answers `EBADF` (`poll`: `POLLNVAL`; a `select` set:
  `EBADF`), `close_range` stops below them, and `/proc/self/fd` leaves them out. A descriptor
  a call reads as a value or from a structure, which no table row marks (`F_DUPFD_QUERY`'s
  argument, `waitid`'s `P_PIDFD` id, a clone's source, a dedupe's destinations), is passed as
  2999 (`FD_NEVER`) when hidden: no descriptor ever has that number, so the kernel answers as
  for any closed one. A spin probe's descriptors sit at fixed numbers (`FD_PROBE_*`), so one
  that host timing starts moves no other number. One difference from Linux remains, the same
  on every run: Linux cuts `select`'s count to its table's size (64 for a small table), and
  here the table always reaches past 3000, so an unopened number in a set past that size is
  `EBADF` here and ignored there. Regression `sandbox/15-fdspace` (against native Linux, and
  with a spin probe against none).
- **`/proc` directories.** The invariant: no path reachable through a `/proc` directory
  descriptor is refused by absolute path, and no runtime descriptor is visible or reachable
  through `/proc/self/fd`. The policy (`path.rs`) is lexical, so the runtime keeps it lexical
  everywhere a path could leave it. `/proc`, `/proc/self` (`/proc/<own pid>`), `/proc/self/fd`
  and `/proc/self/task` open as directories (`O_DIRECTORY`, `O_PATH`), marked on the descriptor
  (`procfs::mark`; copied by `dup`, rebuilt after `exec`). A `vfork` child shares its parent's
  marks but not its descriptors, so there opening, duplicating or reopening one through
  `/proc/self/fd/N` is refused (`EACCES`). A name relative to a marked descriptor is
  joined to the directory's policy path and resolved as that absolute path (`resolve.rs`), so
  it reaches exactly what the absolute path reaches; with `openat2`'s resolve flags a relative
  name answers `ENOENT`. Symlinks are resolved before the policy, and the walk stops where the
  policy takes over: what remains of the path is normalised lexically there, so `..` after a
  `/work` symlink or a `/proc/self/fd/N` link into `/proc` is policed as the path it spells,
  never followed by the kernel into another process's `/proc/PID` (the supervisor's). Their
  listings are written by the runtime: `/proc` lists the files the policy synthesises, `self`
  and the process's own pid; `/proc/self` its synthesised entries, `fd`, `task` and `exe`;
  `/proc/self/task` the process's threads from the supervisor's slots; `/proc/self/fd` is the
  kernel's listing without the runtime's descriptors (numbers from `FD_HIDDEN_MIN`), ascending.
  Each lists the calling process's (after a `fork`, the child's), as its names resolve. No
  directory under `/proc` can become the working directory (`chdir`, `fchdir`, also through a
  `/proc/self/fd/N` link: `EACCES`), and none can be passed in `SCM_RIGHTS` (`EBADF`). The
  lexical `..` departs from Linux only where the kernel would fail (`/proc/cpuinfo/..` is
  `/proc`, not `ENOTDIR`). Their link counts are computed (`/proc/self/task`: 2 + the
  threads). Regression `sandbox/12-procgaps`.
- **Load-time plans** (the default). The trampolines and patched pages are program
  memory (read-execute; a program that remaps or reprotects them gets its original pages back,
  above: only pages of the program's own mappings that hold the plan's patched pages are ever
  mapped over, and never a page of the runtime's region); the plan cell is program memory with the consequences of the compute-point cell
  (below). What the runtime trusts of a plan (its placement and site rows) is mapped read-only
  in the runtime's region. The broker's socket is a hidden descriptor; the plan cache is
  reachable only by the launcher, outside the sandbox; a cache entry changed on disk is
  detected and made again. The plan is made and verified on the host, from untrusted file
  bytes, in safe Rust; the seccomp filter is unchanged (the trampolines make no system call).
- **The compute-point cell** is program memory outside the runtime's region, read and written
  by the runtime only through its fault-safe guest copy. A program that writes it changes only
  when its own process's next compute point comes and how many events it is charged (at most
  the value last written, so at most 2^22 ns per runtime entry), the same in every run; one that
  unmaps or protects it ends the run `unsupported`, stop `compute-cell`. A system call that
  writes it (a `read` into it) is such a write. The arm64 signal restorer page is program
  memory too (read-execute, listed in `/proc/self/maps`): a call reading it reads its two
  instructions, one writing it gets `EFAULT` as for any read-only page.

- **The debug word** (`Config::debug`, "Debugging a run") is in the control region's
  configuration, written by the launcher before the program starts: what holds for the control
  region holds for it, and its rules (the gate, the debugger's signals taken by the runtime)
  exist only in a `patina debug` replay.

Detected:
- A program access that faults in the runtime's region (at a published address, in an unmapped
  part, or a store into its text), and program code running runtime code (a jump into its
  text), end the run with the address, the instruction, and for the control region the field
  (`sup/contain.rs`). A program that probes addresses with its own SIGSEGV handler and walks
  into the runtime's region therefore ends the run there, where natively its handler would run.

Out of scope (a deliberate attack):
- Finding the read-write mappings (reading the runtime's memory with the program's own loads,
  or probing about 2^23 pages of each window) and storing there. Storing into the runtime's
  own data and per-thread state (its `.data`, and the base of its alternate stacks, which stay
  writable because the kernel writes signal frames there): they sit at fixed addresses no
  program is given. Reading the runtime's text and data with the program's own loads is not
  detected (a system call cannot read them for it: above).
- A file built to make the rewriter or verifier fail on the host (with load-time points):
  a panic there ends the launcher, so the run ends without a result, never with the file
  partly planned.
- Pointing the stack pointer into the runtime's region before jumping to the stub, or
  `rt_sigreturn` through the stub with a forged frame.

Write protection that switches at every trap (`mprotect` on entry and exit) was measured and
rejected: 1.3 to 7.8 µs per pair against a trap of about 1 µs.

## Limits

- **Linux x86_64 and arm64.** No macOS. Unprivileged user namespaces are required (on
  Ubuntu 24.04 and later, an AppArmor profile for the executable, or the restriction lifted). arm64 needs Linux 6.12 or later (the counter-timer trap), 4 KiB pages, a
  48-bit address space and one CPU model among the CPUs a run may use; `patina doctor`
  refuses a host without them. Also refused there: an SVE vector length above 512 bits, and a
  run that uses SME's streaming mode or ZA (`signal-context`). A program cannot enable MTE or
  guarded control stacks (their `prctl`s answer `EINVAL` and are recorded) or allocate a
  protection key (`pkey_alloc` answers `ENOSYS`); `FPMR` and `POR_EL0` are carried through
  signal frames. On arm64 every system call is served as on x86_64 (the
  structure layouts and flags that differ are in `proto::abi`, the argument orders in `arch`), and
  `patina doctor` checks the host's arm64 requirements. Threads, fork,
  vfork, exec and signals work as on x86_64 (the clone trampoline is in
  `arch/aarch64/thread.rs`); so do the instruction channels, pause points and spin probes
  (above), and the
  four SDKs and compute points (the SDKs' raw call is `svc #0`; Go's hook is
  `go/patina/compute/compute_arm64.s`). The
  runtime's loader maps a BTI-marked static program, or the interpreter, `PROT_BTI` as the
  kernel does where the host has BTI; the interpreter does it for the program and its
  libraries. The runtime disables the pointer-authentication keys before
  anything else at every image start (`arch/aarch64`): the kernel enables and redraws them at
  each exec. `PR_SET_TSC` makes the counter-timer reads (`CNTVCT_EL0`, `CNTVCTSS_EL0`,
  `CNTFRQ_EL0`) fault, answered from virtual time; `CNTPCT_EL0` raises `SIGILL` natively and
  under Patina alike. CPU features reach the program as the host has them (`AT_HWCAP` to
  `AT_HWCAP4`, `AT_MINSIGSTKSZ`, the `Features` of `/proc/cpuinfo`), as `cpuid` does on x86_64:
  two hosts of the same kind give the same run. A feature bit a later kernel adds passes too
  (state it lets a program enable stops the run at its first signal, `signal-context`); an
  auxiliary vector entry the loader does not list is not given (`proto::hwcap`). Three are
  hidden: `PACGA` (its key cannot be turned off and
  is redrawn at each exec; a program that executes it anyway is labelled, `pacga_sites`);
  SME (with its ZA storage and streaming mode), so a program that asks before using a feature
  never enters SME state, whose contents and vector length are host-dependent; and `CPUID`,
  the kernel's emulation of the ID registers, whose `MIDR_EL1` names the core a thread runs
  on. A program that executes SME instructions or reads ID registers without asking is not
  stopped. Seeds and digests are per architecture and per kind of host: the host's own
  libraries and `/etc/ld.so.cache` are inputs of a dynamic program's run.
- **A seed reproduces for the same program binary and the same Patina build, on the same kind
  of host.** `run.json` records both binaries' SHA-256 (`patina` is the version and the hash of
  the `patina` binary); replay, minimize and `run --config RUNDIR/run.json` refuse a run whose
  either one differs, and a sweep into a directory another build made starts over. The kernel's own behaviour for passed calls is an
  input: a different kernel version or filesystem may change a run.
- **Load-time points** (the default): the points are at backward branches,
  backward calls, indirect jumps and atomics that a single-instruction patch can reach (most,
  not all: above), so a race between plain accesses with no such instruction between them
  is not split, as in stock code. Libraries load at other addresses than without points, and a
  program reading its own text reads the patch. `cpuid`'s core ids are core 0's, but on a
  hybrid CPU the leaves that differ by core type (caches, TLBs) are the core's, so seeds there
  repeat only on one kind of core. A plan is found by the file's identity (device, inode, size,
  change time): a file the program rewrites in place at the same size, on a filesystem whose
  change times are coarse, can keep the old plan for a moment. At most 64 planned images per
  process (more run without points, counted `unplanned`). Seeds found without points do not replay with
  them, or the reverse.
- **compute-stall**: in stock code without points, a spin-wait whose iterations change state
  ends the run (above).
- **Interleaving at system calls, pause points and spin probes only** in stock code. A race on
  plain memory with none of these between the conflicting accesses runs in one order in every
  seed. Rebuilding the code with compute points switches inside it; so do load-time points
  (the default) at the branches, calls and atomics inside it. Compute points do not split an atomic
  read-modify-write (a `lock`-prefixed instruction; on arm64 an LSE instruction, an
  exclusive load/store pair, or the compilers' out-of-line atomic helpers, which are not
  rebuilt), gcc gives edges only, and code not rebuilt (libc, the Go runtime,
  prebuilt libraries) has no points. A seed found on a stock build does not replay on a
  rebuilt one, or the reverse. In Python (`python3 -m patina`) the points are at line starts
  and jumps: inside a line only CPython's own switch request switches, a bytecode-atomic
  operation (`dict.setdefault`, `list.append`) is never split, and C extensions and the
  interpreter's own C code have none.
- **Stock computation does not advance virtual time**: a CPU-bound loop cannot be cut by
  `[run] time-limit` or a program's own deadline, only by `--timeout` (wall time), unless it runs
  with load-time points (the default) and the loop has a point. A loop that
  makes any system call (a clock read) advances it by the per-trap charge. Rebuilt code is
  charged 1 ns per event (Python under `python3 -m patina`, 15 ns per line and jump) and cut at
  the event where a deadline falls due.
- **One thread runs at a time**, so weak-memory behaviours (a store another CPU sees late)
  never happen.
- **One clock, one kernel.** All processes of a run share one sandbox, one kernel and one
  virtual clock. Several machines are nodes inside it (above, "Nodes"): each has its own
  files, hostname, IPC, ports, address and realtime clock offset, but no clock drift (a
  clock's rate is the run's), no own kernel or OS image, no
  IPv6 address, at most 15 besides the driver; and there is no network outside the run.
- **TCP and UDP only.** Raw, packet and netlink sockets, and `SOCK_DGRAM` with a protocol
  other than UDP, are refused and listed in `result.json`'s `refused`; `patina run` prints
  them. On UDP: multicast and broadcast (and their membership options), ancillary data on send,
  options that ask for it on receive (`IP_PKTINFO`, `UDP_GRO`) or change segmentation
  (`UDP_SEGMENT`, `UDP_CORK`), `MSG_MORE`, more than 64 iovecs in one datagram and `sendfile`
  to a UDP socket are refused; a receive carries no ancillary data and `MSG_ERRQUEUE` finds
  nothing.
  `recvmmsg` returns once at least one datagram is there. Names resolve from `/etc/hosts` only.
  A TCP connect after a failed one is a new attempt, and `shutdown(SHUT_RD)` or `SHUT_RDWR` of
  a listener stops it (its waiting connections are reset, `accept` fails `EINVAL`, new connects
  are refused), as in the kernel, where nothing else holds the socket; one that a duplicate
  descriptor, another process or an epoll set also holds ends the run `unsupported` (its real
  socket is replaced). A stopped listener cannot be bound, listened on or connected again.
  Keepalive: answered probes are not modelled one by one, so the time of the first
  unanswered one assumes they came every `max(TCP_KEEPINTVL, TCP_KEEPIDLE)` with no round
  trip (Linux's drift by each round trip is left out), and a change of `TCP_KEEPIDLE` while a
  side is probing takes effect after it; a peer that closed answers probes for ever (Linux's
  orphaned socket answers for `tcp_fin_timeout`, 60 s, then resets); data delivered while the
  way back is cut counts as unacknowledged (no probes), but its retransmissions do not time
  out (Linux's would after `tcp_retries2`); a connection not yet accepted that gives up is
  reported `ECONNRESET` at its accept; an accepted socket starts with its listener's keepalive
  options and no other (Linux copies them all, `TCP_USER_TIMEOUT` included).
- **Fixed tables.** The runtime keeps some state in fixed tables shared by the run: virtual
  inode numbers of pipes, sockets and timers (16,384 per run, never reused), shared writable
  work-tree mappings (128 per process, of 64 files at once in the run; the shadow of each
  file holds its data, as sparse as the file), shared mappings (256 per process), injected
  fsync failures (4,096 files). Filling one ends the run `unsupported`, stop `capacity`, naming it.
  The table of changed files' times drops the entries of deleted files nothing holds open
  (`sup/vtgc.rs`), so only files still reachable count against it (65,536).
- Not modelled: `timer_create`, `io_uring`; another process's `/proc/PID` (the syscall table,
  `patina --help --format json`, says what each call does). Scheduling attributes (`setpriority`, `sched_setscheduler`,
  `sched_setattr` and their getters) are kept and read back but change nothing in the
  schedule; what the kernel refuses an unprivileged process is refused.
