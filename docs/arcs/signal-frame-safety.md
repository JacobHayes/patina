# Signal frame safety: return to C before delivery

## Decision

Status: designed, not implemented. Until the port lands, a guest handler that
leaves by `siglongjmp` or `setcontext` while it interrupts a shim call skips
live shim Rust frames; that path is unsupported. The detector is in place:
in a `planted-faults` shim `PanicScope` counts the scopes each thread holds,
and `native_signals`
(`testbeds/native-boundary/signals/frame_abandon.c`) pins every delivery
origin that still runs a handler over a shim Rust frame as a gap.

Retain `PanicScope` and its destructor. A C driver owns each interval in which a
guest handler may run. Rust preparation returns a result or a delivery request,
with all its locks, allocations and borrows released; C releases the host signal
frames; returning Rust completion runs only if the handler returns. Blocking
operations use explicit continuations. This applies to Linux x86_64, Linux
arm64 and the currently supported Darwin arm64 signal model.

This is an older model/delivery defect exposed by the C-to-Rust wave: the old
C adapters also called guarded Rust model entries that delivered signals.

The invariant is **no shim Rust caller frame at guest delivery**, rather than
just no destructor in the immediate helper. `siglongjmp` and abandoning
`setcontext` then discard C frames; a suspended context retains valid C records
until it returns. The guest remains responsible for nonlocal exits across its
own Rust frames and for the platform's signal/context contracts.

The [Rust Reference](https://doc.rust-lang.org/reference/behavior-considered-undefined.html#undefinedruntime)
forbids discarding Rust frames without running their local destructors.
[RFC 2945](https://rust-lang.github.io/rfcs/2945-c-unwind-abi.html#frame-deallocation-and-forced-unwinding)
adds a stronger reason to choose this seam: being a POF is necessary but does
not itself specify a safe general frame-deallocation contract. Changing ABI
strings or relying on tail-call optimization does not establish this invariant.

## Alternatives

A drop-free `PanicScope` removes one destructor, while delivery still owns a
batch vector and fault scope, and callers own copied buffers and other guards.
TLS depth repair would also need to distinguish abandoned handlers from
handlers suspended in coroutines. More importantly, it would remove the existing
unwind detector that private-aborts even after a guest replaces the panic hook.
Restoring that detector and proving every transitive frame POF costs more than
returning from those frames.

Delivering only after an entire syscall completes is too late. A handler can
change state before the interrupted operation continues; restartable I/O must
run the handler before retrying. The chosen design returns to C at the existing
semantic delivery points, including scheduler handoffs and wait resumption.
A separate Rust execution stack would retain rather than discard destructors,
but would require continuation cancellation and resource reclamation, and could
leave model locks held across guest work. It is a larger mechanism.

## Semantics and ownership

A wait first removes its registrations and settles the interruption/restart
outcome. Its C continuation then delivers, and either returns `EINTR`, retries,
or completes the normal outcome. `poll` never restarts for `SA_RESTART`.
Read/socket continuations must preserve their existing restart classification,
partial-result rules and absolute deadlines. Temporary-mask continuations must
keep the temporary mask through delivery and restore the old mask only on the
normal completion path; a nonlocal exit leaves mask restoration (if requested)
to the guest's `siglongjmp`/`setcontext`, as natively.

Linux delivery retains the existing dequeue order, combined-versus-individual
host-frame release, captured actions, reset/nodefer behavior, saved masks,
virtual SIGSEGV state and containment-mask stripping. Preparation uses Rust
vectors, copies the resulting records into C storage, and frees the vectors
before release. Fault-scope and dispatch/counter restoration state resides in
the C frame and uses explicit returning begin/end helpers. Existing frame
resynchronization handles abandoned signal frames. Handler-depth accounting
uses those same guest-slot markers instead of a decrement that a jump skips;
normal return removes the marker, overwritten slots no longer count, and
potentially resumable contexts remain conservatively tracked. A marker on the
private C stack alone is insufficient: that stack can survive an abandoning
jump. Ownership snapshots restore the previous entry identity and guest stack
pointer after normal completion; no panic-ownership recovery protocol is needed
at a migrated door.

Each Rust step keeps the ordinary guard until it returns. A step's panic therefore
still takes the private abort, leaves an incomplete trace and bypasses guest
SIGABRT handling. The hook, unwind guard and panic-time abort policies remain
in effect under both panic strategies. C release failures use the private fatal
vehicle. Handlers run with guest ownership and may make further shim calls.

Darwin retains its synchronous, unblocked self-signal contract and its existing
refusals for deferred/siginfo delivery. Rust records and validates generation,
then returns the private current-thread vehicle to C. Uncontrolled asynchronous
host signals remain outside this modeled contract.

## Enforcement

Keep the existing export guard lint. With the port, add one compiled must-fail
control behind the existing `test-panic` feature: a guest that wraps the C
delivery seam in a Rust guard must private-abort. It detects guarded enclosing
entries, not every destructor; the C continuation structure supplies the rest.
No destructor inventory, interprocedural checker, generator or per-wrapper
fixtures. Once every caller migrates, remove the Rust-callable release bridge
so Rust model APIs expose only delivery requests and returning completion,
making model-side guest release unavailable by construction.

## Port plan

Start with one returning-Rust-step plus C-driver path (`poll` and
`patina_signal_result`) and a guest that leaves `poll` by `siglongjmp`, checks
masks and keeps making shim calls. Then:

1. Convert scheduler pre-operation and post-handoff delivery into returning
   requests propagated through `with_context` and SUD/counter dispatch. The C
   trap/libc drivers must deliver before continuing the interrupted operation.
2. Convert restartable waits by family: pipe/socket/PTY/eventfd/signalfd I/O,
   futex/IPC/file locks, then reactor/timer/signal waits. Carry owned operand
   snapshots and settled results in C continuations; restore temporary masks
   after normal delivery only. Preserve sync-wait queue ownership separately.
3. Convert signal generation/mask changes, SIGPIPE and abort/fortify paths;
   migrate their public and prefixed ABI doors together. Collapse the remaining
   guarded Rust release callers once no semantic delivery point uses them.
4. Retire the Rust delivery driver and direct delivery bridge. Broaden existing
   interruption/restart/mask and small-stack/context suites at each converted
   family, including execution on Linux arm64.

The audit identifies roughly 18 direct delivery sites and 20 resume sites:
about 10–15 continuation families, plus mechanical outer adapters. Estimate
2,000–4,000 lines touched across several slices; this is a planning estimate,
not measured implementation work.

Automatic C arrays for poll snapshots and delivery batches would be simplest.
Their storage disappears automatically on an abandoning jump and stays valid
for a suspended C context, but scales with descriptor/batch cardinality. This
is not a final resource policy for small guest stacks or large `SA_NODEFER`
realtime batches. Before broad migration, move large buffers to shim-owned
continuation records: reclaim on normal completion or proven frame abandonment,
retain while a context may resume, and preserve current descriptor/queue limits.
Do not truncate, reorder, or introduce a new cardinality refusal to bound the
arrays.
