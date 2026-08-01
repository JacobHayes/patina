# Checkout retry idempotency simulator

This testbed demonstrates the user-facing reason to use Patina's explicit-context mode: build a small, deterministic world around one component whose failure mode is easier to model than to reproduce in a full deployment.

The problem is familiar: a mobile client sends a checkout request, times out before the response returns, and retries with the same idempotency key. The service must not charge the order twice.

The checkout ledger in [`src/checkout.rs`](src/checkout.rs) is ordinary Rust. It imports no Patina crates. The simulator in [`src/main.rs`](src/main.rs) builds a deterministic world around that code:

- a virtual mobile client actor;
- a virtual checkout-service actor;
- a Patina `SimNet` UDP link with 10 ms of virtual latency each way;
- a 15 ms virtual client timeout, short enough to force one retry before the first 20 ms round-trip response arrives;
- an invariant: one logical order and idempotency key may produce at most one charge.

No host sockets are opened, no wall-clock sleep occurs, and no application code has to depend on tokio or a Patina-aware networking trait. The simulator owns the world and calls the ordinary checkout logic from virtual actors.

That boundary is intentional: the ordinary code under test must be deterministic from the simulator's inputs. If `src/checkout.rs` internally read host time, random numbers, files, sockets, real threads, tokio timers, or FFI, explicit-context mode would not control those effects. The fix would be to inject those effects into the ledger, model them in the simulator, or run the full application under the shim/harness instead.

## Run it

```sh
testbeds/checkout-retry-idempotency/run-sim.sh
```

Expected output:

```text
CHECKOUT_IDEMPOTENCY_RESULT mode=correct ... attempts=2 timeouts=1 duplicate_requests=1 charges=1 ... status=ok
```

That line proves the interesting behavior happened. The client really retried, the service really saw the duplicate request, and the ledger still charged once. A test where no retry occurred would not be evidence for this property.

## Prove the check can fail

```sh
testbeds/checkout-retry-idempotency/run-sim.sh --selftest
```

The selftest also runs a planted buggy ledger that recognizes the duplicate request but performs the charge again. It must emit:

```text
CHECKOUT_IDEMPOTENCY_VIOLATION mode=buggy ... duplicate_requests=1 charges=2 reason=retry_charged_twice
CHECKOUT_IDEMPOTENCY_SELFTEST passed
```

## What explicit-context mode is for

Use this shape when you want an executable model or test world around part of your system: protocol code, retry/idempotency logic, storage recovery rules, fake services, or other components whose environment is easier to model explicitly than to run as a whole application.

This is not a formal proof system. It is deterministic simulation testing: you state an invariant, run a controlled model through specific or many seeded interleavings, and get reproducible counterexamples when the invariant fails. For a full application that already uses `std`/tokio directly, the normal Patina path is still the native shim or harness, not this mode.
