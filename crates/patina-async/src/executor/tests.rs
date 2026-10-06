//! Tests for task execution, wakeups, and scheduler state.

use super::*;
use crate::tests::{assert_invalid_state, context};
use crate::{UdpSocket, sleep_for};
use patina_dst_abi::ClockKind;
use patina_dst_net_sim::SimNet;
use patina_dst_runtime::{RuntimeBuilder, RuntimeConfig};
use patina_dst_wrapper_latency::LatencyNet;

#[test]
fn block_on_plain_value() {
    let mut ctx = context(1);
    let value = block_on(&mut ctx, async { 7 }).unwrap();
    assert_eq!(value, 7);
    ctx.finish().unwrap();
}

#[test]
fn spawn_join_and_yield() {
    let mut ctx = context(2);
    let value = block_on(&mut ctx, async {
        let handle = spawn("worker", async {
            yield_now().await;
            41
        })?;
        yield_now().await;
        let value = handle.await?;
        Ok::<_, RuntimeError>(value + 1)
    })
    .unwrap()
    .unwrap();
    assert_eq!(value, 42);
    ctx.finish().unwrap();
}

#[test]
fn nested_block_on_fails_closed_inner() {
    let mut ctx = context(3);
    block_on(&mut ctx, async {
        let mut other = context(4);
        assert_invalid_state(block_on(&mut other, async { 1 }).unwrap_err());
    })
    .unwrap();
    ctx.finish().unwrap();
}

#[test]
fn live_spawned_task_at_main_completion_fails_closed() {
    let mut ctx = context(5);
    let error = block_on(&mut ctx, async {
        let _handle = spawn("parked", async {
            sleep_for(10).await.unwrap();
            1
        })?;
        Ok::<_, RuntimeError>(())
    })
    .unwrap_err();
    assert_invalid_state(error);
}

#[test]
fn preexisting_scheduler_task_is_rejected() {
    // `main` completes on its first poll, so on many seeds the scheduler
    // never selects the foreign task inside the run loop. The rejection must
    // hold regardless of that poll order, so assert it across a seed range.
    for seed in 0..32 {
        let mut ctx = context(seed);
        let _foreign = ctx.task_spawn("foreign").unwrap();
        let error = block_on(&mut ctx, async {}).unwrap_err();
        assert_invalid_state(error);
    }
}

fn interleaving(seed: u64) -> Vec<&'static str> {
    let mut ctx = context(seed);
    let log = Rc::new(RefCell::new(Vec::new()));
    block_on(&mut ctx, {
        let log = Rc::clone(&log);
        async move {
            let mut handles = Vec::new();
            for name in ["a", "b", "c"] {
                let log = Rc::clone(&log);
                handles.push(spawn(name, async move {
                    log.borrow_mut().push(name);
                    yield_now().await;
                    log.borrow_mut().push(name);
                })?);
            }
            for handle in handles {
                handle.await?;
            }
            Ok::<_, RuntimeError>(())
        }
    })
    .unwrap()
    .unwrap();
    ctx.finish().unwrap();
    Rc::try_unwrap(log).unwrap().into_inner()
}

#[test]
fn polling_order_is_seed_stable_and_varies() {
    let mut seen = BTreeSet::new();
    for seed in 0..100 {
        let first = interleaving(seed);
        let second = interleaving(seed);
        assert_eq!(first, second, "seed {seed}");
        seen.insert(first);
    }
    assert!(seen.len() >= 2);
}

#[test]
fn same_deadline_rescue_peer_wake_reconciles_shadow_state() {
    // Two receivers are timed-parked at the SAME rescue deadline (both under
    // 50ns latency) AND each is registered on a recv-waiter address. The
    // deadlock rescue wakes both at once, making them Runnable in the
    // scheduler. When the first-polled task then peer-wakes the second task's
    // address, the executor must not re-wake the already-Runnable second task.
    // Without reconciling the rescued set into `self.parked` / the waiter
    // registries, the drain issues a `task_wake` on a Runnable task and the
    // program aborts with InvalidState.
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(14))
        .with_default_drivers()
        .with_network(LatencyNet::new(SimNet::new(), 1).latency_nanos(50))
        .build()
        .unwrap();
    let order = Rc::new(RefCell::new(Vec::new()));
    block_on(&mut ctx, {
        let order = Rc::clone(&order);
        async move {
            let s1 = UdpSocket::bind("s1").await?;
            let s2 = UdpSocket::bind("s2").await?;
            let client = UdpSocket::bind("client").await?;
            let a = spawn("recv-s1", {
                let order = Rc::clone(&order);
                async move {
                    let datagram = s1.recv().await?;
                    let now = with_scope(|scope| {
                        unsafe { scope.context_mut() }.now(ClockKind::Monotonic)
                    })?;
                    assert_eq!(now, patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS + 50);
                    assert_eq!(datagram.delivery_nanos, now);
                    // Peer-wake the other receiver's address; it is the task
                    // that was rescued at the same deadline.
                    s1.send_to("s2", b"a").await?;
                    order.borrow_mut().push("a");
                    Ok::<_, RuntimeError>(datagram.bytes)
                }
            })?;
            let b = spawn("recv-s2", {
                let order = Rc::clone(&order);
                async move {
                    let datagram = s2.recv().await?;
                    let now = with_scope(|scope| {
                        unsafe { scope.context_mut() }.now(ClockKind::Monotonic)
                    })?;
                    assert_eq!(now, patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS + 50);
                    assert_eq!(datagram.delivery_nanos, now);
                    s2.send_to("s1", b"b").await?;
                    order.borrow_mut().push("b");
                    Ok::<_, RuntimeError>(datagram.bytes)
                }
            })?;
            yield_now().await;
            client.send_to("s1", b"to-s1").await?;
            client.send_to("s2", b"to-s2").await?;
            let a_bytes = a.await??;
            let b_bytes = b.await??;
            assert_eq!(a_bytes, b"to-s1");
            assert_eq!(b_bytes, b"to-s2");
            Ok::<_, RuntimeError>(())
        }
    })
    .unwrap()
    .unwrap();
    assert_eq!(order.borrow().len(), 2);
    ctx.finish().unwrap();
}
