//! Tests for virtual-time sleep and timeout futures.

use super::*;
use crate::executor::with_scope;
use crate::tests::{assert_invalid_state, context};
use crate::{block_on, spawn};
use std::cell::RefCell;
use std::rc::Rc;
use std::task::{RawWaker, RawWakerVTable, Waker};

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, wake);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

#[test]
fn leaf_future_polled_outside_block_on_fails_closed() {
    let mut sleep = Box::pin(sleep_for(1));
    let waker = noop_waker();
    let mut cx = TaskContext::from_waker(&waker);
    let Poll::Ready(Err(error)) = sleep.as_mut().poll(&mut cx) else {
        panic!("sleep outside executor should fail");
    };
    assert_invalid_state(error);
}

// Class pairing: runtime boot_origin::relative_sleep_saturates_at_the_deadline_limit.
#[test]
fn relative_sleep_saturates_and_can_be_timed_out() {
    let mut ctx = context(7);
    let start = ctx.now(ClockKind::Monotonic).unwrap();
    block_on(&mut ctx, async {
        assert!(timeout(10, sleep_for(u64::MAX)).await?.is_none());
        Ok::<_, RuntimeError>(())
    })
    .unwrap()
    .unwrap();
    assert_eq!(ctx.now(ClockKind::Monotonic).unwrap(), start + 10);
    ctx.finish().unwrap();
}

#[test]
fn timers_rescue_at_exact_deadlines_and_timeout_ties() {
    let mut ctx = context(7);
    let start = ctx.now(ClockKind::Monotonic).unwrap();
    let log = Rc::new(RefCell::new(Vec::new()));
    block_on(&mut ctx, {
        let log = Rc::clone(&log);
        async move {
            let a_log = Rc::clone(&log);
            let a = spawn("sleep-200", async move {
                sleep_for(200).await?;
                a_log.borrow_mut().push(("a", 200));
                Ok::<_, RuntimeError>(())
            })?;
            let b_log = Rc::clone(&log);
            let b = spawn("sleep-500", async move {
                sleep_for(500).await?;
                b_log.borrow_mut().push(("b", 500));
                Ok::<_, RuntimeError>(())
            })?;
            a.await??;
            assert_eq!(
                with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))
                    .unwrap(),
                start + 200
            );
            b.await??;
            assert_eq!(
                with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))
                    .unwrap(),
                start + 500
            );
            assert!(timeout(100, sleep_for(300)).await?.is_none());
            assert_eq!(
                with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))
                    .unwrap(),
                start + 600
            );
            assert_eq!(timeout(100, async { 9 }).await?, Some(9));
            Ok::<_, RuntimeError>(())
        }
    })
    .unwrap()
    .unwrap();
    assert_eq!(&*log.borrow(), &[("a", 200), ("b", 500)]);
    ctx.finish().unwrap();
}
