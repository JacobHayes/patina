//! Deterministic task execution, poll scopes, wakeups, yielding, and joining.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Wake, Waker};

use patina_dst_abi::{ClockKind, EffectError, ErrorCode, TaskId};
use patina_dst_runtime::{Context, RuntimeError};

const REASON_ASYNC_WAIT: &str = "async-wait";
const REASON_JOIN_WAIT: &str = "join-wait";
const MAIN_LABEL: &str = "async-main";

thread_local! {
    static SCOPE: Cell<Option<NonNull<PollScope>>> = const { Cell::new(None) };
}

/// Run `future` to completion on a deterministic single-threaded executor.
///
/// The main future becomes a scheduler task on `context`; every pending poll
/// and wakeup is a recorded boundary operation, so the interleaving is a pure
/// function of the run seed. Nesting `block_on` (from within a polled future)
/// fails closed, and a spawned task still live when the main future completes
/// is an error — join or let every [`spawn`]ed task finish first.
pub fn block_on<F: Future>(context: &mut Context, future: F) -> Result<F::Output, RuntimeError> {
    if SCOPE.with(|scope| scope.get().is_some()) {
        return Err(invalid_state(
            "nested patina_dst_async::block_on is not supported",
        ));
    }
    Executor::new(context)?.run(future)
}

/// Spawn a future onto the current Patina async executor as a new
/// deterministic task.
///
/// This function must be called while a future is being polled by [`block_on`].
/// `label` names the task in traces and diagnostics. The returned
/// [`JoinHandle`] resolves to the task's output; dropping it detaches the task,
/// but every spawned task must still complete before the main future does
/// (see [`block_on`]).
pub fn spawn<F>(label: &str, future: F) -> Result<JoinHandle<F::Output>, RuntimeError>
where
    F: Future + 'static,
    F::Output: 'static,
{
    with_scope(|scope| {
        // SAFETY: the poll scope is installed only while the executor's exclusive
        // `&mut self` borrow is live on this thread.
        unsafe { scope.executor_mut().spawn(label, future) }
    })
}

/// Yield the current task, allowing the scheduler to choose another runnable task.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

struct TaskEntry {
    future: Pin<Box<dyn Future<Output = ()>>>,
    waker: Waker,
    joiners: VecDeque<TaskId>,
}

pub(super) struct Executor<'ctx> {
    context: &'ctx mut Context,
    main_task: TaskId,
    tasks: BTreeMap<TaskId, TaskEntry>,
    wake_queue: Arc<Mutex<VecDeque<TaskId>>>,
    queued: BTreeMap<TaskId, Arc<AtomicBool>>,
    current_poll: Arc<Mutex<Option<TaskId>>>,
    self_wake: Arc<AtomicBool>,
    parked: BTreeSet<TaskId>,
    accept_waiters: BTreeMap<String, VecDeque<TaskId>>,
    recv_waiters: BTreeMap<String, VecDeque<TaskId>>,
    send_waiters: BTreeMap<String, VecDeque<TaskId>>,
}

impl<'ctx> Executor<'ctx> {
    fn new(context: &'ctx mut Context) -> Result<Self, RuntimeError> {
        let main_task = context.task_spawn(MAIN_LABEL)?;
        let wake_queue = Arc::new(Mutex::new(VecDeque::new()));
        let current_poll = Arc::new(Mutex::new(None));
        let self_wake = Arc::new(AtomicBool::new(false));
        let mut executor = Self {
            context,
            main_task,
            tasks: BTreeMap::new(),
            wake_queue,
            queued: BTreeMap::new(),
            current_poll,
            self_wake,
            parked: BTreeSet::new(),
            accept_waiters: BTreeMap::new(),
            recv_waiters: BTreeMap::new(),
            send_waiters: BTreeMap::new(),
        };
        executor.ensure_wake_flag(main_task);
        Ok(executor)
    }

    fn run<F: Future>(&mut self, future: F) -> Result<F::Output, RuntimeError> {
        let mut main = Box::pin(future);
        let main_waker = self.waker_for(self.main_task);
        let mut main_output = None;

        loop {
            self.settle_expired();
            self.drain_wake_queue()?;
            let selected = self.context.scheduler_next()?;
            self.settle_expired();
            let Some(task) = selected else {
                break;
            };
            if task == self.main_task {
                self.poll_main_pending(main.as_mut(), &main_waker, &mut main_output)?;
                if main_output.is_some() {
                    break;
                }
            } else if self.tasks.contains_key(&task) {
                self.poll_spawned(task)?;
            } else {
                return Err(invalid_state(format!(
                    "scheduler selected task {} which is not owned by this executor",
                    task.0
                )));
            }
        }

        let output = main_output
            .ok_or_else(|| invalid_state("scheduler became empty before async main completed"))?;
        if !self.tasks.is_empty() {
            return Err(invalid_state(format!(
                "async main completed with {} live spawned tasks; join them or let them finish",
                self.tasks.len()
            )));
        }
        // No executor-owned task remains, so any task the scheduler still hands
        // out belongs to someone else. Probe once at this always-reached point:
        // the loop above can break the instant `main` completes (before the
        // scheduler ever selects the foreign task), so an order-independent check
        // here is what makes the rejection deterministic rather than seed-luck.
        if let Some(task) = self.context.scheduler_next()? {
            return Err(invalid_state(format!(
                "scheduler selected task {} which is not owned by this executor",
                task.0
            )));
        }
        Ok(output)
    }

    fn spawn<F>(&mut self, label: &str, future: F) -> Result<JoinHandle<F::Output>, RuntimeError>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let task = self.context.task_spawn(label)?;
        self.ensure_wake_flag(task);
        let slot = Rc::new(RefCell::new(None));
        let completed = Rc::new(Cell::new(false));
        let body_slot = Rc::clone(&slot);
        let body_completed = Rc::clone(&completed);
        let body = async move {
            let output = future.await;
            *body_slot.borrow_mut() = Some(output);
            body_completed.set(true);
        };
        let entry = TaskEntry {
            future: Box::pin(body),
            waker: self.waker_for(task),
            joiners: VecDeque::new(),
        };
        self.tasks.insert(task, entry);
        Ok(JoinHandle {
            task,
            slot,
            completed,
        })
    }

    fn poll_spawned(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.purge_task_from_waiters(task);
        let mut entry = self
            .tasks
            .remove(&task)
            .ok_or_else(|| invalid_state(format!("missing executor task {}", task.0)))?;
        let mut scope = PollScope::new(self, task);
        let task_context_guard = TaskContextGuard::new(
            Arc::clone(&self.current_poll),
            Arc::clone(&self.self_wake),
            task,
        );
        let _scope_guard = ScopeGuard::install(&mut scope)?;
        let mut cx = TaskContext::from_waker(&entry.waker);
        let poll = entry.future.as_mut().poll(&mut cx);
        drop(_scope_guard);
        drop(task_context_guard);
        match poll {
            Poll::Ready(()) => {
                for joiner in entry.joiners {
                    self.enqueue_wake(joiner);
                }
                self.context.task_complete(task)?;
                self.parked.remove(&task);
                self.queued.remove(&task);
                self.purge_task_from_waiters(task);
                Ok(())
            }
            Poll::Pending => {
                let pending = scope.into_pending();
                self.tasks.insert(task, entry);
                self.apply_pending(task, pending)
            }
        }
    }

    fn apply_pending(
        &mut self,
        task: TaskId,
        pending: PendingDecision,
    ) -> Result<(), RuntimeError> {
        if self.self_wake.swap(false, Ordering::SeqCst) {
            self.context.task_yield(task)?;
            self.parked.remove(&task);
            return Ok(());
        }
        self.apply_interests(task, pending.interests);
        let reason = pending.reason.unwrap_or(REASON_ASYNC_WAIT);
        if let Some(deadline) = pending.deadline {
            self.context
                .task_park_timed(task, reason, ClockKind::Monotonic, deadline)?;
        } else {
            self.context.task_park(task, reason)?;
        }
        self.parked.insert(task);
        // A deadline already reached expires at registration.
        self.settle_expired();
        Ok(())
    }

    /// Reconcile the executor's shadow state with the runtime's timer expiries
    /// (every clock advance and timed park can expire timers, waking their
    /// tasks): an expired task leaves `self.parked` and every net-waiter
    /// registry before anything can wake it again, since `task_wake` on an
    /// already-Runnable task fails closed.
    fn settle_expired(&mut self) {
        for expired in self.context.take_expired_timeouts() {
            self.parked.remove(&expired);
            self.purge_task_from_waiters(expired);
        }
    }

    fn drain_wake_queue(&mut self) -> Result<(), RuntimeError> {
        loop {
            let task = {
                let mut queue = self.wake_queue.lock().expect("wake queue mutex poisoned");
                queue.pop_front()
            };
            let Some(task) = task else { break };
            if let Some(flag) = self.queued.get(&task) {
                flag.store(false, Ordering::SeqCst);
            }
            if self.parked.contains(&task) {
                self.purge_task_from_waiters(task);
                self.context.task_wake(task)?;
                self.parked.remove(&task);
            }
        }
        Ok(())
    }

    fn ensure_wake_flag(&mut self, task: TaskId) -> Arc<AtomicBool> {
        if let Some(flag) = self.queued.get(&task) {
            return Arc::clone(flag);
        }
        let flag = Arc::new(AtomicBool::new(false));
        self.queued.insert(task, Arc::clone(&flag));
        flag
    }

    fn waker_for(&mut self, task: TaskId) -> Waker {
        let queued = self.ensure_wake_flag(task);
        Waker::from(Arc::new(WakeHandle {
            task,
            queue: Arc::clone(&self.wake_queue),
            queued,
            current_poll: Arc::clone(&self.current_poll),
            self_wake: Arc::clone(&self.self_wake),
        }))
    }

    fn enqueue_wake(&mut self, task: TaskId) {
        let Some(flag) = self.queued.get(&task) else {
            return;
        };
        if !flag.swap(true, Ordering::SeqCst) {
            self.wake_queue
                .lock()
                .expect("wake queue mutex poisoned")
                .push_back(task);
        }
    }

    pub(super) fn wake_waiters(&mut self, kind: NetInterestKind, address: &str) {
        let waiters = match kind {
            NetInterestKind::Accept => self.accept_waiters.remove(address),
            NetInterestKind::Recv => self.recv_waiters.remove(address),
            NetInterestKind::Send => self.send_waiters.remove(address),
        };
        if let Some(waiters) = waiters {
            for task in waiters {
                self.enqueue_wake(task);
            }
        }
    }

    fn apply_interests(&mut self, task: TaskId, interests: Vec<NetInterest>) {
        for interest in interests {
            let waiters = match interest.kind {
                NetInterestKind::Accept => self.accept_waiters.entry(interest.address).or_default(),
                NetInterestKind::Recv => self.recv_waiters.entry(interest.address).or_default(),
                NetInterestKind::Send => self.send_waiters.entry(interest.address).or_default(),
            };
            if !waiters.iter().any(|queued| *queued == task) {
                waiters.push_back(task);
            }
        }
    }

    fn purge_task_from_waiters(&mut self, task: TaskId) {
        purge_from_registry(&mut self.accept_waiters, task);
        purge_from_registry(&mut self.recv_waiters, task);
        purge_from_registry(&mut self.send_waiters, task);
    }
}

impl<'ctx> Executor<'ctx> {
    fn poll_main_pending<F: Future>(
        &mut self,
        mut future: Pin<&mut F>,
        waker: &Waker,
        output: &mut Option<F::Output>,
    ) -> Result<(), RuntimeError> {
        let task = self.main_task;
        self.purge_task_from_waiters(task);
        let mut scope = PollScope::new(self, task);
        let task_context_guard = TaskContextGuard::new(
            Arc::clone(&self.current_poll),
            Arc::clone(&self.self_wake),
            task,
        );
        let _scope_guard = ScopeGuard::install(&mut scope)?;
        let mut cx = TaskContext::from_waker(waker);
        let poll = future.as_mut().poll(&mut cx);
        drop(_scope_guard);
        drop(task_context_guard);
        match poll {
            Poll::Ready(value) => {
                *output = Some(value);
                self.context.task_complete(task)?;
                self.parked.remove(&task);
                self.queued.remove(&task);
                self.purge_task_from_waiters(task);
                Ok(())
            }
            Poll::Pending => self.apply_pending(task, scope.into_pending()),
        }
    }
}

fn purge_from_registry(registry: &mut BTreeMap<String, VecDeque<TaskId>>, task: TaskId) {
    registry.retain(|_, waiters| {
        waiters.retain(|queued| *queued != task);
        !waiters.is_empty()
    });
}

struct PendingDecision {
    deadline: Option<u64>,
    interests: Vec<NetInterest>,
    reason: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub(super) enum NetInterestKind {
    Accept,
    Recv,
    Send,
}

struct NetInterest {
    kind: NetInterestKind,
    address: String,
}

pub(super) struct PollScope {
    context: *mut Context,
    executor: *mut (),
    task: TaskId,
    park_deadline: Option<u64>,
    net_interest: Vec<NetInterest>,
    park_reason: Option<&'static str>,
}

impl PollScope {
    fn new(executor: &mut Executor<'_>, task: TaskId) -> Self {
        Self {
            context: executor.context as *mut Context,
            executor: executor as *mut Executor<'_> as *mut (),
            task,
            park_deadline: None,
            net_interest: Vec::new(),
            park_reason: None,
        }
    }

    fn into_pending(self) -> PendingDecision {
        PendingDecision {
            deadline: self.park_deadline,
            interests: self.net_interest,
            reason: self.park_reason,
        }
    }

    /// # Safety
    /// The pointer is valid only during one executor poll. `block_on` owns an
    /// exclusive `&mut Context` for its full extent, installs this scope on the
    /// same thread immediately before polling user code, and clears it before the
    /// executor resumes. No Patina async API may retain this reference.
    pub(super) unsafe fn context_mut(&mut self) -> &mut Context {
        unsafe { &mut *self.context }
    }

    /// # Safety
    /// The pointer is valid only while the executor is polling a future on this
    /// thread. APIs use it only for deterministic executor bookkeeping and never
    /// retain the reference beyond the current call.
    pub(super) unsafe fn executor_mut(&mut self) -> &mut Executor<'static> {
        unsafe { &mut *(self.executor as *mut Executor<'static>) }
    }

    pub(super) fn register_deadline(&mut self, deadline: u64, reason: &'static str) {
        self.park_deadline = Some(self.park_deadline.map_or(deadline, |old| old.min(deadline)));
        self.set_reason(reason);
    }

    pub(super) fn register_interest(
        &mut self,
        kind: NetInterestKind,
        address: impl Into<String>,
        reason: &'static str,
    ) {
        self.net_interest.push(NetInterest {
            kind,
            address: address.into(),
        });
        self.set_reason(reason);
    }

    fn set_reason(&mut self, reason: &'static str) {
        if self.park_reason.is_none() {
            self.park_reason = Some(reason);
        }
    }
}

struct ScopeGuard;

impl ScopeGuard {
    fn install(scope: &mut PollScope) -> Result<Self, RuntimeError> {
        let ptr = NonNull::from(scope);
        let occupied = SCOPE.with(|slot| {
            let occupied = slot.get().is_some();
            if !occupied {
                slot.set(Some(ptr));
            }
            occupied
        });
        if occupied {
            return Err(invalid_state(
                "nested patina_dst_async poll scope is not supported",
            ));
        }
        Ok(Self)
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        SCOPE.with(|slot| slot.set(None));
    }
}

struct TaskContextGuard {
    current_poll: Arc<Mutex<Option<TaskId>>>,
}

impl TaskContextGuard {
    fn new(
        current_poll: Arc<Mutex<Option<TaskId>>>,
        self_wake: Arc<AtomicBool>,
        task: TaskId,
    ) -> Self {
        self_wake.store(false, Ordering::SeqCst);
        *current_poll.lock().expect("current task mutex poisoned") = Some(task);
        Self { current_poll }
    }
}

impl Drop for TaskContextGuard {
    fn drop(&mut self) {
        *self
            .current_poll
            .lock()
            .expect("current task mutex poisoned") = None;
    }
}

struct WakeHandle {
    task: TaskId,
    queue: Arc<Mutex<VecDeque<TaskId>>>,
    queued: Arc<AtomicBool>,
    current_poll: Arc<Mutex<Option<TaskId>>>,
    self_wake: Arc<AtomicBool>,
}

impl WakeHandle {
    fn wake_task(&self) {
        let current = *self
            .current_poll
            .lock()
            .expect("current task mutex poisoned");
        if current == Some(self.task) {
            self.self_wake.store(true, Ordering::SeqCst);
            return;
        }
        if !self.queued.swap(true, Ordering::SeqCst) {
            self.queue
                .lock()
                .expect("wake queue mutex poisoned")
                .push_back(self.task);
        }
    }
}

impl Wake for WakeHandle {
    fn wake(self: Arc<Self>) {
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task();
    }
}

pub(super) fn with_scope<T>(
    operation: impl FnOnce(&mut PollScope) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    SCOPE.with(|slot| {
        let Some(mut ptr) = slot.get() else {
            return Err(invalid_state(
                "patina-dst-async future polled outside patina_dst_async::block_on",
            ));
        };
        // SAFETY: SCOPE contains a pointer to the stack-local PollScope installed
        // for the duration of this single poll and cleared by ScopeGuard.
        unsafe { operation(ptr.as_mut()) }
    })
}

pub(super) fn invalid_state(message: impl Into<String>) -> RuntimeError {
    EffectError::new(ErrorCode::InvalidState, message).into()
}

/// Future returned by [`yield_now`].
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Join handle returned by [`spawn`]. Dropping it detaches the task.
pub struct JoinHandle<T> {
    task: TaskId,
    slot: Rc<RefCell<Option<T>>>,
    completed: Rc<Cell<bool>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if let Some(value) = self.slot.borrow_mut().take() {
            return Poll::Ready(Ok(value));
        }
        if self.completed.get() {
            return Poll::Ready(Err(invalid_state(format!(
                "async task {} completed without a join value",
                self.task.0
            ))));
        }
        let result = with_scope(|scope| {
            let waiter = scope.task;
            scope.set_reason(REASON_JOIN_WAIT);
            // SAFETY: the executor pointer is valid for this poll.
            let executor = unsafe { scope.executor_mut() };
            let Some(entry) = executor.tasks.get_mut(&self.task) else {
                return Err(invalid_state(format!(
                    "joined async task {} is no longer live",
                    self.task.0
                )));
            };
            if !entry.joiners.iter().any(|task| *task == waiter) {
                entry.joiners.push_back(waiter);
            }
            Ok(())
        });
        match result {
            Ok(()) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests;
