//! Deterministic single-threaded futures executor over Patina's explicit boundary.
//!
//! This crate controls futures that perform effects through the Patina [`Context`]
//! boundary. It does not interpose foreign async runtimes, host OS I/O, real
//! threads, or third-party futures that wait on non-Patina reactors.
//!
//! Leaf futures in this crate never park or wake scheduler tasks directly. They
//! perform existing recorded boundary operations, register interests/deadlines in
//! the current poll scope, and return `Pending`; the executor emits exactly one
//! recorded scheduling operation for each pending poll.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Wake, Waker};

use patina_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, SendReport, ShutdownHow, SocketId, TaskId,
};
use patina_runtime::{Context, RuntimeError};

const REASON_ASYNC_WAIT: &str = "async-wait";
const REASON_ASYNC_SLEEP: &str = "async-sleep";
const REASON_ASYNC_TIMEOUT: &str = "async-timeout";
const REASON_TCP_ACCEPT: &str = "tcp-accept";
const REASON_TCP_RECV: &str = "tcp-recv";
const REASON_TCP_SEND: &str = "tcp-send";
const REASON_NET_RECV: &str = "net-recv";
const REASON_JOIN_WAIT: &str = "join-wait";
const MAIN_LABEL: &str = "async-main";

thread_local! {
    static SCOPE: Cell<Option<NonNull<PollScope>>> = const { Cell::new(None) };
}

/// Run `future` to completion on a deterministic single-threaded executor.
pub fn block_on<F: Future>(context: &mut Context, future: F) -> Result<F::Output, RuntimeError> {
    if SCOPE.with(|scope| scope.get().is_some()) {
        return Err(invalid_state(
            "nested patina_async::block_on is not supported",
        ));
    }
    Executor::new(context)?.run(future)
}

/// Spawn a future onto the current Patina async executor.
///
/// This function must be called while a future is being polled by [`block_on`].
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

/// Sleep for a monotonic duration in nanoseconds.
pub fn sleep(duration_nanos: u64) -> Sleep {
    sleep_for(duration_nanos)
}

/// Sleep for a monotonic duration in nanoseconds.
pub fn sleep_for(duration_nanos: u64) -> Sleep {
    Sleep {
        kind: SleepKind::For(duration_nanos),
        deadline: None,
        reason: REASON_ASYNC_SLEEP,
    }
}

/// Sleep until an absolute deadline in the selected clock domain.
pub fn sleep_until(clock: ClockKind, deadline_nanos: u64) -> Sleep {
    Sleep {
        kind: SleepKind::Until(clock, deadline_nanos),
        deadline: None,
        reason: REASON_ASYNC_SLEEP,
    }
}

/// Run a future with a deterministic virtual-time timeout.
///
/// `Ok(None)` means the timeout elapsed before the inner future completed. If the
/// inner future and timeout are both ready in the same poll, the inner future wins.
pub fn timeout<F: Future>(duration_nanos: u64, future: F) -> Timeout<F> {
    Timeout {
        inner: Box::pin(future),
        sleep: Sleep {
            kind: SleepKind::For(duration_nanos),
            deadline: None,
            reason: REASON_ASYNC_TIMEOUT,
        },
    }
}

struct TaskEntry {
    future: Pin<Box<dyn Future<Output = ()>>>,
    waker: Waker,
    joiners: VecDeque<TaskId>,
}

struct Executor<'ctx> {
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
            self.drain_wake_queue()?;
            let selected = self.context.scheduler_next()?;
            // The deadlock rescue inside `scheduler_next` woke every timer-due
            // task (they are now Runnable in the scheduler and gone from the
            // runtime's parked set). Reconcile the executor's own shadow state
            // to match before the next drain/park decision, otherwise a rescued
            // task left in `self.parked` or a net-waiter registry could be woken
            // again — `task_wake` on an already-Runnable task fails closed.
            for rescued in self.context.take_rescued_timeouts() {
                self.parked.remove(&rescued);
                self.purge_task_from_waiters(rescued);
            }
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
        Ok(())
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

    fn wake_waiters(&mut self, kind: NetInterestKind, address: &str) {
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
enum NetInterestKind {
    Accept,
    Recv,
    Send,
}

struct NetInterest {
    kind: NetInterestKind,
    address: String,
}

struct PollScope {
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
    unsafe fn context_mut(&mut self) -> &mut Context {
        unsafe { &mut *self.context }
    }

    /// # Safety
    /// The pointer is valid only while the executor is polling a future on this
    /// thread. APIs use it only for deterministic executor bookkeeping and never
    /// retain the reference beyond the current call.
    unsafe fn executor_mut(&mut self) -> &mut Executor<'static> {
        unsafe { &mut *(self.executor as *mut Executor<'static>) }
    }

    fn register_deadline(&mut self, deadline: u64, reason: &'static str) {
        self.park_deadline = Some(self.park_deadline.map_or(deadline, |old| old.min(deadline)));
        self.set_reason(reason);
    }

    fn register_interest(
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
                "nested patina_async poll scope is not supported",
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

fn with_scope<T>(
    operation: impl FnOnce(&mut PollScope) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    SCOPE.with(|slot| {
        let Some(mut ptr) = slot.get() else {
            return Err(invalid_state(
                "patina-async future polled outside patina_async::block_on",
            ));
        };
        // SAFETY: SCOPE contains a pointer to the stack-local PollScope installed
        // for the duration of this single poll and cleared by ScopeGuard.
        unsafe { operation(ptr.as_mut()) }
    })
}

fn invalid_state(message: impl Into<String>) -> RuntimeError {
    EffectError::new(ErrorCode::InvalidState, message).into()
}

fn invalid_input(message: impl Into<String>) -> RuntimeError {
    EffectError::new(ErrorCode::InvalidInput, message).into()
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

enum SleepKind {
    For(u64),
    Until(ClockKind, u64),
}

/// Future returned by [`sleep`], [`sleep_for`], and [`sleep_until`].
pub struct Sleep {
    kind: SleepKind,
    deadline: Option<u64>,
    reason: &'static str,
}

impl Sleep {
    fn poll_sleep(self: Pin<&mut Self>) -> Poll<Result<(), RuntimeError>> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            let deadline = if let Some(deadline) = this.deadline {
                deadline
            } else {
                // SAFETY: the scope is live for this poll on the executor thread.
                let context = unsafe { scope.context_mut() };
                let resolved = match this.kind {
                    SleepKind::For(duration) => {
                        let now = context.now(ClockKind::Monotonic)?;
                        now.checked_add(duration)
                            .ok_or_else(|| invalid_input("monotonic sleep deadline overflowed"))?
                    }
                    SleepKind::Until(ClockKind::Monotonic, deadline) => deadline,
                    SleepKind::Until(ClockKind::Realtime, deadline) => {
                        let realtime = context.now(ClockKind::Realtime)?;
                        let monotonic = context.now(ClockKind::Monotonic)?;
                        let epoch = realtime.saturating_sub(monotonic);
                        deadline.saturating_sub(epoch)
                    }
                };
                this.deadline = Some(resolved);
                resolved
            };
            // SAFETY: the scope is live for this poll on the executor thread.
            let now = unsafe { scope.context_mut() }.now(ClockKind::Monotonic)?;
            if now >= deadline {
                Ok(true)
            } else {
                scope.register_deadline(deadline, this.reason);
                Ok(false)
            }
        });
        match result {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl Future for Sleep {
    type Output = Result<(), RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        self.poll_sleep()
    }
}

/// Future returned by [`timeout`].
pub struct Timeout<F: Future> {
    inner: Pin<Box<F>>,
    sleep: Sleep,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<Option<F::Output>, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(value) = self.inner.as_mut().poll(cx) {
            return Poll::Ready(Ok(Some(value)));
        }
        match Pin::new(&mut self.sleep).poll_sleep() {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
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

/// A deterministic virtual TCP listener.
///
/// Dropping a listener records no boundary operation. Use explicit protocol
/// shutdown on accepted streams when close semantics matter.
#[derive(Clone, Debug)]
pub struct TcpListener {
    socket: SocketId,
    address: String,
}

impl TcpListener {
    pub fn listen(address: &str, backlog: usize) -> ListenFuture {
        ListenFuture {
            address: address.into(),
            backlog,
            done: false,
        }
    }

    pub fn accept(&self) -> AcceptFuture {
        AcceptFuture {
            listener: self.socket,
            address: self.address.clone(),
        }
    }
}

pub struct ListenFuture {
    address: String,
    backlog: usize,
    done: bool,
}

impl Future for ListenFuture {
    type Output = Result<TcpListener, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpListener::listen polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket =
                unsafe { scope.context_mut() }.net_tcp_listen(&self.address, self.backlog)?;
            Ok(TcpListener {
                socket,
                address: self.address.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct AcceptFuture {
    listener: SocketId,
    address: String,
}

impl Future for AcceptFuture {
    type Output = Result<TcpStream, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_tcp_accept(this.listener)? {
                Some(accepted) => Ok(Some(TcpStream {
                    socket: accepted.socket,
                    local_addr: this.address.clone(),
                    peer_addr: accepted.peer,
                })),
                None => {
                    scope.register_interest(
                        NetInterestKind::Accept,
                        this.address.clone(),
                        REASON_TCP_ACCEPT,
                    );
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(stream)) => Poll::Ready(Ok(stream)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

/// A deterministic virtual TCP stream.
///
/// Dropping a stream records no boundary operation; call [`TcpStream::shutdown`]
/// when deterministic close/EOF behavior matters.
#[derive(Clone, Debug)]
pub struct TcpStream {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
}

impl TcpStream {
    pub fn connect(address: &str, to: &str) -> ConnectFuture {
        ConnectFuture {
            address: address.into(),
            to: to.into(),
            done: false,
        }
    }

    pub fn read(&self, max_len: usize) -> ReadFuture {
        ReadFuture {
            socket: self.socket,
            local_addr: self.local_addr.clone(),
            peer_addr: self.peer_addr.clone(),
            max_len,
        }
    }

    pub fn write_all<'a>(&self, bytes: &'a [u8]) -> WriteAllFuture<'a> {
        WriteAllFuture {
            socket: self.socket,
            local_addr: self.local_addr.clone(),
            peer_addr: self.peer_addr.clone(),
            bytes,
            offset: 0,
        }
    }

    pub fn shutdown(&self, how: ShutdownHow) -> ShutdownFuture {
        ShutdownFuture {
            socket: self.socket,
            peer_addr: self.peer_addr.clone(),
            how,
            done: false,
        }
    }
}

pub struct ConnectFuture {
    address: String,
    to: String,
    done: bool,
}

impl Future for ConnectFuture {
    type Output = Result<TcpStream, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpStream::connect polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket = unsafe { scope.context_mut() }.net_tcp_connect(&self.address, &self.to)?;
            // SAFETY: the executor pointer is valid for this poll.
            unsafe { scope.executor_mut() }.wake_waiters(NetInterestKind::Accept, &self.to);
            Ok(TcpStream {
                socket,
                local_addr: self.address.clone(),
                peer_addr: self.to.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct ReadFuture {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
    max_len: usize,
}

impl Future for ReadFuture {
    type Output = Result<Vec<u8>, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_tcp_recv(this.socket, this.max_len)? {
                Some(bytes) => {
                    if !bytes.is_empty() {
                        // SAFETY: the executor pointer is valid for this poll.
                        unsafe { scope.executor_mut() }
                            .wake_waiters(NetInterestKind::Send, &this.peer_addr);
                    }
                    Ok(Some(bytes))
                }
                None => {
                    scope.register_interest(
                        NetInterestKind::Recv,
                        this.local_addr.clone(),
                        REASON_TCP_RECV,
                    );
                    // SAFETY: the scope is live for this poll on the executor thread.
                    if let Some(deadline) =
                        unsafe { scope.context_mut() }.net_next_delivery(this.socket)?
                    {
                        scope.register_deadline(deadline, REASON_TCP_RECV);
                    }
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(bytes)) => Poll::Ready(Ok(bytes)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

pub struct WriteAllFuture<'a> {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
    bytes: &'a [u8],
    offset: usize,
}

impl Future for WriteAllFuture<'_> {
    type Output = Result<(), RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let result = with_scope(|scope| {
            while self.offset < self.bytes.len() {
                // SAFETY: the scope is live for this poll on the executor thread.
                let accepted = unsafe { scope.context_mut() }
                    .net_tcp_send(self.socket, &self.bytes[self.offset..])?;
                if accepted == 0 {
                    scope.register_interest(
                        NetInterestKind::Send,
                        self.local_addr.clone(),
                        REASON_TCP_SEND,
                    );
                    return Ok(false);
                }
                self.offset += accepted;
                // SAFETY: the executor pointer is valid for this poll.
                unsafe { scope.executor_mut() }
                    .wake_waiters(NetInterestKind::Recv, &self.peer_addr);
            }
            Ok(true)
        });
        match result {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

pub struct ShutdownFuture {
    socket: SocketId,
    peer_addr: String,
    how: ShutdownHow,
    done: bool,
}

impl Future for ShutdownFuture {
    type Output = Result<(), RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpStream::shutdown polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            unsafe { scope.context_mut() }.net_tcp_shutdown(self.socket, self.how)?;
            // SAFETY: the executor pointer is valid for this poll.
            let executor = unsafe { scope.executor_mut() };
            executor.wake_waiters(NetInterestKind::Recv, &self.peer_addr);
            executor.wake_waiters(NetInterestKind::Send, &self.peer_addr);
            Ok(())
        });
        Poll::Ready(result)
    }
}

/// A deterministic virtual UDP socket.
///
/// Dropping a socket records no boundary operation. Packets already sent remain
/// governed by the virtual network driver.
#[derive(Clone, Debug)]
pub struct UdpSocket {
    socket: SocketId,
    address: String,
}

impl UdpSocket {
    pub fn bind(address: &str) -> UdpBindFuture {
        UdpBindFuture {
            address: address.into(),
            done: false,
        }
    }

    pub fn send_to<'a>(&self, to: &str, bytes: &'a [u8]) -> UdpSendToFuture<'a> {
        UdpSendToFuture {
            socket: self.socket,
            to: to.into(),
            bytes,
            done: false,
        }
    }

    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            socket: self.socket,
            address: self.address.clone(),
        }
    }
}

pub struct UdpBindFuture {
    address: String,
    done: bool,
}

impl Future for UdpBindFuture {
    type Output = Result<UdpSocket, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "UdpSocket::bind polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket = unsafe { scope.context_mut() }.net_bind(&self.address)?;
            Ok(UdpSocket {
                socket,
                address: self.address.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct UdpSendToFuture<'a> {
    socket: SocketId,
    to: String,
    bytes: &'a [u8],
    done: bool,
}

impl Future for UdpSendToFuture<'_> {
    type Output = Result<SendReport, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "UdpSocket::send_to polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let report =
                unsafe { scope.context_mut() }.net_send(self.socket, &self.to, self.bytes)?;
            // SAFETY: the executor pointer is valid for this poll.
            unsafe { scope.executor_mut() }.wake_waiters(NetInterestKind::Recv, &self.to);
            Ok(report)
        });
        Poll::Ready(result)
    }
}

pub struct UdpRecvFuture {
    socket: SocketId,
    address: String,
}

impl Future for UdpRecvFuture {
    type Output = Result<Datagram, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_recv(this.socket)? {
                Some(datagram) => Ok(Some(datagram)),
                None => {
                    scope.register_interest(
                        NetInterestKind::Recv,
                        this.address.clone(),
                        REASON_NET_RECV,
                    );
                    // SAFETY: the scope is live for this poll on the executor thread.
                    if let Some(deadline) =
                        unsafe { scope.context_mut() }.net_next_delivery(this.socket)?
                    {
                        scope.register_deadline(deadline, REASON_NET_RECV);
                    }
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(datagram)) => Poll::Ready(Ok(datagram)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::task::{RawWaker, RawWakerVTable};

    use patina_net_sim::SimNet;
    use patina_runtime::{RuntimeBuilder, RuntimeConfig};
    use patina_wrapper_latency::LatencyNet;

    fn context(seed: u64) -> Context {
        Context::from_config(RuntimeConfig::seeded(seed)).unwrap()
    }

    fn assert_invalid_state(error: RuntimeError) {
        match error {
            RuntimeError::Effect(effect) => assert_eq!(effect.code, ErrorCode::InvalidState),
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, wake);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

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
    fn leaf_future_polled_outside_block_on_fails_closed() {
        let mut sleep = Box::pin(sleep_for(1));
        let waker = noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        let Poll::Ready(Err(error)) = sleep.as_mut().poll(&mut cx) else {
            panic!("sleep outside executor should fail");
        };
        assert_invalid_state(error);
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
    fn timers_rescue_at_exact_deadlines_and_timeout_ties() {
        let mut ctx = context(7);
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
                    200
                );
                b.await??;
                assert_eq!(
                    with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))
                        .unwrap(),
                    500
                );
                assert!(timeout(100, sleep_for(300)).await?.is_none());
                assert_eq!(
                    with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))
                        .unwrap(),
                    600
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

    async fn tcp_echo_scenario(
        order: Rc<RefCell<Vec<&'static str>>>,
    ) -> Result<Vec<u8>, RuntimeError> {
        let listener = TcpListener::listen("server", 8).await?;
        let server = spawn("server", {
            let order = Rc::clone(&order);
            async move {
                let stream = listener.accept().await?;
                order.borrow_mut().push("server-accepted");
                let bytes = stream.read(16).await?;
                order.borrow_mut().push("server-read");
                stream.write_all(&bytes).await?;
                Ok::<_, RuntimeError>(())
            }
        })?;
        let client = spawn("client", {
            let order = Rc::clone(&order);
            async move {
                let stream = TcpStream::connect("client", "server").await?;
                stream.write_all(b"hello").await?;
                order.borrow_mut().push("client-wrote");
                let echoed = stream.read(16).await?;
                Ok::<_, RuntimeError>(echoed)
            }
        })?;
        let echoed = client.await??;
        server.await??;
        Ok(echoed)
    }

    #[test]
    fn async_tcp_echo_over_simnet() {
        let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(8))
            .with_default_drivers()
            .with_network(SimNet::new())
            .build()
            .unwrap();
        let order = Rc::new(RefCell::new(Vec::new()));
        let echoed = block_on(&mut ctx, tcp_echo_scenario(Rc::clone(&order)))
            .unwrap()
            .unwrap();
        assert_eq!(echoed, b"hello");
        // The reader (server) is spawned before the writer and its `read` blocks
        // until the client's bytes arrive, so it must observe them only after the
        // client's write — a real park + peer-wake ordering, not just presence.
        let log = order.borrow();
        let wrote = log
            .iter()
            .position(|event| *event == "client-wrote")
            .expect("client recorded its write");
        let read = log
            .iter()
            .position(|event| *event == "server-read")
            .expect("server recorded its read");
        assert!(
            wrote < read,
            "server must observe the payload only after the client wrote it: {log:?}"
        );
        drop(log);
        ctx.finish().unwrap();
    }

    #[test]
    fn tcp_latency_uses_timed_net_delivery() {
        let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(9))
            .with_default_drivers()
            .with_network(LatencyNet::new(SimNet::new(), 1).latency_nanos(75))
            .build()
            .unwrap();
        block_on(&mut ctx, async {
            let listener = TcpListener::listen("server", 1).await?;
            let client = TcpStream::connect("client", "server").await?;
            let server = listener.accept().await?;
            client.write_all(b"x").await?;
            assert_eq!(server.read(8).await?, b"x");
            let now = with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))?;
            assert_eq!(now, 75);
            Ok::<_, RuntimeError>(())
        })
        .unwrap()
        .unwrap();
        ctx.finish().unwrap();
    }

    #[test]
    fn udp_echo_under_latency_advances_exactly_to_delivery() {
        let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(10))
            .with_default_drivers()
            .with_network(LatencyNet::new(SimNet::new(), 1).latency_nanos(50))
            .build()
            .unwrap();
        let payload = block_on(&mut ctx, async {
            let server = UdpSocket::bind("server").await?;
            let client = UdpSocket::bind("client").await?;
            let recv = spawn("udp-recv", async move {
                let datagram = server.recv().await?;
                let now =
                    with_scope(|scope| unsafe { scope.context_mut() }.now(ClockKind::Monotonic))?;
                assert_eq!(now, 50);
                assert_eq!(datagram.delivery_nanos, 50);
                Ok::<_, RuntimeError>(datagram.bytes)
            })?;
            yield_now().await;
            client.send_to("server", b"ping").await?;
            recv.await?
        })
        .unwrap()
        .unwrap();
        assert_eq!(payload, b"ping");
        ctx.finish().unwrap();
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
                        assert_eq!(now, 50);
                        assert_eq!(datagram.delivery_nanos, 50);
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
                        assert_eq!(now, 50);
                        assert_eq!(datagram.delivery_nanos, 50);
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

    #[test]
    fn tcp_backpressure_wakes_writer_when_reader_drains() {
        let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(11))
            .with_default_drivers()
            .with_network(SimNet::builder().tcp_buffer_bytes(4).build().unwrap())
            .build()
            .unwrap();
        let data: Vec<u8> = (0..12).collect();
        let received = block_on(&mut ctx, {
            let data = data.clone();
            async move {
                let listener = TcpListener::listen("server", 1).await?;
                let client = TcpStream::connect("client", "server").await?;
                let server = listener.accept().await?;
                let writer = spawn("writer", async move {
                    client.write_all(&data).await?;
                    Ok::<_, RuntimeError>(())
                })?;
                let mut out = Vec::new();
                while out.len() < 12 {
                    let chunk = server.read(3).await?;
                    out.extend_from_slice(&chunk);
                    yield_now().await;
                }
                writer.await??;
                Ok::<_, RuntimeError>(out)
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(received, (0..12).collect::<Vec<u8>>());
        ctx.finish().unwrap();
    }

    fn run_recorded_echo(config: RuntimeConfig) -> Result<Vec<u8>, RuntimeError> {
        let mut ctx = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_network(SimNet::new())
            .build()?;
        let result = block_on(
            &mut ctx,
            tcp_echo_scenario(Rc::new(RefCell::new(Vec::new()))),
        )?;
        let finish = ctx.finish();
        match (result, finish) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(run), Err(finalize)) => Err(RuntimeError::RunAndFinalize {
                run: Box::new(run),
                finalize: Box::new(finalize),
            }),
        }
    }

    #[test]
    fn record_replay_byte_identity_for_echo() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.patina");
        let second = dir.path().join("second.patina");
        assert_eq!(
            run_recorded_echo(RuntimeConfig::record(12, &first, "async-echo-v1")).unwrap(),
            b"hello"
        );
        assert_eq!(
            run_recorded_echo(RuntimeConfig::record(12, &second, "async-echo-v1")).unwrap(),
            b"hello"
        );
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        assert_eq!(
            run_recorded_echo(RuntimeConfig::replay(&first, "async-echo-v1")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn replay_rejects_divergent_echo_payload() {
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("trace.patina");
        run_recorded_echo(RuntimeConfig::record(13, &trace, "async-echo-v1")).unwrap();
        let mut ctx = RuntimeBuilder::new(RuntimeConfig::replay(&trace, "async-echo-v1"))
            .with_default_drivers()
            .with_network(SimNet::new())
            .build()
            .unwrap();
        let result = block_on(&mut ctx, async {
            let listener = TcpListener::listen("server", 8).await?;
            let server = spawn("server", async move {
                let stream = listener.accept().await?;
                let bytes = stream.read(16).await?;
                stream.write_all(&bytes).await?;
                Ok::<_, RuntimeError>(())
            })?;
            let client = spawn("client", async move {
                let stream = TcpStream::connect("client", "server").await?;
                stream.write_all(b"jello").await?;
                stream.read(16).await
            })?;
            let echoed = client.await??;
            server.await??;
            Ok::<_, RuntimeError>(echoed)
        });
        assert!(matches!(result, Err(RuntimeError::Trace(_))));
    }
}
