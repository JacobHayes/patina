//! Queues of parked tasks whose only way in is a wait's registration.
//!
//! Every queue a task can wait on (futex words, pthread objects, pipes,
//! sockets, descriptor readers, kqueues, IPC objects, record locks, dispatch
//! semaphores) is a [`WaitQueue`]. Its storage cannot be pushed to from
//! outside this module: [`Wait::enqueue`] queues an entry and records the
//! queue's [`WaiterLoc`] in the same wait, which `block`/`block_timed` then
//! register. So `ThreadRuntime::remove_wait` (a wake, a resume, a timer
//! expiry, thread exit) always knows every queue a task is on, and no queue
//! can keep an entry for a task whose wait has ended.

use super::*;
use crate::hostcoll::HostDeque;
use std::ops::Deref;

/// The storage a [`WaitQueue`] is built on.
pub(super) trait Storage: Default {
    type Item;
    fn push(&mut self, item: Self::Item);
}

impl<T> Storage for VecDeque<T> {
    type Item = T;
    fn push(&mut self, item: T) {
        self.push_back(item);
    }
}

impl<T> Storage for HostDeque<T> {
    type Item = T;
    fn push(&mut self, item: T) {
        self.push_back(item);
    }
}

/// A slot that holds at most one waiter (a thread's joiner).
impl<T> Storage for Option<T> {
    type Item = T;
    fn push(&mut self, item: T) {
        debug_assert!(self.is_none(), "a wait slot holds one waiter");
        *self = Some(item);
    }
}

impl<T> Storage for Vec<T> {
    type Item = T;
    fn push(&mut self, item: T) {
        Vec::push(self, item);
    }
}

/// A queue of parked tasks. Reads go through `Deref`; removal and in-place
/// edits through the methods below; insertion only through
/// [`Wait::enqueue`] (or, for an entry whose registration already names this
/// queue, [`WaitQueue::requeue`]).
#[derive(Clone, Debug, Default)]
pub(super) struct WaitQueue<S>(S);

impl<S> Deref for WaitQueue<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.0
    }
}

/// Why an entry may join a queue without a new location in its wait.
#[derive(Clone, Copy, Debug)]
pub(super) enum Covered {
    /// A signalled condition waiter moving to its mutex's queue: its
    /// `WaiterLoc::Cond(cond, mutex)` names that mutex queue too.
    CondMutex,
    /// A futex requeue, which relocated the waiter's `WaiterLoc::Futex` to
    /// the destination word first (Linux `futex2`).
    #[cfg(target_os = "linux")]
    Relocated,
}

impl<S: Storage> WaitQueue<S> {
    pub(super) fn new() -> Self {
        Self(S::default())
    }

    /// Queue an entry whose task's registration already names this queue.
    pub(super) fn requeue(&mut self, item: S::Item, covered: Covered) {
        let _ = covered;
        self.0.push(item);
    }

    /// The entries, leaving the queue empty (only a closing object drains).
    pub(super) fn take(&mut self) -> S {
        std::mem::take(&mut self.0)
    }
}

impl<T> WaitQueue<VecDeque<T>> {
    pub(super) fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    pub(super) fn remove(&mut self, index: usize) -> Option<T> {
        self.0.remove(index)
    }

    pub(super) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    #[cfg(target_os = "linux")]
    pub(super) fn iter_mut(&mut self) -> std::collections::vec_deque::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Every entry, in order, leaving the queue empty.
    pub(super) fn drain(&mut self) -> std::collections::vec_deque::Drain<'_, T> {
        self.0.drain(..)
    }
}

impl<T> WaitQueue<HostDeque<T>> {
    pub(super) fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    pub(super) fn remove(&mut self, index: usize) -> T {
        self.0.remove(index)
    }
}

impl<T> WaitQueue<Vec<T>> {
    pub(super) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    pub(super) fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }
}

impl Wait {
    /// Queue `item` on `queue` and record `loc`, the queue's location, in
    /// this wait: the registration that ends the entry with the wait. One
    /// location per entry, since unlinking a location removes one entry (a
    /// `futex_waitv` may queue twice on one word).
    pub(super) fn enqueue<S: Storage>(
        &mut self,
        queue: &mut WaitQueue<S>,
        item: S::Item,
        loc: WaiterLoc,
    ) {
        queue.0.push(item);
        self.locs.push(loc);
    }
}
