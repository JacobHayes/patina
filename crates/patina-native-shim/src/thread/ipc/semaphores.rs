//! System V semaphore operations, waits, and undo state.

use super::*;

// ---------------------------------------------------------------- semaphores

/// `semget(2)`.
pub(crate) fn semget(key: i32, nsems: i32, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if !(0..=SEMMSL).contains(&nsems) {
        return fail(EINVAL);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.sem,
        key,
        flags,
        |set| {
            if (nsems as usize) > set.sems.len() {
                Err(EINVAL)
            } else {
                Ok(())
            }
        },
        || {
            if nsems == 0 {
                return Err(EINVAL);
            }
            Ok(SemSet {
                sems: vec![(0, 0); nsems as usize],
                adjust: vec![0; nsems as usize],
                undo: false,
                otime: 0,
                ctime: now(),
                pending: WaitQueue::new(),
            })
        },
    );
    answer(result)
}

/// Why an operation vector did not complete.
pub(super) enum Refused {
    /// Operation `index` has to wait.
    Block(usize),
    /// `-errno`: `EAGAIN` for `IPC_NOWAIT`, `ERANGE` past a limit.
    Errno(c_int),
}

/// `perform_atomic_semop_slow`: apply `ops` in order, all or none.
pub(super) fn perform(set: &mut SemSet, ops: &[Sembuf]) -> Result<(), Refused> {
    let mut values: Vec<i32> = set.sems.iter().map(|(value, _)| *value).collect();
    let mut adjust = set.adjust.clone();
    for (index, op) in ops.iter().enumerate() {
        let num = op.num as usize;
        let current = values[num];
        if op.op == 0 && current != 0 {
            return Err(if op.flg & IPC_NOWAIT as i16 != 0 {
                Refused::Errno(EAGAIN)
            } else {
                Refused::Block(index)
            });
        }
        let result = current + i32::from(op.op);
        if result < 0 {
            return Err(if op.flg & IPC_NOWAIT as i16 != 0 {
                Refused::Errno(EAGAIN)
            } else {
                Refused::Block(index)
            });
        }
        if result > SEMVMX {
            return Err(Refused::Errno(ERANGE));
        }
        if op.flg & SEM_UNDO != 0 {
            let undo = adjust[num] - i32::from(op.op);
            if !(-SEMAEM - 1..=SEMAEM).contains(&undo) {
                return Err(Refused::Errno(ERANGE));
            }
            adjust[num] = undo;
        }
        values[num] = result;
    }
    for op in ops {
        set.sems[op.num as usize] = (values[op.num as usize], PID);
    }
    set.adjust = adjust;
    Ok(())
}

/// `update_queue`: complete every blocked operation the values now allow,
/// oldest first, rescanning after one that altered them. Answers the tasks to
/// wake.
pub(super) fn update_queue(
    set: &mut SemSet,
    outcomes: &mut BTreeMap<TaskId, Outcome>,
) -> Vec<TaskId> {
    let mut woken = Vec::new();
    let mut index = 0;
    while index < set.pending.len() {
        let ops = set.pending[index].ops.clone();
        match perform(set, &ops) {
            Ok(()) => {
                let waiter = set.pending.remove(index).expect("indexed above");
                outcomes.insert(waiter.task, Outcome::Done(0));
                woken.push(waiter.task);
                set.otime = now();
                if waiter.alter {
                    index = 0;
                    continue;
                }
            }
            Err(Refused::Block(blocking)) => {
                set.pending
                    .iter_mut()
                    .nth(index)
                    .expect("a pending waiter")
                    .blocking = blocking;
                index += 1;
            }
            Err(Refused::Errno(errno)) => {
                let waiter = set.pending.remove(index).expect("indexed above");
                outcomes.insert(waiter.task, Outcome::Done(fail(errno)));
                woken.push(waiter.task);
            }
        }
    }
    woken
}

/// `semop(2)`/`semtimedop(2)`, `timeout` relative, in 6.8's order: the
/// timeout is copied in (`ksys_semtimedop`: `EFAULT`); then too many
/// operations are `E2BIG` and none `EINVAL`; the operations are copied in
/// (`EFAULT`); then a negative id or an invalid timeout is `EINVAL`
/// (`__do_semtimedop`).
pub(crate) fn semtimedop(
    id: i32,
    sops: *const Sembuf,
    nsops: usize,
    timeout: *const signals::Timespec,
) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let timeout = if timeout.is_null() {
        None
    } else {
        match crate::uaccess::read::<signals::Timespec>(timeout as usize) {
            Ok(timeout) => Some(timeout),
            Err(_) => return fail(EFAULT),
        }
    };
    if nsops > SEMOPM {
        return fail(E2BIG);
    }
    if nsops < 1 {
        return fail(EINVAL);
    }
    let Ok(ops) = crate::uaccess::read_vec::<Sembuf>(sops as usize, nsops) else {
        return fail(EFAULT);
    };
    if id < 0 {
        return fail(EINVAL);
    }
    let relative = match timeout {
        None => None,
        Some(timeout) if timeout.sec < 0 || !(0..1_000_000_000).contains(&timeout.nsec) => {
            return fail(EINVAL);
        }
        Some(timeout) => Some(
            (timeout.sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(timeout.nsec as u64),
        ),
    };
    let max = ops.iter().map(|op| op.num).max().unwrap_or(0) as usize;
    let alter = ops.iter().any(|op| op.op != 0);
    let undos = ops.iter().any(|op| op.flg & SEM_UNDO != 0);
    let me = current_task();
    let mut deadline = None;
    loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(c_int::from(error.into_posix()));
        }
        let Ipc { sem, outcomes, .. } = &mut state.ipc;
        let (perm, set) = match sem.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if undos {
            set.undo = true;
        }
        if max >= set.sems.len() {
            return fail(EFBIG);
        }
        if !perm.allows(if alter { S_IWUGO } else { S_IRUGO }) {
            return fail(EACCES);
        }
        let blocking = match perform(set, &ops) {
            Ok(()) => {
                set.otime = now();
                let woken = if alter {
                    update_queue(set, outcomes)
                } else {
                    Vec::new()
                };
                drop(state);
                wake_all(woken);
                return 0;
            }
            Err(Refused::Errno(errno)) => return fail(errno),
            Err(Refused::Block(blocking)) => blocking,
        };
        let mut wait = Wait::new(BlockClass::Ipc, vec![]);
        let waiter = SemWaiter {
            task: me,
            ops: ops.clone(),
            blocking,
            alter,
        };
        wait.enqueue(&mut set.pending, waiter, WaiterLoc::Ipc(IpcWait::Sem(id)));
        let timed = match (relative, deadline) {
            (None, _) => None,
            (Some(_), Some(at)) => Some((ClockKind::Monotonic, at)),
            (Some(relative), None) => {
                match with_context_raw(|context| context.now(ClockKind::Monotonic)) {
                    Ok(now) => Some((
                        ClockKind::Monotonic,
                        *deadline.insert(now.saturating_add(relative)),
                    )),
                    Err(errno) => return fail(errno),
                }
            }
        };
        let loc = IpcWait::Sem(id);
        match wait_on(state, me, "semop", wait, loc, timed, EAGAIN) {
            Ok(Some(Outcome::Done(result))) => return result,
            Ok(_) => {}
            Err(result) => return result,
        }
    }
}

/// `exit_sem` for a process whose only thread drops its undo list
/// (`unshare(CLONE_SYSVSEM)`): each set it holds an undo entry for gets the
/// adjustments applied — a semaphore kept within `0..=SEMVMX`, its last
/// process the caller where one moved it — and the entry dropped; then the
/// set's waiters are rescanned and its `sem_otime` moves (`do_smart_update`
/// with `otime` forced).
pub(crate) fn exit_sem() {
    let mut state = lock_state();
    let Ipc { sem, outcomes, .. } = &mut state.ipc;
    let mut woken = Vec::new();
    for (_, set) in sem.objects.values_mut() {
        if !set.undo {
            continue;
        }
        set.undo = false;
        for (slot, adjust) in set.sems.iter_mut().zip(set.adjust.iter_mut()) {
            if *adjust != 0 {
                *slot = ((slot.0 + *adjust).clamp(0, SEMVMX), PID);
                *adjust = 0;
            }
        }
        woken.extend(update_queue(set, outcomes));
        set.otime = now();
    }
    drop(state);
    wake_all(woken);
}

/// `semctl(2)`; `arg` is the fourth argument's register (`union semun`).
///
/// # Safety
/// For `IPC_STAT`/`IPC_SET`/`GETALL`/`SETALL`, `arg` must point to the
/// command's buffer.
pub(crate) unsafe fn semctl(id: i32, num: i32, cmd: i32, arg: usize) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | SEM_INFO | SEM_STAT | SEM_STAT_ANY => i64::from(crate::deny(DENY_TABLES)),
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, set) = match state.ipc.sem.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                sem_stat(perm, set)
            };
            let buf = arg as *mut SemidDs;
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        GETALL | GETVAL | GETPID | GETNCNT | GETZCNT | SETALL => {
            // SAFETY: forwarded from this function's contract.
            unsafe { sem_values(id, num, cmd, arg) }
        }
        SETVAL => {
            let value = arg as i32;
            if !(0..=SEMVMX).contains(&value) {
                return fail(ERANGE);
            }
            let mut state = lock_state();
            let Ipc { sem, outcomes, .. } = &mut state.ipc;
            let (perm, set) = match sem.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            if num < 0 || num as usize >= set.sems.len() {
                return fail(EINVAL);
            }
            if !perm.allows(S_IWUGO) {
                return fail(EACCES);
            }
            set.sems[num as usize] = (value, PID);
            set.adjust[num as usize] = 0;
            set.ctime = now();
            let woken = update_queue(set, outcomes);
            drop(state);
            wake_all(woken);
            0
        }
        IPC_SET | IPC_RMID => {
            let from = if cmd == IPC_SET {
                let buf = arg as *const SemidDs;
                if buf.is_null() {
                    return fail(EFAULT);
                }
                // SAFETY: per this function's contract.
                Some(unsafe { (*buf).perm })
            } else {
                None
            };
            let mut state = lock_state();
            match from {
                Some(from) => {
                    let (perm, set) = match state.ipc.sem.get_mut(id) {
                        Ok(found) => found,
                        Err(errno) => return fail(errno),
                    };
                    if let Err(errno) = perm.update(&from) {
                        return fail(errno);
                    }
                    set.ctime = now();
                    0
                }
                None => {
                    // `freeary`: every waiter wakes with EIDRM.
                    let Some((_, set)) = state.ipc.sem.remove(id) else {
                        return fail(EINVAL);
                    };
                    let woken = set.pending.iter().map(|waiter| waiter.task).collect();
                    removed(state, woken)
                }
            }
        }
        _ => fail(EINVAL),
    }
}

fn sem_stat(perm: &Perm, set: &SemSet) -> SemidDs {
    #[cfg(target_arch = "x86_64")]
    {
        SemidDs {
            perm: perm.stat(),
            otime: set.otime,
            otime_pad: 0,
            ctime: set.ctime,
            ctime_pad: 0,
            nsems: set.sems.len() as u64,
            unused: [0; 2],
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        SemidDs {
            perm: perm.stat(),
            otime: set.otime,
            ctime: set.ctime,
            nsems: set.sems.len() as u64,
            unused: [0; 2],
        }
    }
}

/// `semctl_main`: the value commands.
///
/// # Safety
/// For `GETALL`/`SETALL`, `arg` must point to one `u16` per semaphore.
unsafe fn sem_values(id: i32, num: i32, cmd: i32, arg: usize) -> i64 {
    let mut state = lock_state();
    let Ipc { sem, outcomes, .. } = &mut state.ipc;
    let (perm, set) = match sem.get_mut(id) {
        Ok(found) => found,
        Err(errno) => return fail(errno),
    };
    if !perm.allows(if cmd == SETALL { S_IWUGO } else { S_IRUGO }) {
        return fail(EACCES);
    }
    let count = set.sems.len();
    match cmd {
        GETALL => {
            let out = arg as *mut u16;
            if out.is_null() {
                return fail(EFAULT);
            }
            for (index, (value, _)) in set.sems.iter().enumerate() {
                // SAFETY: per this function's contract.
                unsafe { out.add(index).write(*value as u16) };
            }
            return 0;
        }
        SETALL => {
            let from = arg as *const u16;
            if from.is_null() {
                return fail(EFAULT);
            }
            // SAFETY: per this function's contract.
            let values: Vec<u16> = unsafe { std::slice::from_raw_parts(from, count) }.to_vec();
            if values.iter().any(|value| i32::from(*value) > SEMVMX) {
                return fail(ERANGE);
            }
            for (slot, value) in set.sems.iter_mut().zip(values) {
                *slot = (i32::from(value), PID);
            }
            set.adjust.iter_mut().for_each(|adjust| *adjust = 0);
            set.ctime = now();
            let woken = update_queue(set, outcomes);
            drop(state);
            wake_all(woken);
            return 0;
        }
        _ => {}
    }
    if num < 0 || num as usize >= count {
        return fail(EINVAL);
    }
    let num = num as usize;
    let counted = |zero: bool| {
        set.pending
            .iter()
            .filter(|waiter| {
                let op = waiter.ops[waiter.blocking];
                op.num as usize == num && if zero { op.op == 0 } else { op.op < 0 }
            })
            .count() as i64
    };
    match cmd {
        GETVAL => i64::from(set.sems[num].0),
        GETPID => i64::from(set.sems[num].1),
        GETNCNT => counted(false),
        GETZCNT => counted(true),
        _ => unreachable!("the value commands are matched above"),
    }
}
