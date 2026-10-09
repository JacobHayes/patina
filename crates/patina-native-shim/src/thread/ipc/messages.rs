//! System V message-queue operations.

use super::*;

// ---------------------------------------------------------------- message queues

/// `msgget(2)`.
pub(crate) fn msgget(key: i32, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.msg,
        key,
        flags,
        |_| Ok(()),
        || {
            Ok(MsgQueue {
                messages: VecDeque::new(),
                cbytes: 0,
                qbytes: MSGMNB,
                stime: 0,
                rtime: 0,
                ctime: now(),
                lspid: 0,
                lrpid: 0,
                receivers: WaitQueue::new(),
                senders: WaitQueue::new(),
            })
        },
    );
    answer(result)
}

/// `msgsnd(2)`.
///
/// # Safety
/// `msgp` must be NULL or point to a `long` type followed by `size` bytes.
pub(crate) unsafe fn msgsnd(id: i32, msgp: *const u8, size: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    // The type is read before anything is judged.
    if msgp.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: per this function's contract.
    let mtype = unsafe { msgp.cast::<i64>().read_unaligned() };
    if size > MSGMAX || (size as isize) < 0 || id < 0 {
        return fail(EINVAL);
    }
    if mtype < 1 {
        return fail(EINVAL);
    }
    // SAFETY: per this function's contract.
    let text = unsafe { std::slice::from_raw_parts(msgp.add(8), size) }.to_vec();
    let me = current_task();
    let mut message = Some(Message { mtype, text });
    loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(c_int::from(error.into_posix()));
        }
        let Ipc { msg, outcomes, .. } = &mut state.ipc;
        let (perm, queue) = match msg.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(S_IWUGO) {
            return fail(EACCES);
        }
        if queue.fits(size) {
            queue.lspid = pid();
            queue.stime = now();
            let sent = message.take().expect("sent once");
            let woken = deliver_message(queue, outcomes, sent);
            drop(state);
            wake_all(woken);
            return 0;
        }
        if flags & IPC_NOWAIT != 0 {
            return fail(EAGAIN);
        }
        let loc = IpcWait::MsgSend(id);
        let mut wait = Wait::new(BlockClass::Ipc, vec![]);
        wait.enqueue(&mut queue.senders, me, WaiterLoc::Ipc(loc));
        match wait_on(state, me, "msgsnd", wait, loc, None, EAGAIN) {
            Ok(Some(Outcome::Done(result))) => return result,
            Ok(_) => {}
            Err(result) => return result,
        }
    }
}

/// `pipelined_send`, else enqueue: hand `message` to the first waiting
/// receiver it suits (one too small for it is woken with `E2BIG`), or append
/// it. Answers the tasks to wake.
fn deliver_message(
    queue: &mut MsgQueue,
    outcomes: &mut BTreeMap<TaskId, Outcome>,
    message: Message,
) -> Vec<TaskId> {
    let mut woken = Vec::new();
    let mut index = 0;
    while index < queue.receivers.len() {
        let receiver = &queue.receivers[index];
        if !receiver.mode.test(message.mtype, receiver.wanted) {
            index += 1;
            continue;
        }
        let receiver = queue.receivers.remove(index).expect("indexed above");
        woken.push(receiver.task);
        if receiver.max < message.text.len() {
            outcomes.insert(receiver.task, Outcome::Done(fail(E2BIG)));
            continue;
        }
        queue.lrpid = pid();
        queue.rtime = now();
        outcomes.insert(receiver.task, Outcome::Message(message));
        return woken;
    }
    queue.cbytes += message.text.len();
    queue.messages.push_back(message);
    woken
}

/// Wake every sender waiting for room (`ss_wakeup`): each re-judges.
fn wake_senders(queue: &mut MsgQueue) -> Vec<TaskId> {
    queue.senders.drain().collect()
}

/// `msgrcv(2)`: the text length, or `-errno`.
///
/// # Safety
/// `msgp` must be writable for a `long` type followed by `size` bytes.
pub(crate) unsafe fn msgrcv(id: i32, msgp: *mut u8, size: usize, mtype: i64, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 || (size as isize) < 0 {
        return fail(EINVAL);
    }
    if flags & MSG_COPY != 0 {
        if flags & MSG_EXCEPT != 0 || flags & IPC_NOWAIT == 0 {
            return fail(EINVAL);
        }
        // A kernel without CONFIG_CHECKPOINT_RESTORE.
        return fail(ENOSYS);
    }
    let (wanted, mode) = if mtype == 0 {
        (0, Search::Any)
    } else if mtype < 0 {
        (
            if mtype == i64::MIN { i64::MAX } else { -mtype },
            Search::LessEqual,
        )
    } else if flags & MSG_EXCEPT != 0 {
        (mtype, Search::NotEqual)
    } else {
        (mtype, Search::Equal)
    };
    let me = current_task();
    let message = loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(c_int::from(error.into_posix()));
        }
        let (perm, queue) = match state.ipc.msg.get_mut(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(S_IRUGO) {
            return fail(EACCES);
        }
        if let Some(index) = queue.find(wanted, mode) {
            if size < queue.messages[index].text.len() && flags & MSG_NOERROR == 0 {
                return fail(E2BIG);
            }
            let message = queue.messages.remove(index).expect("found above");
            queue.cbytes -= message.text.len();
            queue.rtime = now();
            queue.lrpid = pid();
            let woken = wake_senders(queue);
            drop(state);
            wake_all(woken);
            break message;
        }
        if flags & IPC_NOWAIT != 0 {
            return fail(ENOMSG);
        }
        let loc = IpcWait::MsgRecv(id);
        let mut wait = Wait::new(BlockClass::Ipc, vec![]);
        let receiver = Receiver {
            task: me,
            wanted,
            mode,
            max: if flags & MSG_NOERROR != 0 {
                i32::MAX as usize
            } else {
                size
            },
        };
        wait.enqueue(&mut queue.receivers, receiver, WaiterLoc::Ipc(loc));
        match wait_on(state, me, "msgrcv", wait, loc, None, EAGAIN) {
            Ok(Some(Outcome::Message(message))) => break message,
            Ok(Some(Outcome::Done(result))) | Err(result) => return result,
            Ok(None) => {}
        }
    };
    let copied = size.min(message.text.len());
    // SAFETY: per this function's contract.
    unsafe {
        msgp.cast::<i64>().write_unaligned(message.mtype);
        msgp.add(8)
            .copy_from_nonoverlapping(message.text.as_ptr(), copied);
    }
    copied as i64
}

/// `msgctl(2)`.
///
/// # Safety
/// `buf` must be NULL or valid for the command's `msqid_ds`.
pub(crate) unsafe fn msgctl(id: i32, cmd: i32, buf: *mut MsqidDs) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 || cmd < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | MSG_INFO | MSG_STAT | MSG_STAT_ANY => i64::from(crate::deny(DENY_TABLES)),
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, queue) = match state.ipc.msg.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                MsqidDs {
                    perm: perm.stat(),
                    stime: queue.stime,
                    rtime: queue.rtime,
                    ctime: queue.ctime,
                    cbytes: queue.cbytes as u64,
                    qnum: queue.messages.len() as u64,
                    qbytes: queue.qbytes as u64,
                    lspid: queue.lspid,
                    lrpid: queue.lrpid,
                    unused: [0; 2],
                }
            };
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        IPC_SET => {
            if buf.is_null() {
                return fail(EFAULT);
            }
            // SAFETY: per this function's contract.
            let (from, qbytes) = unsafe { ((*buf).perm, (*buf).qbytes) };
            let mut state = lock_state();
            let (perm, queue) = match state.ipc.msg.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            // Raising the limit past `msgmnb` needs CAP_SYS_RESOURCE.
            if qbytes > MSGMNB as u64 {
                return fail(EPERM);
            }
            if let Err(errno) = perm.update(&from) {
                return fail(errno);
            }
            queue.qbytes = qbytes as usize;
            queue.ctime = now();
            // Receivers re-judge the permissions, senders the room.
            let mut woken: Vec<TaskId> = queue.receivers.drain().map(|r| r.task).collect();
            woken.extend(wake_senders(queue));
            drop(state);
            wake_all(woken);
            0
        }
        IPC_RMID => {
            let mut state = lock_state();
            let Some((_, queue)) = state.ipc.msg.remove(id) else {
                return fail(EINVAL);
            };
            let woken = queue
                .receivers
                .iter()
                .map(|receiver| receiver.task)
                .chain(queue.senders.iter().copied())
                .collect();
            removed(state, woken)
        }
        _ => fail(EINVAL),
    }
}
