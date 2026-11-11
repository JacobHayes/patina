//! Pipes the machine's processes share.
//!
//! A pipe end a child is handed at its spawn stays the root's description:
//! the hub holds a reference on it for each child that holds it (dropped
//! when the child closes it or ends, however it ends), and the child's end
//! is a remote one (`crate::thread::RemoteEnd`) whose every transfer is a
//! request here. The root's pipe model serves it: a transfer that cannot go
//! now notes the child's interest on the channel, and the channel's next
//! change wakes the child's foreign task. Each answer says whether the
//! request woke a task elsewhere (the child's view of the rest of the
//! machine becomes runnable) or one of the child's own (it wakes its remote
//! waiters to look again).

use super::*;
use crate::thread::{RemoteAnswer, RemoteOp};

const READ: u8 = 0;
const WRITE: u8 = 1;
const POLL: u8 = 2;
const WATCH: u8 = 3;
const CLOSE: u8 = 4;

/// A request's header: the operation, whether it may wait, the root's
/// description, and the operation's argument; a write's bytes follow.
const HEADER: usize = 24;
/// An answer's header: the result, what it woke, the two arrival
/// sequences; a read's bytes follow.
const ANSWER: usize = 32;

const WOKE_ELSEWHERE: u64 = 1;
const WOKE_SELF: u64 = 2;

/// The references each child holds on the root's descriptions, by (pid,
/// description): each is one hidden reference in the root's table.
static REFS: SpinMutex<BTreeMap<(i32, u64), usize>> = SpinMutex::new(BTreeMap::new());

/// The child the hub serves a pipe request for now (0 for none).
static SERVING: AtomicI32 = AtomicI32::new(0);
/// What the request being served woke: a task of the root or another
/// child, or the child's own interest.
static WOKE_OTHER: AtomicBool = AtomicBool::new(false);
static WOKE_ITSELF: AtomicBool = AtomicBool::new(false);

/// A child's answer, decoded.
struct Answer {
    result: i64,
    bytes: Vec<u8>,
    seqs: (u64, u64),
}

/// Ask the hub for `op` on the root's description `id`.
fn request(op: u8, id: u64, arg: u64, block: bool, bytes: &[u8]) -> Answer {
    let mut payload = Vec::with_capacity(HEADER + bytes.len());
    payload.extend_from_slice(&[op, u8::from(block), 0, 0, 0, 0, 0, 0]);
    payload.extend_from_slice(&id.to_le_bytes());
    payload.extend_from_slice(&arg.to_le_bytes());
    payload.extend_from_slice(bytes);
    send_frame(
        channel(),
        Message::Pipe {
            len: payload.len() as u64,
        },
        &payload,
    );
    let len = match receive(channel()) {
        Some(Message::PipeReply { len }) => len,
        Some(other) => protocol_fatal("a pipe answer", &other),
        None => orphaned(),
    };
    let reply = receive_payload(channel(), len).unwrap_or_else(|| orphaned());
    if reply.len() < ANSWER {
        protocol_fatal_text("a short pipe answer");
    }
    let word = |at: usize| u64::from_le_bytes(reply[at..at + 8].try_into().unwrap_or([0; 8]));
    let woke = word(8);
    if woke & WOKE_ELSEWHERE != 0 {
        // A task of another process can run now: the next pick of the rest
        // of the machine asks the hub.
        context(|context| context.task_foreign(ELSEWHERE, ForeignState::Runnable));
    }
    if woke & WOKE_SELF != 0 {
        thread::wake_remote_waiters();
    }
    Answer {
        result: word(0) as i64,
        seqs: (word(16), word(24)),
        bytes: reply[ANSWER..].to_vec(),
    }
}

/// A child's read of up to `max` bytes: the bytes (none at end of file), or
/// an errno (`EAGAIN` when none are there yet; with `block`, the hub noted
/// the interest).
pub(crate) fn read(id: u64, max: usize, block: bool) -> Result<Vec<u8>, c_int> {
    let answer = request(READ, id, max as u64, block, &[]);
    if answer.result < 0 {
        return Err((-answer.result) as c_int);
    }
    Ok(answer.bytes)
}

/// A child's write of `bytes`: how many went in, or an errno (`EPIPE`, or
/// `EAGAIN` with the interest noted under `block`).
pub(crate) fn write(id: u64, bytes: &[u8], block: bool) -> Result<usize, c_int> {
    let answer = request(WRITE, id, 0, block, bytes);
    if answer.result < 0 {
        return Err((-answer.result) as c_int);
    }
    Ok(answer.result as usize)
}

/// A child's readiness of its end: `poll`'s mask and the arrival sequences.
pub(crate) fn poll(id: u64) -> (u32, (u64, u64)) {
    let answer = request(POLL, id, 0, false, &[]);
    (answer.result.max(0) as u32, answer.seqs)
}

/// A child parks on its end's readiness: the hub notes its interest.
pub(crate) fn watch(id: u64) {
    request(WATCH, id, 0, false, &[]);
}

/// A child's last reference to its end is gone.
pub(crate) fn close(id: u64) {
    request(CLOSE, id, 0, false, &[]);
}

/// Child `pid` holds the root's description `desc` from its spawn on.
pub(super) fn retain(pid: i32, desc: u64) {
    if crate::state::fd_table().lock().retain(desc).is_err() {
        protocol_fatal_text("a description a spawn hands over is gone");
    }
    *REFS.lock().entry((pid, desc)).or_default() += 1;
}

/// Drop one of child `pid`'s references to `desc`; the last reference of
/// all frees the root's pipe end, as a close does.
fn release(pid: i32, desc: u64) {
    {
        let mut refs = REFS.lock();
        match refs.get_mut(&(pid, desc)) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                refs.remove(&(pid, desc));
            }
            None => return,
        }
    }
    let released = crate::state::fd_table().lock().release(desc);
    if let Ok(Some(release)) = released {
        let _ = crate::state::release_description(release);
    }
}

/// Child `pid` ended: every description it held is released (its last
/// writer gone, a reader sees end of file; its last reader gone, a writer
/// sees `EPIPE`), and it waits for no channel any more.
pub(super) fn release_all(pid: i32) {
    let held: Vec<(u64, usize)> = REFS
        .lock()
        .iter()
        .filter(|((owner, _), _)| *owner == pid)
        .map(|((_, desc), count)| (*desc, *count))
        .collect();
    thread::forget_remote(pid);
    for (desc, count) in held {
        for _ in 0..count {
            release(pid, desc);
        }
    }
}

/// Something of the root's woke a task: of the root itself, or (`task`
/// foreign) of child process `task` stands for.
pub(crate) fn woke(task: Option<TaskId>) {
    let Some(task) = task else {
        WOKE_OTHER.store(true, Ordering::Relaxed);
        return;
    };
    let pid = (task.0 - FOREIGN_BASE) as i32;
    if pid == SERVING.load(Ordering::Relaxed) {
        WOKE_ITSELF.store(true, Ordering::Relaxed);
        return;
    }
    let live = CHILDREN
        .lock()
        .get(&pid)
        .is_some_and(|child| child.ready && child.status.is_none());
    if live {
        WOKE_OTHER.store(true, Ordering::Relaxed);
        let _ = crate::with_context_raw(|context| {
            context.task_foreign(foreign_task(pid), ForeignState::Runnable)
        });
    }
}

/// Serve child `pid`'s pipe request `payload`; the answer's bytes.
pub(super) fn serve(pid: i32, payload: &[u8]) -> Vec<u8> {
    if payload.len() < HEADER {
        protocol_fatal_text("a short pipe request");
    }
    let word = |at: usize| u64::from_le_bytes(payload[at..at + 8].try_into().unwrap_or([0; 8]));
    let (op, block, id, arg) = (payload[0], payload[1] != 0, word(8), word(16));
    SERVING.store(pid, Ordering::Relaxed);
    WOKE_OTHER.store(false, Ordering::Relaxed);
    WOKE_ITSELF.store(false, Ordering::Relaxed);
    let held = REFS.lock().contains_key(&(pid, id));
    let handle = held
        .then(|| crate::state::fd_table().lock().description(id).copied())
        .flatten()
        .filter(|description| description.kind == crate::fdtable::FdKind::Pipe)
        .map(|description| description.handle);
    let answer = match (op, handle) {
        (_, None) => RemoteAnswer {
            result: -i64::from(libc::EBADF),
            bytes: Vec::new(),
            seqs: (0, 0),
        },
        (CLOSE, Some(_)) => {
            release(pid, id);
            RemoteAnswer {
                result: 0,
                bytes: Vec::new(),
                seqs: (0, 0),
            }
        }
        (op, Some(handle)) => {
            let op = match op {
                READ => RemoteOp::Read(arg.min(1 << 20) as usize),
                WRITE => RemoteOp::Write(&payload[HEADER..]),
                POLL => RemoteOp::Poll,
                WATCH => RemoteOp::Watch,
                other => protocol_fatal_text(&format!("an unknown pipe request {other}")),
            };
            thread::serve_remote(handle, pid, op, block)
        }
    };
    SERVING.store(0, Ordering::Relaxed);
    let mut woke = 0;
    if WOKE_OTHER.swap(false, Ordering::Relaxed) {
        woke |= WOKE_ELSEWHERE;
    }
    if WOKE_ITSELF.swap(false, Ordering::Relaxed) {
        woke |= WOKE_SELF;
    }
    let mut reply = Vec::with_capacity(ANSWER + answer.bytes.len());
    for word in [answer.result as u64, woke, answer.seqs.0, answer.seqs.1] {
        reply.extend_from_slice(&word.to_le_bytes());
    }
    reply.extend_from_slice(&answer.bytes);
    reply
}
