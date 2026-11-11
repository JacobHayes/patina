//! The hub-child channel's messages: one fixed-size record each, so a
//! message never allocates and a `SOCK_SEQPACKET` read is always one whole
//! message.

use patina_dst_abi::ForeignState;
use patina_dst_runtime::MachineCarry;

/// How many words a message holds: a tag, the time, a state's two words
/// and the machine's carried state.
const WORDS: usize = 4 + MachineCarry::WORDS;

/// Every message's size.
pub(super) const MESSAGE_BYTES: usize = WORDS * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Message {
    /// Child to hub: installed, frozen until its first resume.
    Ready,
    /// Hub to child: run, at machine time `now`, with the rest of the
    /// machine in state `view`, carrying the machine's `carry`.
    Resume {
        now: u64,
        view: ForeignState,
        carry: MachineCarry,
    },
    /// Child to hub: the baton goes back, at the child's time `now`, the
    /// child's own tasks in `state`, with the machine's `carry`.
    Yield {
        now: u64,
        state: ForeignState,
        carry: MachineCarry,
    },
    /// Child to hub: the child exited with wait status `status`.
    Exit {
        now: u64,
        status: i32,
        carry: MachineCarry,
    },
    /// Child to hub: a new thread id of the machine.
    AllocId,
    /// Hub to child: the id asked for.
    Id(i32),
    /// Child to hub: a filesystem call (`super::fs`) of `len` bytes
    /// follows, in packets of at most [`CHUNK_BYTES`].
    Fs { len: u64 },
    /// Hub to child: the call's answer, of `len` bytes, follows likewise.
    FsReply { len: u64 },
    /// Child to hub: `kill(pid, ..)` of other processes of the machine (a
    /// pid, the machine's group or every process); the signal's
    /// information as its sender made it, of `len` bytes, follows. The hub
    /// answers [`Message::Id`] with the call's result.
    Signal { pid: i32, len: u64 },
    /// Hub to a frozen child: it was sent `SIGKILL`, and dies.
    Kill,
    /// Child to hub: the child stops the run; its stop record, of `len`
    /// bytes, follows.
    Stop { len: u64 },
    /// Child to hub: a facts document of `len` bytes for the run follows.
    Facts { len: u64 },
    /// A recording child's metadata (JSON of `len` bytes), before its
    /// first decision.
    TraceBegin { len: u64 },
    /// Child to hub: an operation on a pipe the root holds
    /// (`super::pipes`), of `len` bytes, follows in packets.
    Pipe { len: u64 },
    /// Hub to child: the operation's answer, of `len` bytes, follows.
    PipeReply { len: u64 },
    /// Child to hub, before it is ready: its descriptors, as its spawn
    /// arranged them.
    Plan,
    /// Hub to child: the descriptor plan (JSON of `len` bytes) follows.
    PlanReply { len: u64 },
    /// Hub to a frozen child, before its resume: a signal another process
    /// sent it; its information, of `len` bytes, follows.
    Raise { len: u64 },
}

/// The largest packet a frame's payload travels in: well inside a
/// `SOCK_SEQPACKET` socket's default buffer.
pub(super) const CHUNK_BYTES: usize = 32 << 10;

fn state_words(state: ForeignState) -> [u64; 2] {
    match state {
        ForeignState::Runnable => [0, 0],
        ForeignState::Parked => [1, 0],
        ForeignState::ParkedUntil { deadline_nanos } => [2, deadline_nanos],
        ForeignState::Gone => [3, 0],
    }
}

fn state_of(kind: u64, deadline_nanos: u64) -> Option<ForeignState> {
    Some(match kind {
        0 => ForeignState::Runnable,
        1 => ForeignState::Parked,
        2 => ForeignState::ParkedUntil { deadline_nanos },
        3 => ForeignState::Gone,
        _ => return None,
    })
}

/// A message's words: the tag, then up to three words, then the carry.
fn words(tag: u64, head: [u64; 3], carry: Option<MachineCarry>) -> [u64; WORDS] {
    let mut words = [0u64; WORDS];
    words[0] = tag;
    words[1..4].copy_from_slice(&head);
    if let Some(carry) = carry {
        words[4..].copy_from_slice(&carry.to_words());
    }
    words
}

impl Message {
    pub(super) fn encode(&self) -> [u8; MESSAGE_BYTES] {
        let words = match *self {
            Message::Ready => words(1, [0; 3], None),
            Message::Resume { now, view, carry } => {
                let [kind, deadline] = state_words(view);
                words(2, [now, kind, deadline], Some(carry))
            }
            Message::Yield { now, state, carry } => {
                let [kind, deadline] = state_words(state);
                words(3, [now, kind, deadline], Some(carry))
            }
            Message::Exit { now, status, carry } => {
                words(4, [now, status as u32 as u64, 0], Some(carry))
            }
            Message::AllocId => words(5, [0; 3], None),
            Message::Id(id) => words(6, [id as u32 as u64, 0, 0], None),
            Message::Fs { len } => words(7, [len, 0, 0], None),
            Message::FsReply { len } => words(8, [len, 0, 0], None),
            Message::Signal { pid, len } => words(9, [pid as u32 as u64, len, 0], None),
            Message::Kill => words(10, [0; 3], None),
            Message::Stop { len } => words(11, [len, 0, 0], None),
            Message::Facts { len } => words(12, [len, 0, 0], None),
            Message::TraceBegin { len } => words(13, [len, 0, 0], None),
            Message::Pipe { len } => words(14, [len, 0, 0], None),
            Message::PipeReply { len } => words(15, [len, 0, 0], None),
            Message::Plan => words(16, [0; 3], None),
            Message::PlanReply { len } => words(17, [len, 0, 0], None),
            Message::Raise { len } => words(18, [len, 0, 0], None),
        };
        let mut bytes = [0u8; MESSAGE_BYTES];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Message> {
        if bytes.len() != MESSAGE_BYTES {
            return None;
        }
        let mut words = [0u64; WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let carry = MachineCarry::from_words(words[4..].try_into().ok()?);
        Some(match words[0] {
            1 => Message::Ready,
            2 => Message::Resume {
                now: words[1],
                view: state_of(words[2], words[3])?,
                carry,
            },
            3 => Message::Yield {
                now: words[1],
                state: state_of(words[2], words[3])?,
                carry,
            },
            4 => Message::Exit {
                now: words[1],
                status: words[2] as u32 as i32,
                carry,
            },
            5 => Message::AllocId,
            6 => Message::Id(words[1] as u32 as i32),
            7 => Message::Fs { len: words[1] },
            8 => Message::FsReply { len: words[1] },
            9 => Message::Signal {
                pid: words[1] as u32 as i32,
                len: words[2],
            },
            10 => Message::Kill,
            11 => Message::Stop { len: words[1] },
            12 => Message::Facts { len: words[1] },
            13 => Message::TraceBegin { len: words[1] },
            14 => Message::Pipe { len: words[1] },
            15 => Message::PipeReply { len: words[1] },
            16 => Message::Plan,
            17 => Message::PlanReply { len: words[1] },
            18 => Message::Raise { len: words[1] },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips() {
        let carry = MachineCarry {
            carry_nanos: 5,
            busy_nanos: 6,
            progress_events: 11,
            arms: [
                patina_dst_runtime::ArmCarry {
                    armed: true,
                    baseline_nanos: 12,
                    stall_ops: 13,
                },
                Default::default(),
            ],
            ..Default::default()
        };
        for message in [
            Message::Ready,
            Message::Resume {
                now: 7,
                view: ForeignState::ParkedUntil { deadline_nanos: 9 },
                carry,
            },
            Message::Yield {
                now: 1,
                state: ForeignState::Runnable,
                carry,
            },
            Message::Exit {
                now: 3,
                status: -1,
                carry,
            },
            Message::AllocId,
            Message::Id(42),
            Message::Fs { len: 1 << 20 },
            Message::FsReply { len: 0 },
            Message::Signal { pid: -1, len: 128 },
            Message::Kill,
            Message::Stop { len: 300 },
            Message::Facts { len: 70_000 },
            Message::TraceBegin { len: 5 },
            Message::Pipe { len: 24 },
            Message::PipeReply { len: 32 },
            Message::Plan,
            Message::PlanReply { len: 2 },
            Message::Raise { len: 128 },
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
    }
}
