//! The hub-child channel's messages: one fixed-size record each, so a
//! message never allocates and a `SOCK_SEQPACKET` read is always one whole
//! message.

use patina_dst_abi::ForeignState;

/// Every message's size: a tag and four words.
pub(super) const MESSAGE_BYTES: usize = 5 * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Message {
    /// Child to hub: installed, frozen until its first resume.
    Ready,
    /// Hub to child: run, at machine time `now`, with the rest of the
    /// machine in state `view`.
    Resume { now: u64, view: ForeignState },
    /// Child to hub: the baton goes back, at the child's time `now`, the
    /// child's own tasks in `state`.
    Yield { now: u64, state: ForeignState },
    /// Child to hub: the child exited with wait status `status`.
    Exit { now: u64, status: i32 },
    /// Child to hub: a new thread id of the machine.
    AllocId,
    /// Hub to child: the id asked for.
    Id(i32),
}

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

impl Message {
    pub(super) fn encode(&self) -> [u8; MESSAGE_BYTES] {
        let words: [u64; 5] = match *self {
            Message::Ready => [1, 0, 0, 0, 0],
            Message::Resume { now, view } => {
                let [kind, deadline] = state_words(view);
                [2, now, kind, deadline, 0]
            }
            Message::Yield { now, state } => {
                let [kind, deadline] = state_words(state);
                [3, now, kind, deadline, 0]
            }
            Message::Exit { now, status } => [4, now, status as u32 as u64, 0, 0],
            Message::AllocId => [5, 0, 0, 0, 0],
            Message::Id(id) => [6, id as u32 as u64, 0, 0, 0],
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
        let mut words = [0u64; 5];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        Some(match words[0] {
            1 => Message::Ready,
            2 => Message::Resume {
                now: words[1],
                view: state_of(words[2], words[3])?,
            },
            3 => Message::Yield {
                now: words[1],
                state: state_of(words[2], words[3])?,
            },
            4 => Message::Exit {
                now: words[1],
                status: words[2] as u32 as i32,
            },
            5 => Message::AllocId,
            6 => Message::Id(words[1] as u32 as i32),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips() {
        for message in [
            Message::Ready,
            Message::Resume {
                now: 7,
                view: ForeignState::ParkedUntil { deadline_nanos: 9 },
            },
            Message::Yield {
                now: 1,
                state: ForeignState::Runnable,
            },
            Message::Exit { now: 3, status: -1 },
            Message::AllocId,
            Message::Id(42),
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
    }
}
