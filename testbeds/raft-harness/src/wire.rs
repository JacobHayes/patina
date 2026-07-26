//! Encoding helpers shared by the file-backed storage and the UDP transport.
//!
//! Every raft type we move across a boundary (`Message`, `Entry`, `HardState`,
//! `Snapshot`) derives `prost::Message`, so a single pair of free functions
//! covers both the wire and the log. On disk we length-prefix each record so a
//! log file can hold many entries; on the network each datagram carries exactly
//! one encoded `Message`, so no framing is needed there.

use prost::Message as _;
use raft::prelude::{Entry, HardState, Message, Snapshot};

/// Encode any prost message to a fresh byte vector.
pub fn encode<M: prost::Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// Decode a raft `Message` from a whole UDP datagram.
pub fn decode_message(bytes: &[u8]) -> Result<Message, prost::DecodeError> {
    Message::decode(bytes)
}

/// Decode a `HardState` from the whole `hardstate.bin` file body.
pub fn decode_hard_state(bytes: &[u8]) -> Result<HardState, prost::DecodeError> {
    HardState::decode(bytes)
}

/// Decode a `Snapshot` from the whole `snapshot.bin` file body.
pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, prost::DecodeError> {
    Snapshot::decode(bytes)
}

/// Serialize a slice of entries as length-prefixed records: for each entry a
/// little-endian `u32` byte count followed by that many prost bytes. This is
/// the on-disk `entries.log` format, chosen to be trivial to truncate and to
/// re-read after a crash.
pub fn encode_entry_log(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let bytes = entry.encode_to_vec();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// Parse the length-prefixed `entries.log` body back into entries. A trailing
/// partial record (a torn final write) is reported as an error so the caller
/// can decide how to recover; the crash-injection phase relies on this being
/// detectable rather than silently dropped.
pub fn decode_entry_log(mut bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(format!("truncated length prefix: {} trailing bytes", bytes.len()));
        }
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        if bytes.len() < len {
            return Err(format!(
                "truncated record body: need {len} bytes, have {}",
                bytes.len()
            ));
        }
        let (record, rest) = bytes.split_at(len);
        let entry = Entry::decode(record).map_err(|error| format!("entry decode failed: {error}"))?;
        entries.push(entry);
        bytes = rest;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raft::prelude::Entry;

    fn entry(index: u64, term: u64, data: &[u8]) -> Entry {
        let mut entry = Entry::default();
        entry.set_index(index);
        entry.set_term(term);
        entry.set_data(data.to_vec());
        entry
    }

    #[test]
    fn entry_log_round_trips() {
        let entries = vec![entry(1, 1, b"a"), entry(2, 1, b""), entry(3, 2, b"cccc")];
        let bytes = encode_entry_log(&entries);
        let decoded = decode_entry_log(&bytes).expect("decode");
        assert_eq!(decoded.len(), 3);
        for (a, b) in entries.iter().zip(&decoded) {
            assert_eq!(a.get_index(), b.get_index());
            assert_eq!(a.get_term(), b.get_term());
            assert_eq!(a.get_data(), b.get_data());
        }
    }

    #[test]
    fn truncated_record_is_rejected() {
        let bytes = encode_entry_log(&[entry(1, 1, b"hello")]);
        // Drop the final byte to simulate a torn write.
        assert!(decode_entry_log(&bytes[..bytes.len() - 1]).is_err());
        // A truncated length prefix is also rejected.
        assert!(decode_entry_log(&[0u8, 0u8]).is_err());
    }
}
