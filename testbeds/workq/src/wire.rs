//! Wire + log encoding: a line-based TEXT protocol. UDP datagrams and WAL
//! records are both space-delimited ASCII lines, so the WAL is literally
//! `cat`-able. Each WAL line ends with a CRC-32 hex field; recovery uses it to
//! tell a crash-torn final line (safe to drop) from mid-log corruption (refuse).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::{FromStr, Split};
use std::time::Duration;

/// Number of accumulator buckets a job's key can land in (payload derivation).
pub const NUM_KEYS: u32 = 8;

/// CRC-32/IEEE, bitwise (no table) — lines are short, so this stays dep-free.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn num<T: FromStr>(t: &mut Split<'_, char>) -> Option<T> {
    t.next()?.parse().ok()
}

/// `Fail` is a cooperative `job-fail`; the server requeues, then fails it past
/// the attempt limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Fail,
}

impl Outcome {
    fn wire(self) -> &'static str {
        if self == Outcome::Success {
            "OK"
        } else {
            "FAIL"
        }
    }
}

/// One UDP datagram, as a text line. Fields are positional; each variant's
/// trailing comment is the legend. `(producer, client_seq)` is the enqueue
/// idempotency key; the server replies to the datagram's source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Enqueue(u32, u64, u32, u64), // ENQ  producer client_seq key work
    EnqueueAck(u32, u64, u64),   // EACK producer client_seq job_id
    Poll(u32),                   // POLL worker
    Assign(u64, u64, u32),       // JOB  job_id work attempt (attempt = 1-based delivery count)
    PollEmpty,                   // NONE
    Complete(u32, u64, Outcome), // DONE worker job_id OK|FAIL
    CompleteAck(u64),            // CACK job_id
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Msg::Enqueue(prod, seq, key, work) => format!("ENQ {prod} {seq} {key} {work}"),
            Msg::EnqueueAck(prod, seq, job) => format!("EACK {prod} {seq} {job}"),
            Msg::Poll(worker) => format!("POLL {worker}"),
            Msg::Assign(job, work, attempt) => format!("JOB {job} {work} {attempt}"),
            Msg::PollEmpty => "NONE".to_string(),
            Msg::Complete(worker, job, outcome) => {
                format!("DONE {worker} {job} {}", outcome.wire())
            }
            Msg::CompleteAck(job) => format!("CACK {job}"),
        }
        .into_bytes()
    }

    /// `None` on a malformed or unknown line — the receiver treats that as a
    /// dropped datagram.
    pub fn decode(bytes: &[u8]) -> Option<Msg> {
        let mut t = std::str::from_utf8(bytes).ok()?.split(' ');
        let msg = match t.next()? {
            "ENQ" => Msg::Enqueue(num(&mut t)?, num(&mut t)?, num(&mut t)?, num(&mut t)?),
            "EACK" => Msg::EnqueueAck(num(&mut t)?, num(&mut t)?, num(&mut t)?),
            "POLL" => Msg::Poll(num(&mut t)?),
            "JOB" => Msg::Assign(num(&mut t)?, num(&mut t)?, num(&mut t)?),
            "NONE" => Msg::PollEmpty,
            "DONE" => Msg::Complete(
                num(&mut t)?,
                num(&mut t)?,
                match t.next()? {
                    "OK" => Outcome::Success,
                    "FAIL" => Outcome::Fail,
                    _ => return None,
                },
            ),
            "CACK" => Msg::CompleteAck(num(&mut t)?),
            _ => return None,
        };
        t.next().is_none().then_some(msg) // reject trailing garbage
    }

    pub fn send(&self, socket: &UdpSocket, to: SocketAddr) {
        let _ = socket.send_to(&self.encode(), to); // a drop is a legitimate net event
    }

    pub fn recv(socket: &UdpSocket, buffer: &mut [u8]) -> Option<Msg> {
        let (len, _) = socket.recv_from(buffer).ok()?;
        Msg::decode(&buffer[..len])
    }
}

/// Retries before a `--server-host` resolution gives up.
const DNS_RESOLVE_RETRIES: u32 = 30;
/// Backoff between resolution attempts.
const DNS_RESOLVE_BACKOFF: Duration = Duration::from_millis(5);

/// Resolve `host:port` (routing through Patina's deterministic resolver under
/// `--dns-entry`/`--dns-fail-permille`/`--dns-latency-nanos`), retrying on
/// failure. An UNretried DNS failure is itself one of the unified-fault-knobs
/// arc's named planted-bug classes, so the clean harness deliberately retries
/// here with a bounded, short-backoff loop instead of giving up on the first
/// NXDOMAIN or injected timeout — a real DNS fault is transient by nature, and
/// giving up on the first failure would wedge the clean (fault-free) path into
/// spurious non-convergence too. `None` after the bound is exhausted (a
/// misconfigured or permanently-failing name), so the caller can fail the
/// thread instead of retrying forever.
pub fn resolve_server_host(host: &str, port: u16) -> Option<SocketAddr> {
    for attempt in 0..DNS_RESOLVE_RETRIES {
        if let Ok(mut addrs) = (host, port).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                return Some(addr);
            }
        }
        if attempt + 1 < DNS_RESOLVE_RETRIES {
            std::thread::sleep(DNS_RESOLVE_BACKOFF);
        }
    }
    None
}

// ---- Write-ahead-log records ------------------------------------------------

/// A durable state transition, one per `cat`-able WAL line; replaying the log in
/// order reconstructs the queue. Terminal state is `Complete` or `Fail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalRecord {
    Enqueue(u64, u32, u64, u32, u64), // ENQ  job_id producer client_seq key work
    Complete(u64),                    // DONE job_id
    Fail(u64),                        // FAIL job_id
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedRecord {
    pub seq: u64,
    pub record: WalRecord,
}

/// A `TornTail` is only legitimate in the last segment (a crash mid-append).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanEnd {
    Clean,
    TornTail,
}

/// Frame a record as `<VERB> <seq> <fields...> <crc32hex>\n`. The CRC covers
/// everything before it, so a torn or bit-flipped line fails to parse.
pub fn frame_record(seq: u64, record: &WalRecord) -> Vec<u8> {
    let body = match record {
        WalRecord::Enqueue(job, prod, cseq, key, work) => {
            format!("ENQ {seq} {job} {prod} {cseq} {key} {work}")
        }
        WalRecord::Complete(job) => format!("DONE {seq} {job}"),
        WalRecord::Fail(job) => format!("FAIL {seq} {job}"),
    };
    format!("{body} {:08x}\n", crc32(body.as_bytes())).into_bytes()
}

/// `None` if the CRC fails or the format is wrong — i.e. the line was torn or
/// corrupted.
fn parse_line(line: &[u8]) -> Option<FramedRecord> {
    let (body, crc_hex) = std::str::from_utf8(line).ok()?.rsplit_once(' ')?;
    if u32::from_str_radix(crc_hex, 16).ok()? != crc32(body.as_bytes()) {
        return None;
    }
    let mut t = body.split(' ');
    let verb = t.next()?;
    let seq = num(&mut t)?;
    let record = match verb {
        "ENQ" => WalRecord::Enqueue(
            num(&mut t)?,
            num(&mut t)?,
            num(&mut t)?,
            num(&mut t)?,
            num(&mut t)?,
        ),
        "DONE" => WalRecord::Complete(num(&mut t)?),
        "FAIL" => WalRecord::Fail(num(&mut t)?),
        _ => return None,
    };
    t.next().is_none().then_some(FramedRecord { seq, record })
}

/// The heart of fail-closed recovery: a torn write only ever damages the last
/// line, so a final line with no newline — or a bad line with nothing valid
/// after it — is a torn tail, while a bad line *followed by* a valid line is
/// real mid-log corruption and returns `Err`.
pub fn scan_segment(bytes: &[u8]) -> Result<(Vec<FramedRecord>, ScanEnd), String> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(rel) = newline_from(bytes, pos) else {
            return Ok((records, ScanEnd::TornTail)); // no newline: torn final write
        };
        match parse_line(&bytes[pos..pos + rel]) {
            Some(rec) => {
                records.push(rec);
                pos += rel + 1;
            }
            None if valid_line_after(bytes, pos + rel + 1) => {
                return Err(format!(
                    "invalid record line at byte {pos} followed by valid data"
                ));
            }
            None => return Ok((records, ScanEnd::TornTail)),
        }
    }
    Ok((records, ScanEnd::Clean))
}

/// Distinguishes a torn tail (nothing valid after) from mid-log corruption
/// (valid data after the bad line).
fn valid_line_after(bytes: &[u8], mut pos: usize) -> bool {
    while let Some(rel) = newline_from(bytes, pos) {
        if parse_line(&bytes[pos..pos + rel]).is_some() {
            return true;
        }
        pos += rel + 1;
    }
    false
}

fn newline_from(bytes: &[u8], pos: usize) -> Option<usize> {
    bytes[pos..].iter().position(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_round_trips_and_rejects_garbage() {
        let msgs = [
            Msg::Enqueue(3, 42, 4, 99),
            Msg::EnqueueAck(3, 42, 9),
            Msg::Poll(2),
            Msg::Assign(9, 1234, 2),
            Msg::PollEmpty,
            Msg::Complete(2, 9, Outcome::Success),
            Msg::CompleteAck(9),
        ];
        for msg in msgs {
            assert_eq!(Msg::decode(&msg.encode()), Some(msg));
        }
        assert_eq!(Msg::decode(b""), None);
        assert_eq!(Msg::decode(b"POLL"), None); // truncated
        assert_eq!(Msg::decode(b"HUH 1"), None); // unknown verb
        assert_eq!(Msg::decode(b"POLL 1 2"), None); // trailing garbage
    }

    #[test]
    fn torn_tail_recovers_but_mid_log_corruption_fails_closed() {
        let good = |id| frame_record(id, &WalRecord::Complete(id));
        // A crash mid-append leaves a torn final line: recover the prefix.
        let mut torn = good(1);
        torn.extend_from_slice(&good(2));
        torn.truncate(torn.len() - 3); // chop the newline + tail
        let (framed, end) = scan_segment(&torn).unwrap();
        assert_eq!((framed.len(), end), (1, ScanEnd::TornTail));
        // A bad line with a valid line after it is real corruption: Err.
        let mut seg = good(1);
        let flip = seg.len() + 6;
        seg.extend_from_slice(&good(2));
        seg.extend_from_slice(&good(3));
        seg[flip] ^= 0x01;
        assert!(scan_segment(&seg).is_err());
    }
}
