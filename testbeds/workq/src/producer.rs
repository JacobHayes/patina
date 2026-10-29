//! A producer thread plus the pure job derivation and the durability ledger.
//! `(producer, client_seq)` is the idempotency key, so a retry never creates a
//! second job.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::wire::{Msg, NUM_KEYS};

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The bucket key and (nonzero) work for one client request. Pure in
/// `(seed, producer, client_seq)`, so a seed's workload — and the outcome hash —
/// is reproducible across runs and platforms.
pub fn derive_job(seed: u64, producer: u32, client_seq: u64) -> (u32, u64) {
    let mut state = seed
        ^ (producer as u64).wrapping_mul(0xD1B5_4A32_D192_ED03)
        ^ client_seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let a = splitmix64(&mut state);
    let b = splitmix64(&mut state);
    ((a % NUM_KEYS as u64) as u32, (a ^ b) | 1)
}

/// Job ids a producer got an `EnqueueAck` for. Every one MUST survive
/// crash-recovery (the durability invariant checked in `report`).
///
/// In memory it survives only the in-process server restart. A process
/// restart (Patina's `--crash-permille`) starts the whole program afresh, so
/// `--ack-ledger PATH` also keeps the acks on disk, the way a real client that
/// outlives the server would remember them: each ack is appended and fsync'd,
/// and the acks an earlier incarnation recorded come back as [`Self::prior`]
/// for `report` to hold the recovered log to.
#[derive(Default)]
pub struct AckedLedger {
    job_ids: BTreeSet<u64>,
    /// Acks an earlier incarnation recorded: job id -> `(producer, client_seq)`.
    prior: BTreeMap<u64, (u32, u64)>,
    /// Prior acks the log no longer held when this incarnation started.
    prior_lost: BTreeSet<u64>,
    file: Option<File>,
}

impl AckedLedger {
    /// Open the on-disk ledger, reading what earlier incarnations recorded.
    /// Creating it makes its directory entry durable too, before the server
    /// creates anything, so the ledger never depends on the queue's own fsyncs.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut prior = BTreeMap::new();
        match File::open(path) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text)?;
                // Only whole lines: a crash can tear the last, unsynced one.
                for line in text.split_inclusive('\n').filter(|l| l.ends_with('\n')) {
                    let fields: Vec<u64> = line
                        .split_whitespace()
                        .filter_map(|f| f.parse().ok())
                        .collect();
                    if let [job_id, producer, client_seq] = fields[..] {
                        prior.insert(job_id, (producer as u32, client_seq));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        File::open(parent.unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(Self {
            job_ids: BTreeSet::new(),
            prior,
            prior_lost: BTreeSet::new(),
            file: Some(file),
        })
    }

    pub fn record(&mut self, job_id: u64, producer: u32, client_seq: u64) {
        self.job_ids.insert(job_id);
        if let Some(file) = &mut self.file {
            // A lost ledger line would silently drop this ack's cross-restart
            // check, so a failed write ends the run instead of passing it.
            if let Err(error) =
                writeln!(file, "{job_id} {producer} {client_seq}").and_then(|()| file.sync_all())
            {
                eprintln!("WORKQ_FAILURE ack-ledger-write-failed: {error}");
                std::process::exit(2);
            }
        }
    }
    /// Record which prior acks `recovered` (job id -> identity) lacks.
    pub fn audit_prior(&mut self, recovered: &BTreeMap<u64, (u32, u64)>) {
        self.prior_lost = self
            .prior
            .iter()
            .filter(|&(id, &(producer, seq))| recovered.get(id) != Some(&(producer, seq)))
            .map(|(&id, _)| id)
            .collect();
    }
    pub fn prior_lost(&self) -> &BTreeSet<u64> {
        &self.prior_lost
    }
    pub fn ids(&self) -> &BTreeSet<u64> {
        &self.job_ids
    }
    pub fn prior(&self) -> &BTreeMap<u64, (u32, u64)> {
        &self.prior
    }
}

pub type AckedHandle = Arc<Mutex<AckedLedger>>;

pub struct ProducerSpec {
    pub id: u32,
    pub server: SocketAddr,
    /// When set, the numeric `server` above is only the port source: the
    /// producer resolves `host:port` once at thread startup instead of
    /// dialing `server` directly (see `wire::resolve_server_host`). `None`
    /// (the default) is the original zero-DNS numeric path, unchanged.
    pub server_host: Option<String>,
    pub seed: u64,
    pub count: u64,
    pub acked: AckedHandle,
    pub shutdown: Arc<AtomicBool>,
    pub retry_timeout: Duration,
}

pub fn run(spec: ProducerSpec) {
    let socket = match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))) {
        Ok(socket) => socket,
        Err(error) => return eprintln!("producer {}: bind failed: {error}", spec.id),
    };
    let _ = socket.set_read_timeout(Some(spec.retry_timeout));
    let mut buffer = [0u8; 512];

    let server = match &spec.server_host {
        Some(host) => match crate::wire::resolve_server_host(host, spec.server.port()) {
            Some(addr) => addr,
            None => {
                return eprintln!(
                    "producer {}: dns resolution of {host:?} exhausted retries",
                    spec.id
                );
            }
        },
        None => spec.server,
    };

    for client_seq in 0..spec.count {
        let (key, work) = derive_job(spec.seed, spec.id, client_seq);
        'resend: while !spec.shutdown.load(Ordering::Relaxed) {
            Msg::Enqueue(spec.id, client_seq, key, work).send(&socket, server);
            // Read past stale acks (a duplicate, or one for an earlier resend)
            // rather than resending for each: every resend earns one more ack,
            // so resending on a stale one keeps a stale ack queued forever.
            while let Some(reply) = Msg::recv(&socket, &mut buffer) {
                if let Msg::EnqueueAck(producer, acked, job_id) = reply {
                    if producer == spec.id && acked == client_seq {
                        spec.acked
                            .lock()
                            .unwrap()
                            .record(job_id, producer, client_seq);
                        break 'resend;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_job_is_deterministic_and_distinct_per_client() {
        assert_eq!(derive_job(7, 0, 3), derive_job(7, 0, 3));
        assert_ne!(derive_job(7, 0, 3), derive_job(7, 0, 4));
        // Distinct work for the same client_seq on two producers — what the
        // (producer, client_seq) identity protects.
        assert_ne!(derive_job(7, 0, 3), derive_job(7, 1, 3));
        let (key, work) = derive_job(1, 0, 5);
        assert!(key < NUM_KEYS && work != 0);
    }
}
