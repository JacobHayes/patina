//! A producer thread plus the pure job derivation and the durability ledger.
//! `(producer, client_seq)` is the idempotency key, so a retry never creates a
//! second job.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
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
#[derive(Default)]
pub struct AckedLedger {
    job_ids: BTreeSet<u64>,
}

impl AckedLedger {
    pub fn record(&mut self, job_id: u64) {
        self.job_ids.insert(job_id);
    }
    pub fn ids(&self) -> &BTreeSet<u64> {
        &self.job_ids
    }
}

pub type AckedHandle = Arc<Mutex<AckedLedger>>;

pub struct ProducerSpec {
    pub id: u32,
    pub server: SocketAddr,
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

    for client_seq in 0..spec.count {
        let (key, work) = derive_job(spec.seed, spec.id, client_seq);
        while !spec.shutdown.load(Ordering::Relaxed) {
            Msg::Enqueue(spec.id, client_seq, key, work).send(&socket, spec.server);
            if let Some(Msg::EnqueueAck(producer, acked, job_id)) = Msg::recv(&socket, &mut buffer)
            {
                if producer == spec.id && acked == client_seq {
                    spec.acked.lock().unwrap().record(job_id);
                    break;
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
