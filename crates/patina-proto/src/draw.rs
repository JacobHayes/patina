//! Stateless random draws: `draw(seed, stream, seq) = mix(seed, stream, seq)`.
//! Either side can compute a draw, and a draw in one stream never shifts another.

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Sched = 1,
    Preempt = 2,
    Entropy = 3,
    FaultFs = 4,
    FaultNet = 5,
    Crash = 6,
    Torn = 7,
    NetDelay = 8,
    /// SDK fault points, knobs and delays (`sdk::point_draw`).
    Sdk = 10,
    /// The run's fault plan: each setting given as a range is resolved by its own draw,
    /// keyed by the setting's name (`faults::plan_draw`).
    FaultPlan = 11,
    /// Compute points: the gap of each segment (`compute::gap`).
    Compute = 12,
    /// Datagrams: delay and faults, keyed by datagram id and a sub-key (`wire::DSUB_*`).
    Dgram = 13,
    /// Load-time points: the instructions a switch walks past its site (`compute::walk`).
    Walk = 14,
    /// Load-time points: whether a switch point the runtime draws ahead stays with its thread
    /// (`compute::chain`).
    Stay = 15,
    /// Nodes: the seed's partition schedule, keyed by the partition's ordinal and a sub-key
    /// (`node::PSUB_*`), so that no draw depends on traffic or on another class.
    Partition = 16,
    /// Nodes: each node's own draws (kill times, down times), keyed by node, boot and a
    /// sub-key (`node::NSUB_*`).
    Node = 17,
}

/// splitmix64 finaliser.
#[inline]
pub const fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[inline]
pub const fn draw(seed: u64, stream: Stream, seq: u64) -> u64 {
    let s = mix64((stream as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5851_f42d_4c95_7f2d);
    mix64(mix64(seed ^ s).wrapping_add(seq.wrapping_mul(0xd6e8_feb8_6659_fd93)) ^ s)
}

/// Piecewise log-uniform in [lo, hi] from the draw `d`: an octave uniformly, then uniform
/// within it.
pub fn log_uniform(d: u64, lo: u64, hi: u64) -> u64 {
    let hi = hi.max(lo);
    let mut octaves = 0u64;
    while octaves < 63 && (lo << (octaves + 1)) <= hi {
        octaves += 1;
    }
    let o = d % (octaves + 1);
    let base = lo << o;
    let n = base + (d >> 8) % base;
    n.min(hi)
}

/// Fill `buf` with bytes derived from one draw: word `i` is `mix64(draw + i * golden)`.
pub fn fill(seed: u64, stream: Stream, seq: u64, buf: &mut [u8]) {
    fill_from(seed, stream, seq, 0, buf)
}

/// The bytes of `fill` from word `word0` on: a buffer filled in pieces, each starting at a
/// multiple of 8 bytes, reads as one `fill`.
pub fn fill_from(seed: u64, stream: Stream, seq: u64, word0: u64, buf: &mut [u8]) {
    let base = draw(seed, stream, seq);
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let i = word0 + i as u64;
        let w = mix64(base.wrapping_add((i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)));
        let b = w.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}
