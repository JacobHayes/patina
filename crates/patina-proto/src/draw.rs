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
    /// Counter preemption: the slice length of each segment.
    Slice = 9,
    /// SDK fault points, knobs and delays (`sdk::point_draw`).
    Sdk = 10,
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

/// Fill `buf` with bytes derived from one draw: word `i` is `mix64(draw + i * golden)`.
pub fn fill(seed: u64, stream: Stream, seq: u64, buf: &mut [u8]) {
    let base = draw(seed, stream, seq);
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let w = mix64(base.wrapping_add((i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)));
        let b = w.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}
