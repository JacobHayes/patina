//! The runtime's entropy source: a seeded, chunk-independent byte stream.

use patina_dst_rng_seeded::SplitMix64;

/// A deterministic entropy source with chunk-independent output.
///
/// Words are generated with SplitMix64 and emitted in little-endian order.
/// Buffered bytes ensure that `fill(3)` followed by `fill(5)` is identical to
/// `fill(8)` for a fresh driver with the same seed.
pub(crate) struct SeededEntropy {
    generator: SplitMix64,
    buffered: [u8; 8],
    next_buffered: usize,
}

impl SeededEntropy {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            generator: SplitMix64::new(seed),
            buffered: [0; 8],
            next_buffered: 8,
        }
    }

    /// Fill `destination` with the next bytes of the stream.
    pub(crate) fn fill(&mut self, destination: &mut [u8]) {
        for byte in destination {
            if self.next_buffered == self.buffered.len() {
                self.buffered = self.generator.next_u64().to_le_bytes();
                self.next_buffered = 0;
            }
            *byte = self.buffered[self.next_buffered];
            self.next_buffered += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_has_a_fixed_seed_dependent_byte_stream() {
        let mut entropy = SeededEntropy::new(0);
        let mut bytes = [0; 16];
        entropy.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                0xaf, 0xcd, 0x1d, 0x7b, 0x39, 0xa8, 0x20, 0xe2, 0xf4, 0x65, 0xb9, 0xa1, 0x6a, 0x9e,
                0x78, 0x6e,
            ]
        );
        let mut other = [0; 16];
        SeededEntropy::new(1).fill(&mut other);
        assert_ne!(bytes, other);
    }

    #[test]
    fn output_does_not_depend_on_fill_chunking() {
        let mut whole = SeededEntropy::new(42);
        let mut expected = [0; 19];
        whole.fill(&mut expected);

        let mut chunked = SeededEntropy::new(42);
        let mut actual = [0; 19];
        chunked.fill(&mut actual[..3]);
        chunked.fill(&mut actual[3..11]);
        chunked.fill(&mut actual[11..]);

        assert_eq!(actual, expected);
    }
}
