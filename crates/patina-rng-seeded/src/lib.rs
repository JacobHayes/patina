//! A deterministic entropy byte stream based on SplitMix64.

use patina_driver_api::{DriverResult, EntropyDriver};

/// The specified SplitMix64 stream used by deterministic decision policies.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

/// A deterministic entropy source with chunk-independent output.
///
/// Words are generated with SplitMix64 and emitted in little-endian order.
/// Buffered bytes ensure that `fill(3)` followed by `fill(5)` is identical to
/// `fill(8)` for a fresh driver with the same seed.
pub struct SeededEntropy {
    generator: SplitMix64,
    buffered: [u8; 8],
    next_buffered: usize,
}

impl SeededEntropy {
    pub fn new(seed: u64) -> Self {
        Self {
            generator: SplitMix64::new(seed),
            buffered: [0; 8],
            next_buffered: 8,
        }
    }
}

impl EntropyDriver for SeededEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> DriverResult<()> {
        for byte in destination {
            if self.next_buffered == self.buffered.len() {
                self.buffered = self.generator.next_u64().to_le_bytes();
                self.next_buffered = 0;
            }
            *byte = self.buffered[self.next_buffered];
            self.next_buffered += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use patina_driver_api::EntropyDriver;

    use super::*;

    #[test]
    fn splitmix64_has_a_fixed_byte_stream() {
        let mut entropy = SeededEntropy::new(0);
        let mut bytes = [0; 16];
        entropy.fill(&mut bytes).unwrap();
        assert_eq!(
            bytes,
            [
                0xaf, 0xcd, 0x1d, 0x7b, 0x39, 0xa8, 0x20, 0xe2, 0xf4, 0x65, 0xb9, 0xa1, 0x6a, 0x9e,
                0x78, 0x6e,
            ]
        );
    }

    #[test]
    fn output_does_not_depend_on_fill_chunking() {
        let mut whole = SeededEntropy::new(42);
        let mut expected = [0; 19];
        whole.fill(&mut expected).unwrap();

        let mut chunked = SeededEntropy::new(42);
        let mut actual = [0; 19];
        chunked.fill(&mut actual[..3]).unwrap();
        chunked.fill(&mut actual[3..11]).unwrap();
        chunked.fill(&mut actual[11..]).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn different_seeds_change_the_stream() {
        let mut left = SeededEntropy::new(1);
        let mut right = SeededEntropy::new(2);
        let mut left_bytes = [0; 8];
        let mut right_bytes = [0; 8];
        left.fill(&mut left_bytes).unwrap();
        right.fill(&mut right_bytes).unwrap();
        assert_ne!(left_bytes, right_bytes);
    }
}
