//! Deterministic monotonic and realtime clocks.

use patina_dst_abi::{ClockKind, EffectError, ErrorCode};
use patina_dst_driver_api::{ClockDriver, DriverResult};

/// Re-exported beside the clock that defaults to it; defined in
/// `patina-dst-abi` so crates below the drivers can name it too.
pub use patina_dst_abi::DEFAULT_REALTIME_EPOCH_NANOS;

/// A clock that advances only when instructed by the deterministic runtime.
pub struct VirtualClock {
    monotonic_nanos: u64,
    realtime_epoch_nanos: u64,
}

impl VirtualClock {
    /// A clock at monotonic zero whose realtime reading is
    /// `realtime_epoch_nanos` plus the monotonic time.
    pub const fn new(realtime_epoch_nanos: u64) -> Self {
        Self {
            monotonic_nanos: 0,
            realtime_epoch_nanos,
        }
    }

    pub const fn at(monotonic_nanos: u64, realtime_epoch_nanos: u64) -> Self {
        Self {
            monotonic_nanos,
            realtime_epoch_nanos,
        }
    }

    fn observed_time(&self, clock: ClockKind) -> DriverResult<u64> {
        match clock {
            ClockKind::Monotonic => Ok(self.monotonic_nanos),
            ClockKind::Realtime => self
                .realtime_epoch_nanos
                .checked_add(self.monotonic_nanos)
                .ok_or_else(|| {
                    EffectError::new(ErrorCode::InvalidInput, "virtual realtime clock overflowed")
                }),
        }
    }
}

impl Default for VirtualClock {
    /// A clock at monotonic zero on the [`DEFAULT_REALTIME_EPOCH_NANOS`] epoch.
    fn default() -> Self {
        Self::new(DEFAULT_REALTIME_EPOCH_NANOS)
    }
}

impl ClockDriver for VirtualClock {
    fn now(&mut self, clock: ClockKind) -> DriverResult<u64> {
        self.observed_time(clock)
    }

    fn sleep_until(&mut self, clock: ClockKind, deadline_nanos: u64) -> DriverResult<()> {
        let monotonic_deadline = match clock {
            ClockKind::Monotonic => deadline_nanos,
            ClockKind::Realtime => deadline_nanos.saturating_sub(self.realtime_epoch_nanos),
        };
        self.monotonic_nanos = self.monotonic_nanos.max(monotonic_deadline);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_clock_reads_the_default_epoch_at_monotonic_zero() {
        let mut clock = VirtualClock::default();
        assert_eq!(clock.now(ClockKind::Monotonic).unwrap(), 0);
        assert_eq!(
            clock.now(ClockKind::Realtime).unwrap(),
            DEFAULT_REALTIME_EPOCH_NANOS
        );
        // 2026-07-22T23:00:09Z, Patina's first commit.
        assert_eq!(DEFAULT_REALTIME_EPOCH_NANOS / 1_000_000_000, 1_784_761_209);
        assert_eq!(DEFAULT_REALTIME_EPOCH_NANOS % 1_000_000_000, 0);
        // A realtime deadline on the default epoch converts back to monotonic.
        clock
            .sleep_until(ClockKind::Realtime, DEFAULT_REALTIME_EPOCH_NANOS + 5)
            .unwrap();
        assert_eq!(clock.now(ClockKind::Monotonic).unwrap(), 5);
    }

    #[test]
    fn sleeping_advances_both_clock_domains() {
        let mut clock = VirtualClock::new(1_000);
        clock.sleep_until(ClockKind::Monotonic, 250).unwrap();
        assert_eq!(clock.now(ClockKind::Monotonic).unwrap(), 250);
        assert_eq!(clock.now(ClockKind::Realtime).unwrap(), 1_250);
    }

    #[test]
    fn sleeping_until_the_past_does_not_move_backwards() {
        let mut clock = VirtualClock::at(100, 1_000);
        clock.sleep_until(ClockKind::Realtime, 1_050).unwrap();
        assert_eq!(clock.now(ClockKind::Monotonic).unwrap(), 100);
    }

    #[test]
    fn realtime_overflow_fails_explicitly() {
        let mut clock = VirtualClock::at(1, u64::MAX);
        let error = clock.now(ClockKind::Realtime).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }
}
