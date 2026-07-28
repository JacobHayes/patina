//! Deterministic monotonic and realtime clocks.

use patina_dst_abi::{ClockKind, EffectError, ErrorCode};
use patina_dst_driver_api::{ClockDriver, DriverResult};

/// A clock that advances only when instructed by the deterministic runtime.
pub struct VirtualClock {
    monotonic_nanos: u64,
    realtime_epoch_nanos: u64,
}

impl VirtualClock {
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
    fn default() -> Self {
        Self::new(0)
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
