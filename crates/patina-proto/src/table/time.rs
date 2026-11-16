//! Clocks, sleeps, timers.
use super::*;

const G: Group = Group::Time;

pub const ROWS: &[Row] = &[
    Row::new(G, 228, Virt, C, "Read from vclock_ns (realtime adds the fixed epoch); CPU-time clocks are the thread's trap charges. The kernel is not asked.")
        .outs(&[out(1, Len::Fixed(16))]),
    Row::new(G, 96, Virt, C, "Realtime from vclock_ns plus the fixed epoch, in microseconds; the timezone is zero.")
        .outs(&[out(0, Len::Fixed(16)), out(1, Len::Fixed(8))]),
    Row::new(G, 201, Virt, C, "Seconds of virtual realtime.").outs(&[out(0, Len::Fixed(8))]),
    Row::new(G, 229, Virt, C, "Resolution is a constant (1 ns, coarse clocks 4 ms).").outs(&[out(1, Len::Fixed(16))]),
    Row::new(G, 100, Virt, C, "CPU times are the sum of trap charges; elapsed ticks are virtual time at 100 Hz.")
        .outs(&[out(0, Len::Fixed(32))]),
    Row::new(G, 35, Virt, C, "A Sleep request: the deadline is virtual and the supervisor's event queue wakes the thread; the kernel never waits."),
    Row::new(G, 230, Virt, C, "A Sleep request (relative or TIMER_ABSTIME, realtime converted by the fixed epoch); CPU-time clocks are refused with EINVAL."),
];
