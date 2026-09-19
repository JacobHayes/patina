// clock_gettime_nsec_np returns the virtual clock value directly in nanoseconds
// (rustix's time module). It must map onto the same virtual clock as
// clock_gettime — CLOCK_UPTIME_RAW/CLOCK_MONOTONIC both read PATINA monotonic —
// so with no intervening sleep the two reads agree, and two same-seed runs are
// byte-identical.
const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 6;
const CLOCK_UPTIME_RAW: u32 = 8;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn clock_gettime_nsec_np(clock_id: u32) -> u64;
    fn clock_gettime(clock_id: u32, tp: *mut Timespec) -> i32;
}

fn main() {
    unsafe {
        let mono_ns = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(clock_gettime(CLOCK_MONOTONIC, &mut ts), 0);
        let mono_gt = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        assert_eq!(
            mono_ns, mono_gt,
            "clock_gettime_nsec_np disagreed with clock_gettime on the virtual monotonic clock"
        );
        let real_ns = clock_gettime_nsec_np(CLOCK_REALTIME);
        println!("CLOCK_NSEC_RESULT mono_ns={mono_ns} real_ns={real_ns}");
    }
}
