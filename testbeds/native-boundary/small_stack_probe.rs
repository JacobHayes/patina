//! A runtime with small thread stacks runs its code on stacks of a few KiB
//! and makes raw syscalls there. The syscall trap's signal frame and its
//! dispatch (larger when recording) must take none of that stack: natively a
//! syscall instruction writes nothing to the stack at all. On the main thread
//! and on a second thread, each raw syscall here runs with its stack pointer
//! at the top of a 2 KiB stack inside a sentinel-filled region, and the probe
//! prints how many bytes of the region were written (x86_64: only
//! syscall-user-dispatch contains raw syscalls).

#[cfg(target_arch = "x86_64")]
mod small {
    use std::arch::asm;

    const REGION: usize = 64 * 1024;
    const STACK: usize = 2048;
    const SENTINEL: u8 = 0xa5;

    /// The syscall `nr` with the stack pointer at `top`, and back.
    unsafe fn raw_at(top: usize, nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "mov r12, rsp",
                "mov rsp, {top}",
                "syscall",
                "mov rsp, r12",
                top = in(reg) top,
                inlateout("rax") nr => ret,
                in("rdi") a0,
                in("rsi") a1,
                in("rdx") a2,
                out("r12") _,
                out("rcx") _,
                out("r11") _,
            );
        }
        ret
    }

    /// Raw syscalls on a 2 KiB stack: what they answered, and how many bytes
    /// of the region the stack sits at the top of they wrote.
    pub fn run(who: &str) -> String {
        const GETPID: i64 = 39;
        const GETTID: i64 = 186;
        const SCHED_YIELD: i64 = 24;
        const WRITE: i64 = 1;
        const CLOCK_GETTIME: i64 = 228;
        const GETRANDOM: i64 = 318;
        let mut region = vec![SENTINEL; REGION];
        let top = (region.as_mut_ptr() as usize + REGION) & !15;
        let mut entropy = [0u8; 16];
        let mut now = [0i64; 2];
        let line = format!("raw write from a 2 KiB stack ({who})\n");
        let (pid, tid, yielded, written, random, clock) = unsafe {
            (
                raw_at(top, GETPID, 0, 0, 0),
                raw_at(top, GETTID, 0, 0, 0),
                raw_at(top, SCHED_YIELD, 0, 0, 0),
                raw_at(top, WRITE, 1, line.as_ptr() as i64, line.len() as i64),
                raw_at(top, GETRANDOM, entropy.as_mut_ptr() as i64, 16, 0),
                raw_at(top, CLOCK_GETTIME, 1, now.as_mut_ptr() as i64, 0),
            )
        };
        assert_eq!((yielded, written, random, clock), (0, line.len() as i64, 16, 0));
        // Nothing of the guest's own runs on the region: any byte written is
        // the trap's. How far below the top, and past the 2 KiB stack.
        let written = region
            .iter()
            .position(|byte| *byte != SENTINEL)
            .map_or(0, |first| top - (region.as_ptr() as usize + first));
        let overrun = written.saturating_sub(STACK);
        let entropy: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        format!(
            "{who}: pid={pid} tid={tid} entropy={entropy} clock={}.{:09} written={written} \
             overrun={overrun}",
            now[0], now[1]
        )
    }
}

fn main() {
    #[cfg(target_arch = "x86_64")]
    {
        let main = small::run("main");
        let thread = std::thread::spawn(|| small::run("thread")).join().unwrap();
        println!("{main}\n{thread}\nSMALL_STACK_PROBE_OK");
    }
}
