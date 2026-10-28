// A guest that can read a source patina does not control: the host-randomized
// (ASLR) address of its own stack, under `--allow-randomized-address-layout`
// (patina fixes the layout otherwise). Nothing it calls is unsupported, so the
// audit passes it; whatever it derives from that address differs from run to
// run.
//
// The `leak-*` modes let that address decide what the run does; the `det-*`
// modes are the same shapes with the address left out, the deterministic
// controls. Argument one picks the mode.
//
// * `det-exit`: fail with exit 3 after printing a fixed six-letter token, the
//   failure's signature.
// * `leak-number-exit`: the same failure with the token spelled as the
//   address's digits, so the leak survives only in the exact line: a signature
//   collapses a digit run, and both runs share one signature.
// * `forge-marker` / `forge-native-run`: fail with exit 3 after printing the
//   leaked address as a quoted field of a line shaped like patina's own
//   `PATINA_INFRA` marker (a near-miss head, then the exact `native_run`
//   head). The guest wrote it, so it is evidence like any other guest line.
// * `det-segv-unterminated`: die on SIGSEGV writing to address 1, a fault
//   that happens the same way on every run, after writing a stderr line with
//   no trailing newline, so patina's own line follows unfinished guest output.
// * `forge-divergence`: report a fixed violation, then leave a custom
//   operation open under a label that spells a replay divergence, and print
//   the structured token too. Deterministic: every word of it is the guest's,
//   and a guest cannot claim a divergence its own run did not have.
// * `leak-clean`: pass, after a thread and its peer each yield a leaked
//   number of times. Two runnable threads make every yield a
//   recorded scheduling decision, so a leaked count reaches the trace.
// * `leak-schedule`: report a violation first, under a label drawn from
//   patina's seeded entropy (so each seed is its own signature), then yield a
//   leaked number of times. The verdict reproduces; the schedule after it does
//   not, so a replay of the trace diverges.

unsafe extern "C" {
    fn patina_verdict(
        kind: u32,
        label: *const u8,
        label_len: usize,
        detail: *const u8,
        detail_len: usize,
    ) -> i32;
    fn patina_custom_op_begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32;
}

const VIOLATION: u32 = 1;

fn verdict(kind: u32, label: &str, detail: &str) {
    unsafe {
        patina_verdict(kind, label.as_ptr(), label.len(), detail.as_ptr(), detail.len());
    }
}

fn address_bits() -> usize {
    let local = 0u8;
    (std::hint::black_box(&local) as *const u8 as usize) >> 4
}

fn token(mut bits: usize) -> String {
    (0..6)
        .map(|_| {
            let letter = (b'a' + (bits % 26) as u8) as char;
            bits /= 26;
            letter
        })
        .collect()
}

fn seeded_label() -> String {
    let mut bytes = [0u8; 2];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .unwrap();
    format!("broken-{}", token(usize::from(u16::from_le_bytes(bytes))))
}

// Each thread yields its own leaked count, so the schedule carries a pair of
// numbers below 997: two runs agree on it by chance about once in a million,
// where a single count would agree about once in a thousand runs.
fn yield_alongside_a_peer() {
    let bits = address_bits();
    let (own_yields, peer_yields) = (bits % 997 + 1, bits / 997 % 997 + 1);
    let peer = std::thread::spawn(move || {
        for _ in 0..peer_yields {
            std::thread::yield_now();
        }
    });
    for _ in 0..own_yields {
        std::thread::yield_now();
    }
    peer.join().unwrap();
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "det-exit" => {
            eprintln!("ADDRESS_LEAK failure token={}", token(0));
            std::process::exit(3);
        }
        "leak-number-exit" => {
            eprintln!("ADDRESS_LEAK failure token={}", address_bits());
            std::process::exit(3);
        }
        "forge-divergence" => {
            verdict(VIOLATION, "forged", "");
            eprintln!("replay_divergence=unconsumed_events");
            let label = "replay consumed 0 of 1 trace events";
            let mut len = 0usize;
            unsafe {
                patina_custom_op_begin(label.as_ptr(), label.len(), [].as_ptr(), 0, 0, &mut len);
            }
        }
        "forge-marker" => {
            eprintln!("PATINA_INFRASTRUCTURE failure detail=\"{}\"", address_bits());
            std::process::exit(3);
        }
        "forge-native-run" => {
            eprintln!(
                "PATINA_INFRA native_run trace=incomplete reason=\"{}\"",
                address_bits()
            );
            std::process::exit(3);
        }
        "det-segv-unterminated" => {
            eprint!("guest fatal");
            unsafe { std::ptr::write_volatile(1 as *mut u8, 0) }
        }
        "leak-clean" => {
            yield_alongside_a_peer();
            println!("ADDRESS_LEAK clean");
        }
        "leak-schedule" => {
            verdict(VIOLATION, &seeded_label(), "");
            yield_alongside_a_peer();
        }
        other => panic!("unknown mode {other:?}"),
    }
}
