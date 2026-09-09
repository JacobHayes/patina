//! entropy/getrandom — getrandom: lengths, the flag vocabulary, and that two
//! draws differ (the bytes themselves are never recorded).

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        let (r, first) = p.getrandom(16, 0);
        p.check("getrandom fills 16 bytes", r == 16 && first.len() == 16);
        let (r, second) = p.getrandom(16, 0);
        p.check("two draws differ", r == 16 && first != second);
        let (r, _) = p.getrandom(0, 0);
        p.check("a zero-length draw returns 0", r == 0);
        let (r, _) = p.getrandom(16, GRND_NONBLOCK);
        p.check("GRND_NONBLOCK on a seeded pool fills", r == 16);
        let (r, _) = p.getrandom(16, GRND_RANDOM);
        p.check("GRND_RANDOM fills", r == 16);
        let (r, _) = p.getrandom(16, GRND_RANDOM | GRND_NONBLOCK);
        p.check("GRND_RANDOM|GRND_NONBLOCK fills", r == 16);
        let (r, _) = p.getrandom(16, 0x100);
        p.check("an unknown flag is EINVAL", r == neg(EINVAL));
        let (r, large) = p.getrandom(4096, 0);
        p.check(
            "a large draw is served in full",
            r == 4096 && large.iter().any(|&b| b != 0),
        );
    }
}

syscall_conformance::probe_main!("entropy/getrandom", scenario::run);
