//! The invariant against small simulated programs: a probe that arrives at any step of a
//! thread's cycle decides the same, and a thread whose state changes is never found.

extern crate std;

use super::*;
use std::vec;
use std::vec::Vec;

/// A program state: the instruction index and the values the program keeps.
type State = (usize, [u64; 3]);

fn addr(s: &State) -> u64 {
    0x40_1000 + 4 * s.0 as u64
}

/// What a probe that arrives at `s` decides: the address and state it yields at and the
/// period, or None. The runtime's comparison: the state is the last check's, from the third
/// check of a candidate on.
fn probe(next: &dyn Fn(&State) -> State, mut s: State, retraces: u8) -> Option<(u64, State, u32)> {
    let (mut t, mut f) = (vec![0u64; TRACE_MAX], vec![0u32; TRACE_MAX]);
    let mut tr = Trace::new();
    tr.start(&mut t, &mut f, addr(&s), retraces);
    let mut prev: Option<State> = None;
    loop {
        s = next(&s);
        match tr.record(&mut t, &mut f, addr(&s)) {
            Step::Go => {}
            Step::Abort => return None,
            Step::Retrace => tr.restart(&mut t, &mut f, addr(&s)),
            Step::Check => {
                let equal = tr.checks > 1 && prev == Some(s);
                match tr.checked(equal) {
                    Checked::Found => return Some((addr(&s), s, tr.period)),
                    Checked::Again => prev = Some(s),
                    Checked::Rejected => prev = None,
                }
            }
        }
    }
}

/// The states from `s0` on, `n` of them.
fn run(next: &dyn Fn(&State) -> State, s0: State, n: usize) -> Vec<State> {
    let mut v = vec![s0];
    for _ in 1..n {
        let s = next(v.last().unwrap());
        v.push(s);
    }
    v
}

/// `while (!flag) for (i = 0; i < n; i++);` with `flag` never set: 0 tests the flag, 1 sets
/// `i`, 2-5 the inner loop (load, compare and branch out to 0, add, store and branch back).
fn nested(n: u64) -> impl Fn(&State) -> State {
    move |&(pc, v): &State| match pc {
        0 => (1, v),
        1 => (2, [0, v[1], v[2]]),
        2 => (3, v),
        3 if v[0] < n => (4, v),
        3 => (0, v),
        4 => (5, [v[0] + 1, v[1], v[2]]),
        _ => (2, v),
    }
}

/// Three loops deep, the innermost two bounded: `while (!flag) for (j < m) for (i < n);`.
fn nested3(m: u64, n: u64) -> impl Fn(&State) -> State {
    move |&(pc, v): &State| match pc {
        0 => (1, [v[0], 0, v[2]]),
        1 if v[1] < m => (2, [0, v[1], v[2]]),
        1 => (0, v),
        2 if v[0] < n => (3, [v[0] + 1, v[1], v[2]]),
        2 => (4, v),
        3 => (2, v),
        _ => (1, [v[0], v[1] + 1, v[2]]),
    }
}

/// A flag wait that calls the same function twice per pass: its addresses come round twice in
/// each period, from two return addresses (`v[2]`).
fn twice() -> impl Fn(&State) -> State {
    |&(pc, v): &State| match pc {
        0 => (10, [v[0], v[1], 1]),
        1 => (10, [v[0], v[1], 2]),
        2 => (0, v),
        10 | 11 => (pc + 1, v),
        _ => (v[2] as usize, v),
    }
}

/// `while (!flag) count++;` around a bounded inner loop: its state never comes back.
fn counting(n: u64) -> impl Fn(&State) -> State {
    let inner = nested(n);
    move |s: &State| {
        let (pc, mut v) = inner(s);
        if s.0 == 3 && pc == 0 {
            v[2] += 1;
        }
        (pc, v)
    }
}

/// The length of the cycle `s` is in.
fn cycle(next: &dyn Fn(&State) -> State, s: State) -> usize {
    let mut t = next(&s);
    let mut p = 1;
    while t != s {
        t = next(&t);
        p += 1;
        assert!(p <= 2 * TRACE_MAX, "no cycle");
    }
    p
}

/// Arrivals across the cycle from `s` (all of them in a short one) decide as the first does;
/// what it decided, and the cycle's length.
fn same_everywhere(
    next: &dyn Fn(&State) -> State,
    s: State,
    retraces: u8,
) -> (Option<(u64, State, u32)>, usize) {
    let p = cycle(next, s);
    let states = run(next, s, p);
    let first = probe(next, s, retraces);
    for k in (0..p).step_by(p.div_ceil(400)) {
        assert_eq!(
            probe(next, states[k], retraces),
            first,
            "arrival {k} of a cycle of {p}"
        );
    }
    (first, p)
}

/// A state of `next`'s cycle: `warm` steps from the start.
fn warm(next: &dyn Fn(&State) -> State, warm: usize) -> State {
    *run(next, (0, [0; 3]), warm + 1).last().unwrap()
}

#[test]
fn a_nested_spin_is_found_at_one_point_wherever_the_probe_arrives() {
    for retraces in [0, 8] {
        for n in [0, 1, 2, 7, 300, 2000] {
            let s = warm(&nested(n), 4 * n as usize + 8);
            let (r, p) = same_everywhere(&nested(n), s, retraces);
            assert_eq!(p, 4 * n as usize + 4);
            assert_eq!(r.map(|r| r.2 as usize), Some(p), "n {n}");
        }
        let s = warm(&nested3(5, 9), 200);
        let (r, p) = same_everywhere(&nested3(5, 9), s, retraces);
        assert_eq!(r.map(|r| r.2 as usize), Some(p), "three deep");
        let (r, p) = same_everywhere(&twice(), warm(&twice(), 20), retraces);
        assert_eq!(r.map(|r| r.2 as usize), Some(p), "a function called twice");
    }
}

#[test]
fn a_spin_whose_state_changes_is_never_found() {
    for retraces in [0, 8] {
        for n in [0, 3, 300] {
            let states = run(&counting(n), (0, [0; 3]), 8 * n as usize + 8);
            for (k, s) in states.iter().enumerate() {
                assert_eq!(
                    probe(&counting(n), *s, retraces),
                    None,
                    "n {n}, arrival {k}"
                );
            }
        }
    }
}

/// `while (!flag) x ^= 1;`: its addresses repeat every pass, its state every second pass.
fn toggling() -> impl Fn(&State) -> State {
    |&(pc, v): &State| match pc {
        0 => (1, v),
        _ => (0, [v[0] ^ 1, v[1], v[2]]),
    }
}

#[test]
fn a_state_that_comes_back_every_second_pass_is_never_found() {
    for retraces in [0, 8] {
        let s = warm(&toggling(), 4);
        let (r, _) = same_everywhere(&toggling(), s, retraces);
        assert_eq!(r, None);
    }
}

/// A wait around an exclusive pair: 0 checks the flag, 1-3 a delay, 4 is the pair, 5 retries it
/// when its store failed (`v[1]`). `v[2]` passes from now, the store fails once (as a host
/// interrupt makes it).
fn llsc() -> impl Fn(&State) -> State {
    |&(pc, v): &State| match pc {
        4 => {
            let fail = v[2] == 1;
            (5, [v[0], fail as u64, v[2].saturating_sub(1)])
        }
        5 if v[1] != 0 => (4, [v[0], 0, v[2]]),
        5 => (0, v),
        _ => (pc + 1, v),
    }
}

#[test]
fn a_store_that_fails_once_is_retraced_past() {
    let clean = probe(&llsc(), (0, [0; 3]), 8).expect("found");
    // The extra pass comes in the trace's first, second or third pass of the loop.
    for k in 1..=3 {
        for pc in 0..6 {
            assert_eq!(
                probe(&llsc(), (pc, [0, 0, k]), 8),
                Some(clean),
                "fails in pass {k}, arrival {pc}"
            );
        }
    }
}

#[test]
fn a_cycle_longer_than_the_limit_is_never_found() {
    // The longest found and the shortest not, each from arrivals across its cycle.
    let n = (PERIOD_MAX as u64 - 4) / 4;
    for (n, found) in [(n, true), (n + 1, false)] {
        let s = warm(&nested(n), 4 * n as usize + 8);
        let p = cycle(&nested(n), s);
        assert_eq!(p <= PERIOD_MAX, found);
        let states = run(&nested(n), s, p);
        for k in (0..p).step_by(p / 97) {
            assert_eq!(
                probe(&nested(n), states[k], 0).is_some(),
                found,
                "period {p}, arrival {k}"
            );
        }
    }
}

#[test]
fn a_probe_before_the_cycle_finds_it_or_nothing() {
    // 500 steps of counting down before the nested spin starts.
    let pre = |s: &State| match s.0 {
        100 if s.1[0] > 0 => (100, [s.1[0] - 1, 0, 0]),
        100 => (0, [0; 3]),
        _ => nested(40)(s),
    };
    let s0 = (100, [500, 0, 0]);
    let states = run(&pre, s0, 501 + 166);
    let inside = probe(&pre, states[600], 0).expect("found from inside the cycle");
    for (k, s) in states.iter().enumerate() {
        let r = probe(&pre, *s, 0);
        assert!(r.is_none() || r == Some(inside), "arrival {k}: {r:?}");
    }
}

#[test]
fn least_rotation_names_one_position() {
    let w = [5u64, 3, 9, 3, 1, 4];
    let r = least_rotation(&w);
    assert_eq!(w[r], 1);
    for k in 0..w.len() {
        let rot: Vec<u64> = (0..w.len()).map(|j| w[(j + k) % w.len()]).collect();
        let rk = least_rotation(&rot);
        assert_eq!(rot[rk], 1);
    }
}
