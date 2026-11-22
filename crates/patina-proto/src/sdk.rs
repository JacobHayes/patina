//! The SDK channel: one reserved system call through which a guest states assertions, asks
//! fault-point decisions and marks points of its run. Shared by the runtime (which answers it
//! under the turn), the launcher (which configures it and reads the site table) and, as the
//! reference, every language binding (`sdk/c/patina.h`).
//!
//! ```text
//! long r = syscall(SYSCALL, op, ptr, len);
//! ```
//!
//! Outside Patina the kernel answers `ENOSYS` (a container's filter may answer `EPERM`); an SDK
//! treats any error from its first call (`HELLO`) as "not under Patina" and stays inert.
//!
//! `ptr`/`len` name one little-endian payload: a fixed `HDR_LEN`-byte header, then the label,
//! then the text (an assertion's detail, a declaration's source location):
//!
//! ```text
//! 0   u8   kind        KIND_*
//! 1   u8   cond        ASSERT: 1 if the condition held (ignored for UNREACHABLE: it fails)
//! 2   u16  label_len   1..=LABEL_MAX
//! 4   u32  text_len    0..=TEXT_MAX
//! 8   i64  a           BUGGIFY: permille or -1 (run default); KNOB: default, and the answer
//!                      on return; DELAY: largest delay in ns (0: the run default)
//! 16  i64  b           KNOB: low
//! 24  i64  c           KNOB: high
//! 32  label bytes, then text bytes; len = HDR_LEN + label_len + text_len
//! ```
//!
//! Two operations take no payload; they serve compute points (`crate::compute`): code rebuilt
//! with the compilers' coverage hooks and a hook file (`sdk/c/patina_compute.c`) counts its
//! events down in one guest word, the cell, and enters the runtime when it runs out.
//!
//! ```text
//! COMPUTE_HELLO  arg = COMPUTE_VERSION | kinds << 8 (COMPUTE_EDGE, _ACCESS, _COMPARE, _LINE)
//!                -> the cell's address (crate::layout::COMPUTE_CELL); any error: stay inert
//! COMPUTE_POINT  arg = 0; the cell reached 0 -> 0, the cell refilled
//! ```

use crate::draw::{draw, mix64, Stream};
use crate::rec::hash_bytes;

/// The reserved system call number: far above the kernel's table, no x32 bit (`0x4000_0000`).
pub const SYSCALL: u64 = 0x7061;
const _: () = assert!(SYSCALL & 0x4000_0000 == 0);

/// Protocol version, the low 16 bits of the `HELLO` answer.
pub const VERSION: u64 = 1;
/// `HELLO` answer bit: the run has `--faults buggify` (fault points may fire). Without it an SDK
/// answers every fault point locally (false, the default value) and never traps for one.
pub const HELLO_BUGGIFY: u64 = 1 << 16;

pub const OP_HELLO: u64 = 1;
pub const OP_ASSERT: u64 = 2;
pub const OP_BUGGIFY: u64 = 3;
pub const OP_KNOB: u64 = 4;
pub const OP_DELAY: u64 = 5;
pub const OP_MARK: u64 = 6;
pub const OP_DECLARE: u64 = 7;
/// Compute points: announce a hook copy and get the cell; and the cell ran out.
pub const OP_COMPUTE_HELLO: u64 = 8;
pub const OP_COMPUTE_POINT: u64 = 9;
/// `COMPUTE_HELLO`'s version (its low 8 bits); another version is `EINVAL`.
pub const COMPUTE_VERSION: u64 = 1;
/// `COMPUTE_HELLO`'s event kinds (bits 8..16 of its argument): what the hook copy can count.
pub const COMPUTE_EDGE: u64 = 1;
pub const COMPUTE_ACCESS: u64 = 2;
pub const COMPUTE_COMPARE: u64 = 4;
/// An interpreter's lines and jumps (`sdk/python/patina.py`). Its hook runs in the program
/// that interprets, through libc, so the image noted is the program, not the image at the call.
pub const COMPUTE_LINE: u64 = 8;
pub const COMPUTE_KINDS: u64 = COMPUTE_EDGE | COMPUTE_ACCESS | COMPUTE_COMPARE | COMPUTE_LINE;
/// A control call (`crate::machine` has the grammar): `ptr`/`len` name the words alone, no
/// header, 1 to `TEXT_MAX` bytes. Answers 0 or -errno; the trap record's strings are the label
/// `control` and the words.
pub const OP_CONTROL: u64 = 10;
/// The label a control call's words are logged under.
pub const CONTROL_LABEL: &[u8] = b"control";

pub const KIND_ALWAYS: u8 = 1;
pub const KIND_SOMETIMES: u8 = 2;
pub const KIND_REACHABLE: u8 = 3;
pub const KIND_BUGGIFY: u8 = 4;
pub const KIND_KNOB: u8 = 5;
pub const KIND_DELAY: u8 = 6;
/// A point that must not be reached (`unreachable!`): reaching it is a failed `always`; never
/// reaching it is what it says, so a report does not list it as unmet.
pub const KIND_UNREACHABLE: u8 = 7;

/// `BUGGIFY` and `DELAY` answers: 0 no, 1 fire, `NEVER` no, and this point never fires in this
/// run (inactive, or forced off): the SDK may stop asking for it in this process.
pub const NEVER: i64 = 2;

pub const HDR_LEN: usize = 32;
pub const LABEL_MAX: usize = 255;
pub const TEXT_MAX: usize = 4096;

pub fn kind_name(k: u8) -> &'static str {
    match k {
        KIND_ALWAYS => "always",
        KIND_SOMETIMES => "sometimes",
        KIND_REACHABLE => "reachable",
        KIND_BUGGIFY => "buggify",
        KIND_KNOB => "knob",
        KIND_DELAY => "delay",
        KIND_UNREACHABLE => "unreachable",
        _ => "?",
    }
}

/// A decoded payload header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hdr {
    pub kind: u8,
    pub cond: u8,
    pub label_len: usize,
    pub text_len: usize,
    pub a: i64,
    pub b: i64,
    pub c: i64,
}

impl Hdr {
    /// Decode and check a header against the payload length: `None` is `EINVAL`.
    pub fn parse(b: &[u8], len: usize) -> Option<Hdr> {
        if b.len() < HDR_LEN {
            return None;
        }
        let w = |i: usize| i64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let h = Hdr {
            kind: b[0],
            cond: b[1],
            label_len: u16::from_le_bytes([b[2], b[3]]) as usize,
            text_len: u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize,
            a: w(8),
            b: w(16),
            c: w(24),
        };
        let ok = (1..=LABEL_MAX).contains(&h.label_len)
            && h.text_len <= TEXT_MAX
            && HDR_LEN + h.label_len + h.text_len == len
            && (KIND_ALWAYS..=KIND_UNREACHABLE).contains(&h.kind);
        ok.then_some(h)
    }
}

/// The identity of a label, as decisions and `buggify:LABEL` overrides key it.
pub fn label_hash(label: &[u8]) -> u64 {
    hash_bytes(0x7061_6c61_6265_6c00, label)
}

/// Domains of the keyed draws, so a point's activation, firing, knob value and delay never
/// correlate.
pub const D_ACTIVE: u64 = 1;
pub const D_FIRE: u64 = 2;
pub const D_KNOB: u64 = 3;
pub const D_DELAY: u64 = 4;

/// `draw(seed, hash(label), n)`: a point's `n`-th decision depends on nothing but the seed,
/// its label and `n`, so adding or removing another point moves none of its decisions.
pub fn point_draw(seed: u64, label: u64, domain: u64, n: u64) -> u64 {
    draw(
        seed ^ mix64(label ^ domain.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        Stream::Sdk,
        n,
    )
}

/// The old engine's defaults (FoundationDB's): a point is active in a quarter of runs, and an
/// active point fires on a quarter of its evaluations.
pub const ACTIVATION_PERMILLE: u64 = 250;
pub const FIRE_PERMILLE: u64 = 250;
/// `delay` without a caller's bound: a seeded delay in [1 ms, 5 s].
pub const DELAY_MIN_NS: u64 = 1_000_000;
pub const DELAY_MAX_NS: u64 = 5_000_000_000;

/// `--fault buggify:LABEL=PERMILLE` overrides, at most this many.
pub const MAX_POINTS: usize = 32;

/// `SdkCfg::buggify`: no fault point fires; every point may (the `buggify` class); only the
/// points `buggify:LABEL=P` names (the key without the class).
pub const BUGGIFY_OFF: u64 = 0;
pub const BUGGIFY_ALL: u64 = 1;
pub const BUGGIFY_NAMED: u64 = 2;

/// One machine's fault-point settings, written by the launcher before the run; read-only
/// afterwards. Main's (and a run without machines') is `SdkTab::cfg`, a machine's
/// `machine::MachineTab::sdk`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdkCfg {
    /// `BUGGIFY_*`.
    pub buggify: u64,
    /// The machine's seed: the run's, or a machine's own, so each machine draws its own decisions.
    pub seed: u64,
    /// Boot: firing draws are fresh after a restart; activation and knobs are per run.
    pub boot: u64,
    pub npoints: u64,
    /// (label hash, permille): the point is active and fires at this rate (0: never).
    pub points: [[u64; 2]; MAX_POINTS],
}

impl Default for SdkCfg {
    fn default() -> SdkCfg {
        SdkCfg {
            buggify: BUGGIFY_OFF,
            seed: 0,
            boot: 0,
            npoints: 0,
            points: [[0; 2]; MAX_POINTS],
        }
    }
}

impl SdkCfg {
    fn point(&self, label: u64) -> Option<u64> {
        self.points[..(self.npoints as usize).min(MAX_POINTS)]
            .iter()
            .find(|p| p[0] == label)
            .map(|p| p[1])
    }
    /// The firing rate of a point for this run, or `None` if it never fires
    /// (no `--faults buggify`, inactive, or forced off).
    pub fn rate(&self, label: u64, asked: i64) -> Option<u64> {
        if self.buggify == BUGGIFY_OFF {
            return None;
        }
        let r = match self.point(label) {
            Some(p) => p,
            None if self.buggify == BUGGIFY_NAMED => return None,
            None => {
                if point_draw(self.seed, label, D_ACTIVE, 0) % 1000 >= ACTIVATION_PERMILLE {
                    return None;
                }
                if asked >= 0 {
                    (asked as u64).min(1000)
                } else {
                    FIRE_PERMILLE
                }
            }
        };
        (r > 0).then_some(r)
    }
    /// Does the `n`-th evaluation of a point fire at `rate`?
    pub fn fires(&self, label: u64, rate: u64, n: u64) -> bool {
        let n = n ^ self.boot.wrapping_mul(0x2545_f491_4f6c_dd1d);
        point_draw(self.seed, label, D_FIRE, n) % 1000 < rate
    }
    /// A knob's value for this run: `default` unless the point is active.
    pub fn knob(&self, label: u64, default: i64, lo: i64, hi: i64) -> i64 {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        if self.rate(label, -1).is_none() {
            return default;
        }
        let span = (hi as i128 - lo as i128 + 1) as u128;
        let d = point_draw(self.seed, label, D_KNOB, 0) as u128;
        (lo as i128 + (d % span) as i128) as i64
    }
    /// The length of the `n`-th delay of a point, at most `max` (0: the default range).
    pub fn delay_ns(&self, label: u64, n: u64, max: u64) -> u64 {
        let (lo, hi) = if max == 0 {
            (DELAY_MIN_NS, DELAY_MAX_NS)
        } else {
            (1, max)
        };
        let n = n ^ self.boot.wrapping_mul(0x2545_f491_4f6c_dd1d);
        lo + point_draw(self.seed, label, D_DELAY, n) % (hi - lo + 1)
    }
}

pub const MAX_SITES: usize = 4096;
const NBUCKET: usize = 8192;
pub const LOC_MAX: usize = 120;

/// One site of the run: a (kind, label) pair. Counts are of reports, and an SDK reports a
/// passing assertion only the first time each process image evaluates it (and a `sometimes`
/// the first time it holds); fault points report every evaluation until they answer `NEVER`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Site {
    pub key: u64,
    pub label_hash: u64,
    pub kind: u8,
    pub label_len: u8,
    pub loc_len: u8,
    /// The machine whose fault point this is (0: main's, or a site every machine shares). In a
    /// run with machines a machine's fault points (`buggify`, `knob`, `delay`) are sites of its own,
    /// counted and drawn for that machine alone.
    pub machine: u8,
    pub _pad: [u8; 4],
    /// Reports (assertions), evaluations (fault points, knobs, delays).
    pub evaluated: u64,
    /// Reports in which the condition held, hits of a `reachable`, firings of a point or delay.
    pub held: u64,
    /// A knob's value.
    pub value: i64,
    pub label: [u8; 256],
    /// Source location, when declared (`file:line`).
    pub loc: [u8; LOC_MAX],
}

impl Site {
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }
    pub fn loc(&self) -> &[u8] {
        &self.loc[..self.loc_len as usize]
    }
}

/// The run's site table and violation, after the wire table in the control region.
#[repr(C)]
pub struct SdkTab {
    pub cfg: SdkCfg,
    pub nsites: u64,
    /// Sites not recorded because the table was full.
    pub dropped: u64,
    /// The failed `always`: `label: detail` (`violation_len` 0: none), the label's length.
    pub violation_label: u64,
    pub violation_len: u64,
    pub violation: [u8; LABEL_MAX + 2 + TEXT_MAX],
    index: [u16; NBUCKET],
    pub sites: [Site; MAX_SITES],
}

pub const SDK_OFFSET: usize = (crate::wire::WIRE_OFFSET + crate::wire::WIRE_SIZE + 0xFFF) & !0xFFF;
pub const SDK_SIZE: usize = core::mem::size_of::<SdkTab>();

fn site_key(kind: u8, label: u64, machine: u8) -> u64 {
    mix64(label ^ (kind as u64 | (machine as u64) << 8).wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1
}

/// Whether a kind's sites are each machine's own (fault points), not shared by the run.
pub fn per_machine(kind: u8) -> bool {
    matches!(kind, KIND_BUGGIFY | KIND_KNOB | KIND_DELAY)
}

impl SdkTab {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut SdkTab {
        &mut *(ctl_base.add(SDK_OFFSET) as *mut SdkTab)
    }

    /// The site of (kind, label), created on first use. `None` when the table is full.
    pub fn site(&mut self, kind: u8, label: &[u8]) -> Option<&mut Site> {
        self.site_on(kind, label, 0)
    }

    /// The site of (kind, label) on machine `machine` (a fault point's: `per_machine`; 0 otherwise).
    pub fn site_on(&mut self, kind: u8, label: &[u8], machine: u8) -> Option<&mut Site> {
        let machine = if per_machine(kind) { machine } else { 0 };
        let lh = label_hash(label);
        let key = site_key(kind, lh, machine);
        let mut b = (key as usize) % NBUCKET;
        loop {
            let i = self.index[b] as usize;
            if i == 0 {
                break;
            }
            let s = &self.sites[i - 1];
            if s.key == key && s.kind == kind && s.machine == machine && s.label() == label {
                return Some(&mut self.sites[i - 1]);
            }
            b = (b + 1) % NBUCKET;
        }
        let n = self.nsites as usize;
        if n >= MAX_SITES {
            self.dropped += 1;
            return None;
        }
        self.index[b] = n as u16 + 1;
        self.nsites += 1;
        let s = &mut self.sites[n];
        s.key = key;
        s.label_hash = lh;
        s.kind = kind;
        s.machine = machine;
        let l = label.len().min(LABEL_MAX);
        s.label_len = l as u8;
        s.label[..l].copy_from_slice(&label[..l]);
        Some(s)
    }

    /// Give a site its source location if it has none.
    pub fn locate(s: &mut Site, loc: &[u8]) {
        if s.loc_len == 0 && !loc.is_empty() {
            let n = loc.len().min(LOC_MAX);
            s.loc[..n].copy_from_slice(&loc[..n]);
            s.loc_len = n as u8;
        }
    }

    pub fn used(&self) -> &[Site] {
        &self.sites[..(self.nsites as usize).min(MAX_SITES)]
    }

    pub fn violation(&self) -> &[u8] {
        &self.violation[..(self.violation_len as usize).min(self.violation.len())]
    }

    /// The failed `always` as (label, detail).
    pub fn violation_parts(&self) -> Option<(&[u8], &[u8])> {
        let v = self.violation();
        if v.is_empty() {
            return None;
        }
        let l = (self.violation_label as usize).min(v.len());
        let rest = &v[l..];
        Some((&v[..l], rest.strip_prefix(b": ").unwrap_or(rest)))
    }
}

/// The ELF section a compiled SDK places its declarations in. A record is `MAGIC`, the kind,
/// the label length and the location length, then the label and the location: no pointers, so
/// it needs no relocation and is read from the file. Bytes between records that are not
/// `MAGIC` (alignment padding) are skipped.
pub const SECTION: &[u8] = b"patina_sites";
pub const MAGIC: u8 = 0xb7;

/// Every well-formed record in a `patina_sites` section: (kind, label, location).
pub fn records(mut b: &[u8]) -> impl Iterator<Item = (u8, &[u8], &[u8])> {
    core::iter::from_fn(move || loop {
        let i = b.iter().position(|&c| c == MAGIC)?;
        b = &b[i..];
        if b.len() < 4 {
            return None;
        }
        let (kind, ll, sl) = (b[1], b[2] as usize, b[3] as usize);
        if !(KIND_ALWAYS..=KIND_UNREACHABLE).contains(&kind) || ll == 0 {
            b = &b[1..];
            continue;
        }
        if b.len() < 4 + ll + sl {
            return None;
        }
        let rec = (kind, &b[4..4 + ll], &b[4 + ll..4 + ll + sl]);
        b = &b[4 + ll + sl..];
        return Some(rec);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_skip_padding_and_garbage() {
        let mut b = [0u8; 64];
        let r1 = [MAGIC, KIND_SOMETIMES, 3, 2, b'a', b'b', b'c', b'x', b'y'];
        b[1..10].copy_from_slice(&r1);
        let r2 = [MAGIC, KIND_ALWAYS, 1, 0, b'z'];
        b[16..21].copy_from_slice(&r2);
        let got: [(u8, &[u8], &[u8]); 2] = {
            let mut it = records(&b);
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!(got[0], (KIND_SOMETIMES, &b"abc"[..], &b"xy"[..]));
        assert_eq!(got[1], (KIND_ALWAYS, &b"z"[..], &b""[..]));
        assert_eq!(records(&b).count(), 2);
    }

    #[test]
    fn header_checks_lengths() {
        let mut b = [0u8; HDR_LEN + 3];
        b[0] = KIND_REACHABLE;
        b[2] = 3;
        assert!(Hdr::parse(&b, b.len()).is_some());
        assert!(Hdr::parse(&b, b.len() + 1).is_none());
        b[2] = 0;
        assert!(Hdr::parse(&b, HDR_LEN).is_none());
    }

    #[test]
    fn decisions_are_keyed_by_label() {
        let mut c = SdkCfg {
            buggify: BUGGIFY_ALL,
            seed: 7,
            npoints: 1,
            ..SdkCfg::default()
        };
        let (a, b) = (label_hash(b"a"), label_hash(b"b"));
        c.points[0] = [a, 1000];
        assert_eq!(c.rate(a, -1), Some(1000));
        assert!((0..50).all(|n| c.fires(a, 1000, n)));
        c.points[0] = [a, 0];
        assert_eq!(c.rate(a, -1), None);
        // Over many seeds, about a quarter of runs activate a point.
        let active = (0..4000)
            .filter(|s| SdkCfg { seed: *s, ..c }.rate(b, -1).is_some())
            .count();
        assert!((800..1200).contains(&active), "{active}");
        // A point the key names fires alone without the class.
        c.buggify = BUGGIFY_NAMED;
        c.points[0] = [a, 1000];
        assert_eq!(c.rate(a, -1), Some(1000));
        assert!((0..4000).all(|s| SdkCfg { seed: s, ..c }.rate(b, -1).is_none()));
        c.buggify = BUGGIFY_OFF;
        assert_eq!(c.rate(a, -1), None);
        assert_eq!(c.knob(b, 5, 1, 9), 5);
    }
}
