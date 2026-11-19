//! Nodes: several machines in one run. Node 0 is the driver (the command after `--`); the
//! nodes a run declares (`[node.NAME]`) are 1 upward, in declaration order. Every node has its
//! own view of the sandbox (work tree, `/tmp`, `/dev/shm`, hostname, IPC), its own port space
//! and the address `10.0.0.(node + 1)`; one supervisor, clock, log and seed serve them all.
//!
//! The node table sits in the control region after the instruction scans: the launcher writes
//! it before the run, the runtime reads it to parse a control call's words and to know which
//! addresses exist. A run without nodes has `n == 0` and nothing here is consulted.
//!
//! A control call (`sdk::OP_CONTROL`) carries words; the grammar (also in `sdk/c/patina.h`):
//!
//! ```text
//! net cut A B                  both directions between the sets A and B
//! net cut --from A --to B      one direction: what A sends to B is held
//! net heal                     every scripted cut
//! net heal A B                 both directions between A and B
//! net heal --from A --to B     one direction
//! mark LABEL                   the SDK's mark (any node)
//! ```
//!
//! A set is node names joined by commas, or `rest`: every node not in the other set. Only the
//! driver's node may use `net` (elsewhere `EPERM`); an unknown name is `ENOENT`, other words
//! `EINVAL`, and words of a later feature (`node ...`, `clock ...`) `EOPNOTSUPP`.

/// The driver and at most 15 nodes.
pub const MAX_NODES: usize = 16;
/// The longest node name.
pub const NAME_MAX: usize = 32;
/// The driver's name in a run with nodes (its hostname; without nodes the hostname is `sim`).
pub const DRIVER: &[u8] = b"driver";
/// Names a node cannot have besides `DRIVER`, and why.
pub const RESERVED: &[(&[u8], &str)] = &[
    (b"rest", "a control call's word for every other node"),
    (b"localhost", "the loopback name in /etc/hosts"),
    (b"sim", "the hostname of a run without nodes"),
];

#[repr(C)]
pub struct NodeTab {
    /// Nodes, the driver included (0: a run without nodes).
    pub n: u64,
    pub name_len: [u64; MAX_NODES],
    pub names: [[u8; NAME_MAX]; MAX_NODES],
    /// Written by the supervisor: each node's first process (0: not started), and how it
    /// ended: `RUNNING`, or the status word (`(code & 0xff) << 8`, or the signal).
    pub first_pid: [u64; MAX_NODES],
    pub status: [u64; MAX_NODES],
    /// Scripted `net cut` and `net heal` calls served, and the links cut at the end (bit
    /// `to` of `cut_at_end[from]`).
    pub cuts: u64,
    pub heals: u64,
    pub cut_at_end: [u64; MAX_NODES],
    /// Connection directions a cut held (each counted once per hold).
    pub held: u64,
    /// The seed's partitions (`partition-*`), in order: how many were drawn, and the first
    /// `PARTS_MAX` of them.
    pub parts_n: u64,
    pub parts: [Part; PARTS_MAX],
    /// Partitions that acted on traffic, listed or not.
    pub parts_acted: u64,
    /// The link faults' chances on the links they act on (`net-links`), by `ELIG_*`: what a
    /// run with nodes reports as their eligible counts.
    pub elig: [u64; ELIG_N],
}

/// `NodeTab::elig`: connections, deliveries, FINs, reads of sent data, datagrams.
pub const ELIG_CONNECTIONS: usize = 0;
pub const ELIG_CHUNKS: usize = 1;
pub const ELIG_FINS: usize = 2;
pub const ELIG_SENDS: usize = 3;
pub const ELIG_DATAGRAMS: usize = 4;
pub const ELIG_N: usize = 5;

/// Partitions `NodeTab::parts` keeps (later ones are counted, not listed).
pub const PARTS_MAX: usize = 64;

/// One partition the seed drew.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Part {
    /// Its ordinal (1 upward), its shape (`SHAPE_*`), and its two sides (node bits).
    pub n: u64,
    pub shape: u64,
    pub a: u64,
    pub b: u64,
    /// Virtual time it started and ended (`to_ns` 0: in force when the run ended).
    pub from_ns: u64,
    pub to_ns: u64,
    /// Whether a cut link of it held or lost traffic, or kept a connect from completing.
    pub acted: u64,
    /// A bridge's node, which keeps its links to both sides.
    pub bridge: u64,
}

/// Partition shapes (`partition-shape`), as bits of `NetCfg::part_shapes`. Each cuts the links
/// between two sides A and B of the faultable nodes: `split` both ways, `isolate` one node (A)
/// from all the others both ways, `oneway` only from A to B, and `bridge` both ways but for
/// one node of B that still reaches both sides.
pub const SHAPE_SPLIT: u64 = 1;
pub const SHAPE_ISOLATE: u64 = 2;
pub const SHAPE_ONEWAY: u64 = 3;
pub const SHAPE_BRIDGE: u64 = 4;
pub const SHAPES: [(u64, &str); 4] = [
    (SHAPE_SPLIT, "split"),
    (SHAPE_ISOLATE, "isolate"),
    (SHAPE_ONEWAY, "oneway"),
    (SHAPE_BRIDGE, "bridge"),
];

pub fn shape_name(s: u64) -> &'static str {
    SHAPES.iter().find(|x| x.0 == s).map_or("unknown", |x| x.1)
}

/// The fewest faultable nodes a shape needs (a bridge needs one node besides two sides).
pub const fn shape_min_nodes(s: u64) -> usize {
    if s == SHAPE_BRIDGE {
        3
    } else {
        2
    }
}

/// Sub-keys of `draw(Stream::Partition, ordinal << 16 | sub << 8 | i)`.
pub const PSUB_GAP: u64 = 1;
pub const PSUB_LEN: u64 = 2;
pub const PSUB_SHAPE: u64 = 3;
/// The shuffle of the faultable nodes that makes the sides (`i`: the position).
pub const PSUB_ORDER: u64 = 4;
/// How many nodes side A gets.
pub const PSUB_SIZE: u64 = 5;

/// The sides of a partition: from `nodes` (the faultable ones, in order) and a draw function
/// `d(sub, i)`, the shape's (A, B, bridge) node bit sets; `None` when the nodes are too few.
/// `isolate` puts one node in A; `bridge` takes one node out of B, which keeps both sides.
pub fn sides(shape: u64, nodes: &[usize], d: impl Fn(u64, u64) -> u64) -> Option<(u64, u64, u64)> {
    let n = nodes.len();
    if n < shape_min_nodes(shape) || n > MAX_NODES {
        return None;
    }
    // A keyed Fisher-Yates shuffle: position i draws among the ones not yet placed.
    let mut order = [0usize; MAX_NODES];
    order[..n].copy_from_slice(nodes);
    for i in (1..n).rev() {
        let j = (d(PSUB_ORDER, i as u64) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let order = &order[..n];
    let (bridge, rest) = if shape == SHAPE_BRIDGE {
        (Some(order[n - 1]), &order[..n - 1])
    } else {
        (None, order)
    };
    let m = rest.len();
    let size = if shape == SHAPE_ISOLATE {
        1
    } else {
        1 + (d(PSUB_SIZE, 0) % (m as u64 - 1)) as usize
    };
    let bits = |s: &[usize]| s.iter().fold(0u64, |b, &k| b | 1 << k);
    Some((
        bits(&rest[..size]),
        bits(&rest[size..]),
        bridge.map_or(0, |k| 1 << k),
    ))
}

/// `NodeTab::status` of a node whose first process had not ended when the run did.
pub const RUNNING: u64 = u64::MAX;

pub const NODE_TAB_OFFSET: usize =
    (crate::ctl::SCAN_TAB_OFFSET + crate::ctl::SCAN_TAB_SIZE + 0xFFF) & !0xFFF;
pub const NODE_TAB_SIZE: usize = core::mem::size_of::<NodeTab>();

impl NodeTab {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut NodeTab {
        &mut *(ctl_base.add(NODE_TAB_OFFSET) as *mut NodeTab)
    }

    pub fn count(&self) -> usize {
        (self.n as usize).min(MAX_NODES)
    }

    pub fn name(&self, i: usize) -> &[u8] {
        &self.names[i][..(self.name_len[i] as usize).min(NAME_MAX)]
    }

    /// Set the table (the launcher): `names[0]` is the driver's.
    pub fn set<'a>(&mut self, names: impl Iterator<Item = &'a [u8]>) {
        let mut n = 0;
        for (i, nm) in names.take(MAX_NODES).enumerate() {
            let k = nm.len().min(NAME_MAX);
            self.names[i] = [0; NAME_MAX];
            self.names[i][..k].copy_from_slice(&nm[..k]);
            self.name_len[i] = k as u64;
            n = i + 1;
        }
        self.n = n as u64;
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        (0..self.count()).find(|&i| self.name(i) == name)
    }
}

/// Is `s` a node name: 1 to `NAME_MAX` letters, digits and `-`, starting with a letter.
pub fn valid_name(s: &[u8]) -> bool {
    (1..=NAME_MAX).contains(&s.len())
        && s[0].is_ascii_alphabetic()
        && s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// `Op::Net` verbs.
pub const NET_CUT: u64 = 1;
pub const NET_HEAL: u64 = 2;

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EINVAL: i64 = 22;
const EOPNOTSUPP: i64 = 95;

/// A parsed control call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control<'a> {
    /// `NET_CUT` or `NET_HEAL` from the nodes of `from` to those of `to` (bit sets), and
    /// back when `both`. A heal with both sets empty heals every scripted cut.
    Net {
        verb: u64,
        from: u64,
        to: u64,
        both: bool,
    },
    Mark(&'a [u8]),
}

/// Why a control call is refused: the errno (positive) and a reason for `patina ctl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub errno: i64,
    pub why: &'static str,
}

const fn no(errno: i64, why: &'static str) -> Refusal {
    Refusal { errno, why }
}

/// The words of a control call, from a process of node `node`.
pub fn parse<'a>(text: &'a [u8], tab: &NodeTab, node: usize) -> Result<Control<'a>, Refusal> {
    let mut w = [&[][..]; 8];
    let mut n = 0;
    for x in text
        .split(|c| c.is_ascii_whitespace())
        .filter(|x| !x.is_empty())
    {
        if n == w.len() {
            return Err(no(EINVAL, "too many words"));
        }
        w[n] = x;
        n += 1;
    }
    let w = &w[..n];
    match w {
        [b"mark", label] if label.len() <= crate::sdk::LABEL_MAX => Ok(Control::Mark(label)),
        [b"mark", ..] => Err(no(EINVAL, "expected: mark LABEL")),
        [b"net", rest @ ..] => {
            let (verb, rest) = match rest {
                [b"cut", r @ ..] => (NET_CUT, r),
                [b"heal", r @ ..] => (NET_HEAL, r),
                _ => return Err(no(EINVAL, "expected: net cut ... or net heal ...")),
            };
            if tab.count() == 0 {
                return Err(no(EINVAL, "net: the run has no nodes"));
            }
            if node != 0 {
                return Err(no(
                    EPERM,
                    "net: only the driver's node may act on the network",
                ));
            }
            let (a, b, both) = match rest {
                [] if verb == NET_HEAL => {
                    return Ok(Control::Net {
                        verb,
                        from: 0,
                        to: 0,
                        both: true,
                    })
                }
                [b"--from", a, b"--to", b] => (*a, *b, false),
                [a, b] if !a.starts_with(b"-") && !b.starts_with(b"-") => (*a, *b, true),
                _ => {
                    return Err(no(
                        EINVAL,
                        "expected: net cut|heal A B, or net cut|heal --from A --to B",
                    ))
                }
            };
            let from = set(a, tab, None)?;
            let to = set(b, tab, Some(from))?;
            let from = if a == b"rest" {
                set(a, tab, Some(to))?
            } else {
                from
            };
            if from == 0 || to == 0 {
                return Err(no(EINVAL, "net: a set names no node"));
            }
            Ok(Control::Net {
                verb,
                from,
                to,
                both,
            })
        }
        [b"node", ..] => Err(no(
            EOPNOTSUPP,
            "node: not available yet (node crash, restart and pause come later)",
        )),
        [b"clock", ..] => Err(no(
            EOPNOTSUPP,
            "clock: not available yet (per-node clocks come later)",
        )),
        _ => Err(no(EINVAL, "expected: net ..., or mark LABEL")),
    }
}

/// A set of nodes: names joined by commas, or `rest` (every node not in `other`; `None` while
/// the other side is not known yet, which answers 0).
fn set(s: &[u8], tab: &NodeTab, other: Option<u64>) -> Result<u64, Refusal> {
    let all = (1u64 << tab.count()) - 1;
    if s == b"rest" {
        return Ok(other.map_or(0, |o| all & !o));
    }
    let mut m = 0u64;
    for name in s.split(|&c| c == b',') {
        if name == b"rest" {
            return Err(no(EINVAL, "net: rest stands alone"));
        }
        match tab.find(name) {
            Some(i) => m |= 1 << i,
            None if valid_name(name) => return Err(no(ENOENT, "net: no node of that name")),
            None => return Err(no(EINVAL, "net: not a node name")),
        }
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(names: &[&str]) -> NodeTab {
        let mut t = NodeTab {
            n: 0,
            name_len: [0; MAX_NODES],
            names: [[0; NAME_MAX]; MAX_NODES],
            first_pid: [0; MAX_NODES],
            status: [0; MAX_NODES],
            cuts: 0,
            heals: 0,
            cut_at_end: [0; MAX_NODES],
            held: 0,
            parts_n: 0,
            parts: [Part::default(); PARTS_MAX],
            parts_acted: 0,
            elig: [0; ELIG_N],
        };
        t.set(names.iter().map(|n| n.as_bytes()));
        t
    }

    #[test]
    fn words_name_sets_of_nodes() {
        let t = tab(&["driver", "a", "b", "c"]);
        let net = |verb, from, to, both| {
            Ok(Control::Net {
                verb,
                from,
                to,
                both,
            })
        };
        assert_eq!(
            parse(b"net cut a b", &t, 0),
            net(NET_CUT, 0b10, 0b100, true)
        );
        assert_eq!(
            parse(b"  net  cut --from a,b --to driver\n", &t, 0),
            net(NET_CUT, 0b110, 0b1, false)
        );
        // `rest` is every node the other side does not name, on either side.
        assert_eq!(
            parse(b"net cut a rest", &t, 0),
            net(NET_CUT, 0b10, 0b1101, true)
        );
        assert_eq!(
            parse(b"net cut rest a", &t, 0),
            net(NET_CUT, 0b1101, 0b10, true)
        );
        assert_eq!(parse(b"net heal", &t, 0), net(NET_HEAL, 0, 0, true));
        assert_eq!(
            parse(b"net heal c b", &t, 0),
            net(NET_HEAL, 0b1000, 0b100, true)
        );
        assert_eq!(
            parse(b"mark setup-complete", &t, 2),
            Ok(Control::Mark(b"setup-complete"))
        );
    }

    #[test]
    fn refusals_name_their_errno() {
        let t = tab(&["driver", "a", "b"]);
        let errno = |w: &[u8], node| parse(w, &t, node).unwrap_err().errno;
        assert_eq!(errno(b"net cut a b", 1), EPERM);
        assert_eq!(errno(b"net cut a zed", 0), ENOENT);
        for bad in [
            &b"net cut a"[..],
            b"net cut a,,b driver",
            b"net cut rest rest",
            b"net cut --to a --from b",
            b"net cut a b c",
            b"net",
            b"cut a b",
            b"",
            b"net cut a_b driver",
            b"net cut rest,a b",
        ] {
            assert_eq!(errno(bad, 0), EINVAL, "{bad:?}");
        }
        assert_eq!(errno(b"node kill a", 0), EOPNOTSUPP);
        assert_eq!(errno(b"clock step a +90s", 0), EOPNOTSUPP);
        // Without nodes there is no network to act on; a mark still works.
        let none = tab(&[]);
        assert_eq!(parse(b"net heal", &none, 0).unwrap_err().errno, EINVAL);
        assert!(parse(b"mark m", &none, 0).is_ok());
    }

    #[test]
    fn sides_are_never_empty_and_follow_the_draws() {
        let nodes = [1, 2, 3, 4];
        for shape in [SHAPE_SPLIT, SHAPE_ISOLATE, SHAPE_ONEWAY, SHAPE_BRIDGE] {
            let (mut seen, mut ns) = ([(0u64, 0u64); 64], 0);
            for seed in 0..64u64 {
                let d = |sub: u64, i: u64| crate::draw::mix64(seed << 16 | sub << 8 | i);
                let (a, b, x) = sides(shape, &nodes, d).unwrap();
                assert!(
                    a != 0 && b != 0 && a & b == 0 && (a | b) & x == 0,
                    "{shape} {seed}"
                );
                assert_eq!(a | b | x, 0b11110);
                if shape == SHAPE_ISOLATE {
                    assert_eq!(a.count_ones(), 1);
                }
                assert_eq!((x != 0), shape == SHAPE_BRIDGE);
                assert_eq!(sides(shape, &nodes, d), Some((a, b, x)));
                if !seen[..ns].contains(&(a, b)) {
                    seen[ns] = (a, b);
                    ns += 1;
                }
            }
            assert!(ns > 3, "{shape}: {ns}");
        }
        let d = |_: u64, _: u64| 0;
        assert_eq!(sides(SHAPE_BRIDGE, &[1, 2], d), None);
        assert_eq!(sides(SHAPE_SPLIT, &[1], d), None);
        assert!(sides(SHAPE_SPLIT, &[0, 1], d).is_some());
    }

    #[test]
    fn names_are_letters_digits_and_dashes() {
        for ok in ["a", "db-1", "Primary"] {
            assert!(valid_name(ok.as_bytes()), "{ok}");
        }
        for bad in ["", "1a", "-a", "a_b", "a.b", &"x".repeat(NAME_MAX + 1)] {
            assert!(!valid_name(bad.as_bytes()), "{bad}");
        }
    }
}
