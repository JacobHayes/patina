//! Materialiser rules as operation sequences and the set of legal results. No sandbox: logs
//! are built by hand.

use super::log::{Op, OpLog};
use super::materialise::{materialise, replay, Model, BLOCK};
use super::model_ext4;
use super::tree::Tree;
use proto::oplog::{OpKind, FSYNC_NO_COMMIT};
use std::collections::BTreeSet;

const ROOT: u64 = 1;
const MS: u64 = 1_000_000;
const SEEDS: u64 = 200;

struct B {
    ops: Vec<Op>,
    seq: u64,
    t: u64,
}

impl B {
    fn new() -> B {
        let mut b = B {
            ops: vec![],
            seq: 0,
            t: 0,
        };
        b.ops.push(Op::new(
            OpKind::Root,
            ROOT,
            [0o755, 1000, 1000, 0, 0, 0],
            vec![],
        ));
        b
    }
    /// A base file (seq 0: durable).
    fn base_file(&mut self, name: &str, ino: u64, data: &[u8]) -> &mut Self {
        self.ops.push(Op::new(
            OpKind::Create,
            ino,
            [ROOT, 0o644, 0o100000, 1, 0, 0],
            name.as_bytes().to_vec(),
        ));
        self.ops.push(Op::new(
            OpKind::Write,
            ino,
            [0, data.len() as u64, 1, 0, 0, 0],
            data.to_vec(),
        ));
        self
    }
    fn op(&mut self, kind: OpKind, ino: u64, a: [u64; 6], data: Vec<u8>) -> &mut Self {
        self.seq += 1;
        self.t += MS;
        let mut o = Op::new(kind, ino, a, data);
        o.seq = self.seq;
        o.vclock_ns = self.t;
        self.ops.push(o);
        self
    }
    fn at(&mut self, t: u64) -> &mut Self {
        self.t = t - MS;
        self
    }
    fn create(&mut self, parent: u64, name: &str, ino: u64) -> &mut Self {
        self.op(
            OpKind::Create,
            ino,
            [parent, 0o644, 0o100000, 0, 0, 0],
            name.as_bytes().to_vec(),
        )
    }
    fn mkdir(&mut self, parent: u64, name: &str, ino: u64) -> &mut Self {
        self.op(
            OpKind::Mkdir,
            ino,
            [parent, 0o755, 0, 0, 0, 0],
            name.as_bytes().to_vec(),
        )
    }
    fn write(&mut self, ino: u64, off: u64, d: &[u8]) -> &mut Self {
        self.op(
            OpKind::Write,
            ino,
            [off, d.len() as u64, 0, 0, 0, 0],
            d.to_vec(),
        )
    }
    fn fsync(&mut self, ino: u64) -> &mut Self {
        self.op(OpKind::Fsync, ino, [0; 6], vec![])
    }
    fn fsync_dir(&mut self, ino: u64) -> &mut Self {
        self.op(OpKind::FsyncDir, ino, [0; 6], vec![])
    }
    fn fail(&mut self, ino: u64) -> &mut Self {
        self.op(OpKind::FsyncFail, ino, [0; 6], vec![])
    }
    fn sync(&mut self) -> &mut Self {
        self.op(OpKind::Sync, 0, [0; 6], vec![])
    }
    fn link(&mut self, parent: u64, name: &str, ino: u64) -> &mut Self {
        self.op(
            OpKind::Link,
            ino,
            [parent, 0, 0, 0, 0, 0],
            name.as_bytes().to_vec(),
        )
    }
    fn unlink(&mut self, parent: u64, name: &str, ino: u64) -> &mut Self {
        self.op(
            OpKind::Unlink,
            ino,
            [parent, 0, 0, 0, 0, 0],
            name.as_bytes().to_vec(),
        )
    }
    fn rename(&mut self, old: &str, new: &str, ino: u64, replaced: u64) -> &mut Self {
        let data = [old.as_bytes(), new.as_bytes()].concat();
        self.op(
            OpKind::Rename,
            ino,
            [ROOT, ROOT, replaced, 0, old.len() as u64, 0],
            data,
        )
    }
    fn close(&mut self, ino: u64) -> &mut Self {
        self.op(OpKind::Close, ino, [0; 6], vec![])
    }
    fn truncate(&mut self, ino: u64, size: u64) -> &mut Self {
        self.op(OpKind::Truncate, ino, [size, 0, 0, 0, 0, 0], vec![])
    }
    fn crash(&mut self) -> OpLog {
        self.op(OpKind::Crash, 0, [1, 0, 0, 0, 0, 0], vec![]);
        OpLog {
            ops: self.ops.clone(),
        }
    }
}

fn mat(log: &OpLog, seed: u64, m: Model) -> Tree {
    materialise(log, u64::MAX, seed, 0, m).unwrap()
}

fn file(t: &Tree, p: &str) -> Option<Vec<u8>> {
    t.nodes.get(p.as_bytes()).map(|n| n.data.to_vec())
}

fn all(log: &OpLog, m: Model) -> Vec<Tree> {
    (0..SEEDS).map(|s| mat(log, s, m)).collect()
}

const BOTH: [Model; 2] = [Model::Ext4Ordered, Model::PosixStrict];

#[test]
fn ext4_uncommitted_create_is_absent() {
    let log = B::new()
        .create(ROOT, "a", 10)
        .write(10, 0, b"hello")
        .crash();
    let t = model_ext4::materialise_at(&log, None, 0, 0).unwrap();
    assert_eq!(file(&t, "a"), None);
    // Over seeds both outcomes are legal; the minimum is reached.
    let ts = all(&log, Model::Ext4Ordered);
    assert!(ts.iter().any(|t| file(t, "a").is_none()));
    assert!(ts
        .iter()
        .all(|t| matches!(file(t, "a").as_deref(), None | Some(b"") | Some(b"hello"))));
}

#[test]
fn posix_uncommitted_create_is_maybe() {
    let log = B::new().create(ROOT, "a", 10).crash();
    let ts = all(&log, Model::PosixStrict);
    assert!(ts.iter().any(|t| file(t, "a").is_none()));
    assert!(ts.iter().any(|t| file(t, "a").is_some()));
}

#[test]
fn ext4_committed_create_with_unsynced_data_is_empty() {
    // b's fsync commits the transaction, which holds a's creation but not a's data.
    let log = B::new()
        .create(ROOT, "a", 10)
        .write(10, 0, b"hello")
        .create(ROOT, "b", 11)
        .fsync(11)
        .crash();
    for t in all(&log, Model::Ext4Ordered) {
        assert_eq!(file(&t, "a").as_deref(), Some(&b""[..]));
        assert!(file(&t, "b").is_some());
    }
}

#[test]
fn fsync_makes_data_durable() {
    for m in BOTH {
        let log = B::new()
            .create(ROOT, "a", 10)
            .write(10, 0, b"hello")
            .fsync(10)
            .fsync_dir(ROOT)
            .crash();
        for t in all(&log, m) {
            assert_eq!(file(&t, "a").as_deref(), Some(&b"hello"[..]), "{m:?}");
        }
    }
}

#[test]
fn ext4_directory_needs_no_fsync() {
    let log = B::new()
        .create(ROOT, "a", 10)
        .write(10, 0, b"x")
        .fsync(10)
        .crash();
    for t in all(&log, Model::Ext4Ordered) {
        assert_eq!(file(&t, "a").as_deref(), Some(&b"x"[..]));
    }
}

#[test]
fn posix_directory_entry_needs_dir_fsync() {
    let log = B::new()
        .create(ROOT, "a", 10)
        .write(10, 0, b"x")
        .fsync(10)
        .crash();
    let ts = all(&log, Model::PosixStrict);
    assert!(
        ts.iter().any(|t| file(t, "a").is_none()),
        "entry without FsyncDir can be lost"
    );
    assert!(ts
        .iter()
        .all(|t| matches!(file(t, "a").as_deref(), None | Some(b"x"))));
    let log = B::new()
        .create(ROOT, "a", 10)
        .fsync_dir(ROOT)
        .write(10, 0, b"x")
        .fsync(10)
        .crash();
    for t in all(&log, Model::PosixStrict) {
        assert_eq!(file(&t, "a").as_deref(), Some(&b"x"[..]));
    }
}

#[test]
fn rename_is_atomic() {
    for m in BOTH {
        let log = B::new()
            .base_file("x", 10, b"A")
            .rename("x", "y", 10, 0)
            .crash();
        let ts = all(&log, m);
        let mut seen = BTreeSet::new();
        for t in &ts {
            let (x, y) = (file(t, "x"), file(t, "y"));
            assert!(x.is_some() != y.is_some(), "{m:?}: exactly one name");
            assert_eq!(x.or(y).as_deref(), Some(&b"A"[..]));
            seen.insert(file(t, "x").is_some());
        }
        assert_eq!(seen.len(), 2, "{m:?}: both outcomes reachable");
    }
}

#[test]
fn ext4_auto_da_alloc_on_rename_over() {
    // Write a new file, rename it over an existing name, without fsync of the new file; a
    // later commit (another file's fsync) carries the rename and the data.
    let log = B::new()
        .base_file("f", 10, b"old")
        .create(ROOT, "tmp", 11)
        .write(11, 0, b"new")
        .rename("tmp", "f", 11, 10)
        .create(ROOT, "other", 12)
        .fsync(12)
        .crash();
    for t in all(&log, Model::Ext4Ordered) {
        assert_eq!(file(&t, "f").as_deref(), Some(&b"new"[..]));
    }
    // The contrast: rename to a fresh name has no auto_da_alloc; the file comes back empty.
    let log = B::new()
        .create(ROOT, "tmp", 11)
        .write(11, 0, b"new")
        .rename("tmp", "g", 11, 0)
        .create(ROOT, "other", 12)
        .fsync(12)
        .crash();
    for t in all(&log, Model::Ext4Ordered) {
        assert_eq!(file(&t, "g").as_deref(), Some(&b""[..]));
    }
    // posix-strict promises nothing for the rename-over: the old contents can come back.
    let log = B::new()
        .base_file("f", 10, b"old")
        .create(ROOT, "tmp", 11)
        .write(11, 0, b"new")
        .rename("tmp", "f", 11, 10)
        .crash();
    let ts = all(&log, Model::PosixStrict);
    assert!(ts
        .iter()
        .any(|t| file(t, "f").as_deref() == Some(&b"old"[..])));
    assert!(
        ts.iter().all(|t| file(t, "f").is_some()),
        "never neither name"
    );
}

#[test]
fn ext4_auto_da_alloc_on_close_after_truncate_to_zero() {
    let log = B::new()
        .base_file("f", 10, b"old")
        .truncate(10, 0)
        .write(10, 0, b"new!")
        .close(10)
        .create(ROOT, "other", 12)
        .fsync(12)
        .crash();
    for t in all(&log, Model::Ext4Ordered) {
        assert_eq!(file(&t, "f").as_deref(), Some(&b"new!"[..]));
    }
}

#[test]
fn ext4_in_place_overwrite_tears_per_block() {
    let blocks = 4u64;
    let old = vec![b'a'; (blocks * BLOCK) as usize];
    let new = vec![b'b'; (blocks * BLOCK) as usize];
    let log = B::new().base_file("f", 10, &old).write(10, 0, &new).crash();
    let mut per_block: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); blocks as usize];
    for t in all(&log, Model::Ext4Ordered) {
        let d = file(&t, "f").unwrap();
        assert_eq!(d.len() as u64, blocks * BLOCK);
        for (b, chunk) in d.chunks(BLOCK as usize).enumerate() {
            assert!(
                chunk.iter().all(|&c| c == chunk[0]),
                "block {b} mixes old and new"
            );
            per_block[b].insert(chunk[0]);
        }
    }
    for (b, s) in per_block.iter().enumerate() {
        assert_eq!(s.len(), 2, "block {b}: both old and new reachable");
    }
}

#[test]
fn ext4_append_inside_last_block_shows_zeros() {
    // The size grows in the transaction at once; the data waits for writeback.
    let log = B::new()
        .base_file("f", 10, &[b'a'; 100])
        .write(10, 100, &[b'b'; 50])
        .create(ROOT, "other", 12)
        .fsync(12)
        .crash();
    let mut zeros = vec![b'a'; 100];
    zeros.extend_from_slice(&[0; 50]);
    let mut data = vec![b'a'; 100];
    data.extend_from_slice(&[b'b'; 50]);
    let ts = all(&log, Model::Ext4Ordered);
    // The committed size is 150 either way; the block, allocated before, may also have been
    // written back in place (the block is old or new as a whole).
    assert!(ts
        .iter()
        .all(|t| file(t, "f") == Some(zeros.clone()) || file(t, "f") == Some(data.clone())));
    assert!(
        ts.iter().any(|t| file(t, "f") == Some(zeros.clone())),
        "zeros case reachable"
    );
}

#[test]
fn ext4_five_second_commit() {
    // The transaction holding a's creation is older than 5 s when b is created: it commits.
    let log = B::new()
        .create(ROOT, "a", 10)
        .at(6_000 * MS)
        .create(ROOT, "b", 11)
        .crash();
    let t = model_ext4::materialise_at(&log, None, 0, 0).unwrap();
    assert!(file(&t, "a").is_some());
    assert!(file(&t, "b").is_none());
    // Observed at the crash too.
    let log = B::new().create(ROOT, "a", 10).at(6_000 * MS).crash();
    let t = model_ext4::materialise_at(&log, None, 0, 0).unwrap();
    assert!(file(&t, "a").is_some());
    // Under 5 s: no commit.
    let log = B::new().create(ROOT, "a", 10).at(4_000 * MS).crash();
    let t = model_ext4::materialise_at(&log, None, 0, 0).unwrap();
    assert!(file(&t, "a").is_none());
}

/// Brute-force legality oracle for a tail with no forced commits, no overwrites of committed
/// blocks and no rename-over: a legal ext4 state is the full replay of some prefix after the
/// last forced commit (the spontaneous cut writes back and commits everything before it;
/// nothing after it reaches the disk).
#[test]
fn ext4_spontaneous_cut_gives_a_legal_subset() {
    let mut b = B::new();
    b.base_file("seed", 9, b"base");
    b.mkdir(ROOT, "d", 10)
        .create(10, "x", 11)
        .write(11, 0, b"xx")
        .create(ROOT, "y", 12)
        .write(12, 0, b"yyy")
        .link(10, "y2", 12)
        .rename("y", "z", 12, 0)
        .unlink(ROOT, "seed", 9)
        .create(ROOT, "w", 13)
        .write(13, 0, b"w");
    let log = b.crash();
    let n = log.ops.len();
    let nbase = log.ops.iter().take_while(|o| o.is_base()).count();
    let legal: BTreeSet<String> = (nbase..=n)
        .map(|k| {
            replay(&OpLog {
                ops: log.ops[..k].to_vec(),
            })
            .unwrap()
            .to_tree()
            .digest()
        })
        .collect();
    let mut got = BTreeSet::new();
    for s in 0..SEEDS {
        let t = mat(&log, s, Model::Ext4Ordered);
        assert!(legal.contains(&t.digest()), "seed {s}: illegal tree {t:?}");
        got.insert(t.digest());
    }
    assert!(
        got.len() >= 3,
        "only {} distinct trees over {SEEDS} seeds",
        got.len()
    );
}

#[test]
fn failed_fsync_data_never_durable() {
    for m in BOTH {
        let log = B::new()
            .create(ROOT, "f", 10)
            .fsync_dir(ROOT)
            .fsync(10)
            .write(10, 0, b"AAAA")
            .fail(10)
            .fsync(10) // the retry succeeds and makes nothing durable
            .write(10, 4, b"BBBB")
            .fsync(10)
            .crash();
        for t in all(&log, m) {
            let d = file(&t, "f").unwrap();
            assert_eq!(d.len(), 8, "{m:?}");
            assert_ne!(&d[..4], b"AAAA", "{m:?}: failed bytes came back");
            assert_eq!(
                &d[4..],
                b"BBBB",
                "{m:?}: data synced after the failure is durable"
            );
        }
    }
}

#[test]
fn failed_fsync_rewritten_data_durable() {
    // Error at fsync 1, the program writes the same bytes again, fsync 2 succeeds: the
    // rewrite is durable (the page is dirty again), as on Linux.
    for m in BOTH {
        let log = B::new()
            .create(ROOT, "f", 10)
            .fsync_dir(ROOT)
            .fsync(10)
            .write(10, 0, b"AAAA")
            .fail(10)
            .write(10, 0, b"AAAA")
            .fsync(10)
            .crash();
        for t in all(&log, m) {
            assert_eq!(file(&t, "f").as_deref(), Some(&b"AAAA"[..]), "{m:?}");
        }
    }
}

#[test]
fn failed_fsync_report_does_not_commit() {
    // An fsync that reports an earlier error (NO_COMMIT) makes nothing durable in posix.
    let log = B::new()
        .create(ROOT, "f", 10)
        .fsync_dir(ROOT)
        .write(10, 0, b"Q")
        .op(OpKind::Fsync, 10, [FSYNC_NO_COMMIT, 0, 0, 0, 0, 0], vec![])
        .crash();
    let ts = all(&log, Model::PosixStrict);
    assert!(ts.iter().any(|t| file(t, "f").as_deref() == Some(&b""[..])));
}

#[test]
fn hard_links_survive_as_one_inode() {
    for m in BOTH {
        let log = B::new()
            .create(ROOT, "f", 10)
            .write(10, 0, b"L")
            .link(ROOT, "g", 10)
            .sync()
            .crash();
        for t in all(&log, m) {
            let (f, g) = (&t.nodes[&b"f"[..]], &t.nodes[&b"g"[..]]);
            assert_eq!(f.ino, g.ino, "{m:?}");
            assert_eq!(f.data.to_vec(), b"L");
        }
    }
}

#[test]
fn sync_makes_everything_durable() {
    for m in BOTH {
        let log = B::new()
            .mkdir(ROOT, "d", 10)
            .create(10, "f", 11)
            .write(11, 0, b"S")
            .sync()
            .crash();
        for t in all(&log, m) {
            assert_eq!(file(&t, "d/f").as_deref(), Some(&b"S"[..]), "{m:?}");
        }
    }
}

#[test]
fn unlinked_open_file_does_not_appear() {
    for m in BOTH {
        let log = B::new()
            .create(ROOT, "f", 10)
            .write(10, 0, b"x")
            .unlink(ROOT, "f", 10)
            .write(10, 1, b"y")
            .sync()
            .crash();
        for t in all(&log, m) {
            assert_eq!(t.nodes.len(), 1, "{m:?}: only the root");
        }
    }
}

#[test]
fn same_seed_same_tree() {
    let log = B::new()
        .base_file("f", 10, &vec![b'a'; 3 * BLOCK as usize])
        .write(10, 0, &vec![b'b'; 3 * BLOCK as usize])
        .create(ROOT, "n", 11)
        .crash();
    for m in BOTH {
        for s in 0..20 {
            assert_eq!(mat(&log, s, m), mat(&log, s, m));
        }
    }
}

/// `write_dir` leaves all-zero chunks as holes: the tree read back is identical
/// (zero runs inside, at the ends, a sparse tail, and a file that is all zeros).
#[test]
fn write_dir_sparse_is_content_identical() {
    let mut b = B::new();
    let mut big = vec![0u8; 300 << 10];
    big[70_000] = 7;
    big[(200 << 10) + 3] = 9;
    b.base_file("big", 2, &big);
    b.base_file("zeros", 3, &vec![0u8; 200 << 10]);
    b.base_file("small", 4, b"abc");
    let t = mat(&b.crash(), 1, Model::Ext4Ordered);
    let base = std::env::var_os("PATINA_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&base).unwrap();
    let dir = base.join(format!("patina-sparse-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    t.write_dir(&dir).unwrap();
    let back = Tree::from_dir(&dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(file(&back, "big").unwrap(), big);
    assert_eq!(file(&back, "zeros").unwrap(), vec![0u8; 200 << 10]);
    assert_eq!(file(&back, "small").unwrap(), b"abc");
}

/// A crash's tree takes each inode's time from the live tree (none for an inode the live tree
/// lacks); the time survives the archive and the list carried to the next boot, an
/// archive without times still reads, and neither the digest nor `diff` sees times.
#[test]
fn times_are_carried_and_never_compared() {
    let mut b = B::new();
    b.base_file("kept", 2, b"abc");
    b.base_file("gone", 3, b"xyz");
    let mut t = mat(&b.crash(), 1, Model::Ext4Ordered);
    let untimed = t.clone();
    let ino = |t: &Tree, p: &str| t.nodes[p.as_bytes()].ino;
    let mut live = t.clone();
    live.nodes.remove(&b"gone"[..]);
    let at = 1_767_225_605_000_000_123u64;
    live.nodes.get_mut(&b"kept"[..]).unwrap().mtime = Some(at);
    t.times_from(&live);
    assert_eq!(t.nodes[&b"kept"[..]].mtime, Some(at));
    assert_eq!(t.nodes[&b"gone"[..]].mtime, None);
    assert_eq!(ino(&t, "kept"), ino(&untimed, "kept"));
    assert_eq!(Tree::decode(&t.encode()).unwrap(), t);
    assert_eq!(t.digest(), untimed.digest());
    assert_eq!(crate::durability::tree::diff(&t, &untimed, true), None);
    // An archive of the earlier format: the root alone, without the time field (after the
    // magic, the path's length, kind, mode, uid, gid and inode number).
    let root = Tree {
        nodes: [(Vec::new(), untimed.nodes[&b""[..]].clone())].into(),
    };
    let mut old = root.encode();
    old[..8].copy_from_slice(b"PATINAT2");
    old.remove(8 + 4 + 1 + 12 + 8);
    assert_eq!(Tree::decode(&old).unwrap(), root);
    let carried = crate::durability::tree::decode_times(&t.times()).unwrap();
    assert_eq!(carried, vec![(b"kept".to_vec(), at)]);
}

/// A small deterministic generator for random logs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
}

/// A random but valid log: base files (some sparse), then creates, writes (some of zeros),
/// truncates (to zero, small, 64 MiB), fallocates, renames (also over a file), links,
/// unlinks, attributes, every sync kind, failed fsyncs, closes and 6-second gaps.
fn random_log(seed: u64, n: usize) -> OpLog {
    use proto::oplog::WRITE_SPARSE;
    let mut r = Rng(seed);
    let mut b = B::new();
    let mut dirs = vec![ROOT];
    let mut names: Vec<(u64, String, u64)> = vec![]; // (parent, name, ino) of files
    let mut ino = 100;
    let mut uniq = 0;
    for i in 0..r.below(3) {
        ino += 1;
        let name = format!("base{i}");
        b.ops.push(Op::new(
            OpKind::Create,
            ino,
            [ROOT, 0o644, 0o100000, 1, 0, 0],
            name.as_bytes().to_vec(),
        ));
        let mut c = super::content::Content::new();
        c.write(r.below(200_000), &vec![b'B'; r.below(9000) as usize + 1]);
        c.resize(c.len() + r.below(100_000));
        let ex = super::materialise::sparse_encode(&c);
        b.ops.push(Op::new(
            OpKind::Write,
            ino,
            [0, c.len(), 1, WRITE_SPARSE, 0, 0],
            ex,
        ));
        names.push((ROOT, name, ino));
    }
    let data = |r: &mut Rng| -> Vec<u8> {
        let len = r.pick(&[0u64, 1, 100, 4096, 5000, 20000]) as usize;
        let z = r.below(4) == 0;
        (0..len)
            .map(|i| if z { 0 } else { (i as u8) | 1 })
            .collect()
    };
    for _ in 0..n {
        let files: Vec<u64> = names.iter().map(|x| x.2).collect();
        match r.below(20) {
            0 | 1 => {
                ino += 1;
                uniq += 1;
                let p = r.pick(&dirs);
                let name = format!("f{uniq}");
                b.create(p, &name, ino);
                names.push((p, name, ino));
            }
            2 => {
                ino += 1;
                uniq += 1;
                let p = r.pick(&dirs);
                b.mkdir(p, &format!("d{uniq}"), ino);
                dirs.push(ino);
            }
            3..=6 if !files.is_empty() => {
                let f = r.pick(&files);
                let off = r.pick(&[0, 1, 4095, 4096, 10_000, 70_000, 300_000]) + r.below(3);
                let d = data(&mut r);
                b.write(f, off, &d);
            }
            7 if !files.is_empty() => {
                let f = r.pick(&files);
                let size = r.pick(&[0u64, 1, 5000, 9000, 64 << 20]);
                b.truncate(f, size);
            }
            8 if !files.is_empty() => {
                let f = r.pick(&files);
                let mode = r.pick(&[0u64, 1, 2 | 1, 0x10, 0x10 | 1]);
                b.op(
                    OpKind::Fallocate,
                    f,
                    [mode, r.below(20_000), r.below(20_000) + 1, 0, 0, 0],
                    vec![],
                );
            }
            9 | 10 if !files.is_empty() => {
                let f = r.pick(&files);
                let flags = r.pick(&[
                    0u64,
                    0,
                    FSYNC_NO_COMMIT,
                    proto::oplog::FSYNC_MSYNC | FSYNC_NO_COMMIT,
                    proto::oplog::FSYNC_DATA_ONLY,
                ]);
                b.op(OpKind::Fsync, f, [flags, 0, 0, 0, 0, 0], vec![]);
            }
            11 => {
                let d = r.pick(&dirs);
                b.fsync_dir(d);
            }
            12 if !files.is_empty() => {
                let f = if r.below(3) == 0 { 0 } else { r.pick(&files) };
                b.fail(f);
            }
            13 if r.below(4) == 0 => {
                b.sync();
            }
            14 if !files.is_empty() => {
                let f = r.pick(&files);
                b.close(f);
            }
            15 if !names.is_empty() => {
                // rename within or across directories, sometimes over another file
                let i = r.below(names.len() as u64) as usize;
                let (op_, old, f) = names[i].clone();
                let over = names.iter().position(|x| x.2 != f && r.below(2) == 0);
                let (np, new, replaced) = match over {
                    Some(j) => (names[j].0, names[j].1.clone(), names[j].2),
                    None => {
                        uniq += 1;
                        (r.pick(&dirs), format!("r{uniq}"), 0)
                    }
                };
                let data = [old.as_bytes(), new.as_bytes()].concat();
                b.op(
                    OpKind::Rename,
                    f,
                    [op_, np, replaced, 0, old.len() as u64, 0],
                    data,
                );
                if replaced != 0 {
                    let j = names.iter().position(|x| x.0 == np && x.1 == new).unwrap();
                    names.remove(j);
                }
                let i = names.iter().position(|x| x.0 == op_ && x.1 == old).unwrap();
                names[i] = (np, new, f);
            }
            16 if !names.is_empty() => {
                let i = r.below(names.len() as u64) as usize;
                let (p, name, f) = names.remove(i);
                b.unlink(p, &name, f);
            }
            17 if !names.is_empty() => {
                let f = r.pick(&files);
                uniq += 1;
                let p = r.pick(&dirs);
                let name = format!("l{uniq}");
                b.link(p, &name, f);
                names.push((p, name, f));
            }
            18 if !files.is_empty() => {
                let f = r.pick(&files);
                b.op(
                    OpKind::SetAttr,
                    f,
                    [0o600 + r.below(64), 1000, 1000, 1, 0, 0],
                    vec![],
                );
            }
            _ => {
                b.t += r.pick(&[MS, 1000 * MS, 6000 * MS]);
            }
        }
    }
    b.crash()
}

/// The single-replay materialiser (snapshot at the last forced commit, then only the tail
/// with the drawn cut) gives the tree a full replay with the same cut gives.
#[test]
fn ext4_single_pass_equals_full_replay_with_the_cut() {
    let (mut cuts, mut distinct) = (0, BTreeSet::new());
    for s in 0..300u64 {
        let log = random_log(s, 120);
        for key in 0..6 {
            let (f, k) = model_ext4::cut_for(&log.ops, s, key).unwrap();
            let full =
                model_ext4::materialise_at(&log, if k == f { None } else { Some(k) }, s, key)
                    .unwrap();
            let fast = materialise(&log, u64::MAX, s, key, Model::Ext4Ordered).unwrap();
            assert!(
                full == fast,
                "seed {s} key {key}: {:?}",
                super::tree::diff(&full, &fast, true)
            );
            cuts += (k != f) as usize;
            distinct.insert(fast.digest());
        }
        // posix-strict runs on the same logs (its equivalence with the pre-crash materialiser code is checked
        // against that build by tests/durability).
        for key in 0..3 {
            materialise(&log, u64::MAX, s, key, Model::PosixStrict).unwrap();
        }
    }
    // The logs exercise spontaneous cuts and give many different trees.
    assert!(
        cuts > 900 && distinct.len() > 900,
        "{cuts} cuts, {} trees",
        distinct.len()
    );
}

/// `Fs::would_fail` answers exactly what applying to a copy would: random records, valid and
/// invalid, against random states.
#[test]
fn would_fail_matches_applying_to_a_copy() {
    use super::materialise::Fs;
    for s in 0..200u64 {
        let log = random_log(s, 80);
        let mut r = Rng(s ^ 0xabc);
        let mut fs = Fs::default();
        let mut checked = 0;
        for o in &log.ops {
            // a mutated copy of the record: other parent, inode, name or flags
            for _ in 0..4 {
                let mut x = o.clone();
                match r.below(5) {
                    0 => x.a[0] = r.pick(&[0, ROOT, 101, 102, 105, 999]),
                    1 => x.ino = r.pick(&[ROOT, 101, 102, 103, 105, 999]),
                    2 => x.data = r.pick(&[&b"f1"[..], b"base0", b"zz", b""]).to_vec(),
                    3 => x.a[1] = r.pick(&[0, ROOT, 101, 1 << 40]),
                    _ => x.a[3] = r.pick(&[0, 1, 2, 0x40]),
                }
                if let Some(w) = fs.would_fail(&x) {
                    let mut c = fs.clone();
                    assert_eq!(w, c.apply(&x).is_err(), "seed {s}: {x:?}");
                    checked += 1;
                }
            }
            if fs.would_fail(o) == Some(false) {
                fs.apply(o).unwrap();
            }
        }
        assert!(checked > 100);
    }
}
