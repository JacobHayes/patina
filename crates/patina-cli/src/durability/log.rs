//! Reading the operation log (`proto::oplog`): `oplog.meta` records with their bytes from
//! `oplog.data`, and `patina oplog dump`.

use proto::oplog::{OpKind, OpRec, OPREC_SIZE};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Op {
    pub seq: u64,
    pub vclock_ns: u64,
    pub kind: OpKind,
    pub pid: u32,
    pub ino: u64,
    pub a: [u64; 6],
    pub data: Vec<u8>,
}

impl Op {
    #[cfg(test)]
    pub fn new(kind: OpKind, ino: u64, a: [u64; 6], data: Vec<u8>) -> Op {
        Op {
            seq: 0,
            vclock_ns: 0,
            kind,
            pid: 0,
            ino,
            a,
            data,
        }
    }
    /// Record `i`, `r`, with its bytes.
    pub fn from_rec(i: usize, r: &OpRec, data: Vec<u8>) -> Result<Op, String> {
        let kind = OpKind::from_u32(r.kind)
            .ok_or_else(|| format!("oplog record {i}: unknown kind {}", r.kind))?;
        Ok(Op {
            seq: r.seq,
            vclock_ns: r.vclock_ns,
            kind,
            pid: r.pid,
            ino: r.ino,
            a: r.a,
            data,
        })
    }

    /// A base record (part of the initial tree: durable at seq 0)?
    pub fn is_base(&self) -> bool {
        self.seq == 0
    }
    /// For records whose data holds two names (`Symlink`: name ++ target, `Rename`: old ++
    /// new, `XattrSet`: name ++ value): split at the stored first length.
    pub fn split(&self, first: u64) -> (&[u8], &[u8]) {
        let n = (first as usize).min(self.data.len());
        (&self.data[..n], &self.data[n..])
    }
}

#[derive(Clone, Debug, Default)]
pub struct OpLog {
    pub ops: Vec<Op>,
}

impl OpLog {
    /// Load `dir/oplog.meta` and `dir/oplog.data` (a boot directory).
    pub fn load(dir: &Path) -> Result<OpLog, String> {
        let meta = read_all(&dir.join("oplog.meta"))?;
        let data = read_all(&dir.join("oplog.data"))?;
        let mut ops = Vec::with_capacity(meta.len() / OPREC_SIZE);
        for (i, c) in meta.chunks(OPREC_SIZE).enumerate() {
            if c.len() < OPREC_SIZE {
                return Err(format!("oplog.meta: partial record {i}"));
            }
            let r = OpRec::from_bytes(c);
            let (o, l) = (r.data_off as usize, r.data_len as usize);
            if o + l > data.len() {
                return Err(format!("oplog record {i}: data beyond oplog.data"));
            }
            ops.push(Op::from_rec(i, &r, data[o..o + l].to_vec())?);
        }
        Ok(OpLog { ops })
    }

    /// The records with `seq <= upto` (base records have seq 0).
    pub fn upto(&self, upto: u64) -> OpLog {
        OpLog {
            ops: self.ops.iter().filter(|o| o.seq <= upto).cloned().collect(),
        }
    }

    pub fn bytes(&self) -> (usize, usize) {
        (
            self.ops.len() * OPREC_SIZE,
            self.ops.iter().map(|o| o.data.len()).sum(),
        )
    }
}

/// Split the shared operation log of a run with machines, `bdir/oplog.*`, whose kinds carry their
/// machine (`proto::oplog::tag_kind`), into one log per disk: machine `k`'s records (`k` > 0) go to
/// `disk(k, b)/oplog.*`, where `b` is the boot its disk began with (0, or the boot after a
/// machine crash), and the live tree record that ends each disk (`KIND_LIVE_TREE`, at a
/// machine crash or at the end of the run) to `disk(k, b)/live.tree`; main's stay in
/// `bdir/oplog.*`. Every log is then plain, with its records' bytes in its own `oplog.data`, in
/// the shared log's order. A log without a tagged record is left as it is.
pub fn split_machines(
    bdir: &Path,
    disk: impl Fn(usize, u64) -> Option<std::path::PathBuf>,
) -> Result<(), String> {
    use proto::oplog::{kind_machine, KIND_LIVE_TREE, KIND_MASK};
    use std::collections::BTreeMap;
    let meta = read_all(&bdir.join("oplog.meta"))?;
    let recs: Vec<OpRec> = meta
        .as_chunks::<OPREC_SIZE>()
        .0
        .iter()
        .map(|c| OpRec::from_bytes(c))
        .collect();
    if recs.iter().all(|r| kind_machine(r.kind) == 0) {
        return Ok(());
    }
    let data = read_all(&bdir.join("oplog.data"))?;
    // Per disk (machine, first boot): its meta, its data, its live tree.
    type Disk = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);
    let mut out: BTreeMap<(usize, u64), Disk> = BTreeMap::new();
    out.entry((0, 0)).or_default();
    // Each machine's disk now, and the boot its next disk begins with (after a machine crash).
    let mut cur: BTreeMap<usize, u64> = BTreeMap::new();
    let mut next: BTreeMap<usize, u64> = BTreeMap::new();
    for (i, r) in recs.iter().enumerate() {
        let (o, l) = (r.data_off as usize, r.data_len as usize);
        let bytes = data
            .get(o..o + l)
            .ok_or_else(|| format!("oplog record {i}: data beyond oplog.data"))?;
        let k = kind_machine(r.kind);
        let b = *cur.entry(k).or_insert(0);
        let e = out.entry((k, b)).or_default();
        let kind = r.kind & KIND_MASK;
        if kind == KIND_LIVE_TREE {
            e.2 = Some(bytes.to_vec());
            if let Some(n) = next.remove(&k) {
                cur.insert(k, n);
            }
            continue;
        }
        if k > 0 && kind == OpKind::Crash as u32 && r.a[0] == proto::faults::CRASH_MACHINE {
            next.insert(k, r.a[1] + 1);
        }
        let plain = OpRec {
            kind,
            data_off: e.1.len() as u64,
            ..*r
        };
        e.0.extend_from_slice(plain.as_bytes());
        e.1.extend_from_slice(bytes);
    }
    let write = |p: std::path::PathBuf, b: &[u8]| {
        fs::write(&p, b).map_err(|e| format!("{}: {e}", p.display()))
    };
    for ((k, b), (m, d, tree)) in out {
        let dir = if k == 0 {
            bdir.to_path_buf()
        } else {
            disk(k, b)
                .ok_or_else(|| format!("oplog: records of machine {k}, which the run lacks"))?
        };
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        write(dir.join("oplog.meta"), &m)?;
        write(dir.join("oplog.data"), &d)?;
        if let Some(t) = tree {
            write(dir.join("live.tree"), &t)?;
        }
    }
    Ok(())
}

/// The whole file, read into a buffer of its size (no regrowth).
fn read_all(p: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let err = |e: std::io::Error| format!("{}: {e}", p.display());
    let mut f = fs::File::open(p).map_err(err)?;
    let n = f.metadata().map_err(err)?.len() as usize;
    let mut v = Vec::with_capacity(n);
    f.read_to_end(&mut v).map_err(err)?;
    Ok(v)
}

fn show_name(b: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(b).chars().take(60).collect();
    format!("{s:?}")
}

/// One line per record.
pub fn describe(i: usize, o: &Op) -> String {
    let a = &o.a;
    let detail = match o.kind {
        OpKind::Root => format!("mode={:o}", a[0]),
        OpKind::Create => format!(
            "parent={} name={} mode={:o} fmt={:o}",
            a[0],
            show_name(&o.data),
            a[1],
            a[2]
        ),
        OpKind::Mkdir => format!(
            "parent={} name={} mode={:o}",
            a[0],
            show_name(&o.data),
            a[1]
        ),
        OpKind::Symlink => {
            let (n, t) = o.split(a[1]);
            format!(
                "parent={} name={} target={}",
                a[0],
                show_name(n),
                show_name(t)
            )
        }
        OpKind::Link => format!("parent={} name={}", a[0], show_name(&o.data)),
        OpKind::Unlink | OpKind::Rmdir => {
            format!("parent={} name={} left={}", a[0], show_name(&o.data), a[1])
        }
        OpKind::Rename => {
            let (x, y) = o.split(a[4]);
            format!(
                "{}:{} -> {}:{} replaced={} flags={}",
                a[0],
                show_name(x),
                a[1],
                show_name(y),
                a[2],
                a[3]
            )
        }
        OpKind::Write | OpKind::MmapDirty => format!("off={} len={}", a[0], a[1]),
        OpKind::Truncate => format!("size={}", a[0]),
        OpKind::Fallocate => format!("mode={} off={} len={}", a[0], a[1], a[2]),
        OpKind::SetAttr => format!("mode={:o} uid={} gid={}", a[0], a[1], a[2]),
        OpKind::XattrSet => {
            let (n, v) = o.split(a[0]);
            format!("name={} len={}", show_name(n), v.len())
        }
        OpKind::XattrRemove => format!("name={}", show_name(&o.data)),
        OpKind::MmapShared => format!("off={} len={}", a[0], a[1]),
        OpKind::Fsync => format!("flags={}", a[0]),
        OpKind::Crash => format!("kind={}", a[0]),
        _ => String::new(),
    };
    format!(
        "{i:6} seq={:<8} vt={:<14} pid={:<3} {:<11} ino={:<6} {detail}",
        o.seq,
        o.vclock_ns,
        o.pid,
        o.kind.name(),
        o.ino
    )
}

pub fn dump(dir: &Path) -> Result<(), String> {
    let log = OpLog::load(dir)?;
    for (i, o) in log.ops.iter().enumerate() {
        println!("{}", describe(i, o));
    }
    Ok(())
}
