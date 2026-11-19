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
    /// Load `dir/oplog.meta` and `dir/oplog.data` (an incarnation directory).
    pub fn load(dir: &Path) -> Result<OpLog, String> {
        let meta = read_all(&dir.join("oplog.meta"))?;
        let data = read_all(&dir.join("oplog.data"))?;
        let mut ops = Vec::with_capacity(meta.len() / OPREC_SIZE);
        for (i, c) in meta.chunks(OPREC_SIZE).enumerate() {
            if c.len() < OPREC_SIZE {
                return Err(format!("oplog.meta: partial record {i}"));
            }
            let r = OpRec::from_bytes(c);
            let kind = OpKind::from_u32(r.kind)
                .ok_or_else(|| format!("oplog record {i}: unknown kind {}", r.kind))?;
            let (o, l) = (r.data_off as usize, r.data_len as usize);
            if o + l > data.len() {
                return Err(format!("oplog record {i}: data beyond oplog.data"));
            }
            ops.push(Op {
                seq: r.seq,
                vclock_ns: r.vclock_ns,
                kind,
                pid: r.pid,
                ino: r.ino,
                a: r.a,
                data: data[o..o + l].to_vec(),
            });
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
