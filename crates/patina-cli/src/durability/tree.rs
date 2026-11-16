//! A file tree as data: what the supervisor exports at the end of an incarnation (the live
//! tree, descriptor 3006), what replaying an operation log produces, and what the
//! materialiser writes as the next incarnation's `/in`.
//!
//! Archive format (deterministic: entries in sorted path order): magic `PATINAT2`, then per
//! entry: path (u32 length + bytes, "" = the root), kind u8, mode u32, uid u32, gid u32,
//! ino u64, data (file contents or symlink target: u64 length, u32 extent count, then per
//! extent u64 offset + u64 length + bytes; the extents are the maximal runs of 4 KiB blocks
//! holding a non-zero byte, everything else reads as zeros), xattrs (u32 count, then u32
//! length + name, u32 length + value each). The encoding of a tree is a function of its
//! contents only (not of which zero blocks happen to be stored), so `digest` is too.
//!
//! Contents are `Content` (sparse, shared blocks): a 64 MiB file made by `set_len` costs
//! what its written blocks cost, here, in the archive and in the trees written out.

use super::content::{Content, BLOCK};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Dir,
    File,
    Symlink,
    Fifo,
    Socket,
    Other,
}

impl Kind {
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn from_code(c: u8) -> Kind {
        [
            Kind::Dir,
            Kind::File,
            Kind::Symlink,
            Kind::Fifo,
            Kind::Socket,
            Kind::Other,
        ]
        .get(c as usize)
        .copied()
        .unwrap_or(Kind::Other)
    }
    /// From the `S_IFMT` bits of a mode.
    pub fn from_mode(m: u32) -> Kind {
        match m & 0o170000 {
            0o040000 => Kind::Dir,
            0o100000 => Kind::File,
            0o120000 => Kind::Symlink,
            0o010000 => Kind::Fifo,
            0o140000 => Kind::Socket,
            _ => Kind::Other,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::Dir => "dir",
            Kind::File => "file",
            Kind::Symlink => "symlink",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
            Kind::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    /// Permission bits (07777).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Inode number in the tree it came from (link identity).
    pub ino: u64,
    /// File contents, or the symlink target.
    pub data: Content,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    /// Relative path (no leading slash; "" is the root) to node.
    pub nodes: BTreeMap<Vec<u8>, Node>,
}

const MAGIC: &[u8; 8] = b"PATINAT2";

fn put_bytes(o: &mut Vec<u8>, b: &[u8], wide: bool) {
    if wide {
        o.extend_from_slice(&(b.len() as u64).to_le_bytes());
    } else {
        o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    }
    o.extend_from_slice(b);
}

/// Contents as length + non-zero extents (see the module documentation).
fn put_content(o: &mut Vec<u8>, c: &Content) {
    o.extend_from_slice(&c.len().to_le_bytes());
    let ex = c.extent_ranges();
    o.extend_from_slice(&(ex.len() as u32).to_le_bytes());
    for (off, n) in ex {
        o.extend_from_slice(&off.to_le_bytes());
        o.extend_from_slice(&n.to_le_bytes());
        c.append_to(o, off, off + n);
    }
}

/// Read a regular file's contents, visiting only its data extents (`SEEK_DATA`/`SEEK_HOLE`);
/// holes read as zeros, so the result equals a full read.
fn read_sparse(p: &Path) -> io::Result<Content> {
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::AsRawFd;
    let f = fs::File::open(p)?;
    let len = f.metadata()?.len();
    let fd = f.as_raw_fd();
    let mut c = Content::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while off < len {
        let d = unsafe { libc::lseek(fd, off as i64, libc::SEEK_DATA) };
        if d < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break; // a hole up to the end
            }
            return Err(e);
        }
        let d = d as u64;
        let h = (unsafe { libc::lseek(fd, d as i64, libc::SEEK_HOLE) }).max(0) as u64;
        let h = if h <= d { len } else { h.min(len) };
        let mut o = d;
        while o < h {
            let want = ((h - o) as usize).min(buf.len());
            let n = f.read_at(&mut buf[..want], o)?;
            if n == 0 {
                break;
            }
            c.write(o, &buf[..n]);
            o += n as u64;
        }
        off = h.max(d + 1);
    }
    c.resize(len);
    Ok(c)
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.p + n > self.b.len() {
            return Err("truncated tree archive".into());
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self, wide: bool) -> Result<Vec<u8>, String> {
        let n = if wide {
            self.u64()? as usize
        } else {
            self.u32()? as usize
        };
        Ok(self.take(n)?.to_vec())
    }
    fn content(&mut self) -> Result<Content, String> {
        let len = self.u64()?;
        let n = self.u32()?;
        let mut c = Content::new();
        for _ in 0..n {
            let off = self.u64()?;
            let b = self.bytes(true)?;
            if off + b.len() as u64 > len {
                return Err("tree archive extent beyond the length".into());
            }
            c.write(off, &b);
        }
        c.resize(len);
        Ok(c)
    }
}

impl Tree {
    pub fn encode(&self) -> Vec<u8> {
        let size: u64 = self
            .nodes
            .iter()
            .map(|(p, n)| p.len() as u64 + 64 + n.data.blocks().count() as u64 * BLOCK)
            .sum();
        let mut o = Vec::with_capacity(size as usize);
        o.extend_from_slice(MAGIC);
        for (p, n) in &self.nodes {
            put_bytes(&mut o, p, false);
            o.push(n.kind.code());
            o.extend_from_slice(&n.mode.to_le_bytes());
            o.extend_from_slice(&n.uid.to_le_bytes());
            o.extend_from_slice(&n.gid.to_le_bytes());
            o.extend_from_slice(&n.ino.to_le_bytes());
            put_content(&mut o, &n.data);
            o.extend_from_slice(&(n.xattrs.len() as u32).to_le_bytes());
            for (k, v) in &n.xattrs {
                put_bytes(&mut o, k, false);
                put_bytes(&mut o, v, false);
            }
        }
        o
    }

    pub fn decode(b: &[u8]) -> Result<Tree, String> {
        if b.len() < 8 || &b[..8] != MAGIC {
            return Err("not a tree archive".into());
        }
        let mut c = Cur { b, p: 8 };
        let mut t = Tree::default();
        while c.p < b.len() {
            let path = c.bytes(false)?;
            let kind = Kind::from_code(c.u8()?);
            let mode = c.u32()?;
            let uid = c.u32()?;
            let gid = c.u32()?;
            let ino = c.u64()?;
            let data = c.content()?;
            let nx = c.u32()?;
            let mut xattrs = BTreeMap::new();
            for _ in 0..nx {
                let k = c.bytes(false)?;
                let v = c.bytes(false)?;
                xattrs.insert(k, v);
            }
            t.nodes.insert(
                path,
                Node {
                    kind,
                    mode,
                    uid,
                    gid,
                    ino,
                    data,
                    xattrs,
                },
            );
        }
        Ok(t)
    }

    pub fn read_archive(p: &Path) -> Result<Tree, String> {
        let b = fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Tree::decode(&b)
    }

    /// Read a directory tree from disk (the live `/work`, or a materialised tree).
    pub fn from_dir(root: &Path) -> io::Result<Tree> {
        let mut t = Tree::default();
        fn walk(t: &mut Tree, root: &Path, rel: &[u8]) -> io::Result<()> {
            let full = if rel.is_empty() {
                root.to_path_buf()
            } else {
                root.join(std::ffi::OsStr::from_bytes(rel))
            };
            let m = fs::symlink_metadata(&full)?;
            let kind = Kind::from_mode(m.mode());
            let data = match kind {
                Kind::File => read_sparse(&full)?,
                Kind::Symlink => Content::from_slice(fs::read_link(&full)?.as_os_str().as_bytes()),
                _ => Content::new(),
            };
            let xattrs = if kind == Kind::Symlink {
                BTreeMap::new()
            } else {
                read_xattrs(&full)
            };
            t.nodes.insert(
                rel.to_vec(),
                Node {
                    kind,
                    mode: m.mode() & 0o7777,
                    uid: m.uid(),
                    gid: m.gid(),
                    ino: m.ino(),
                    data,
                    xattrs,
                },
            );
            if kind == Kind::Dir {
                let mut names: Vec<Vec<u8>> = fs::read_dir(&full)?
                    .map(|e| e.map(|e| e.file_name().as_bytes().to_vec()))
                    .collect::<Result<_, _>>()?;
                names.sort();
                for n in names {
                    let child = if rel.is_empty() {
                        n
                    } else {
                        [rel, b"/", &n].concat()
                    };
                    walk(t, root, &child)?;
                }
            }
            Ok(())
        }
        walk(&mut t, root, b"")?;
        Ok(t)
    }

    /// Write the tree into `dir` (created; must not exist), in sorted path order, with modes,
    /// hard links (nodes sharing an inode number), symlinks, FIFOs and user xattrs.
    /// Directory modes are applied last, deepest first, so read-only directories still fill.
    /// Directories get `mode | 0o700` so the launcher can always remove the tree later.
    pub fn write_dir(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir(dir)?;
        self.fill(dir, 0o700)
    }

    /// Populate the existing, empty directory `dir` (its own mode is left alone);
    /// directory modes are or'ed with `dir_or`.
    pub fn fill(&self, dir: &Path, dir_or: u32) -> io::Result<()> {
        let mut first_path: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let full = |rel: &[u8]| {
            if rel.is_empty() {
                dir.to_path_buf()
            } else {
                dir.join(std::ffi::OsStr::from_bytes(rel))
            }
        };
        for (p, n) in &self.nodes {
            if p.is_empty() {
                continue;
            }
            let f = full(p);
            if n.kind != Kind::Dir {
                if let Some(q) = first_path.get(&n.ino) {
                    fs::hard_link(full(q), &f)?;
                    continue;
                }
                first_path.insert(n.ino, p.clone());
            }
            match n.kind {
                Kind::Dir => fs::create_dir(&f)?,
                Kind::File => {
                    // Sparse: all-zero 64 KiB chunks are left as holes (same
                    // contents). fjall preallocates 64 MiB journals with `set_len`, and
                    // writing every post-crash copy in full cost ~64 MB per journal.
                    // Only chunks holding a non-zero byte are visited; each is
                    // written whole, zeros included, exactly as before.
                    let h = fs::File::create(&f)?;
                    const CHUNK: u64 = 64 << 10;
                    let len = n.data.len();
                    let mut chunks: Vec<u64> = n
                        .data
                        .nonzero_blocks()
                        .map(|(b, _)| b * BLOCK / CHUNK)
                        .collect();
                    chunks.dedup();
                    for i in chunks {
                        let (lo, hi) = (i * CHUNK, len.min((i + 1) * CHUNK));
                        if n.data.any_nonzero(lo, hi) {
                            std::os::unix::fs::FileExt::write_all_at(&h, &n.data.read(lo, hi), lo)?;
                        }
                    }
                    h.set_len(len)?;
                }
                Kind::Symlink => {
                    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&n.data.to_vec()), &f)?
                }
                Kind::Fifo => {
                    let c = CString::new(f.as_os_str().as_bytes()).unwrap();
                    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Kind::Socket | Kind::Other => continue, // not reproducible as a plain file; dropped
            }
            if n.kind != Kind::Symlink {
                for (k, v) in &n.xattrs {
                    set_xattr(&f, k, v)?;
                }
                if n.kind != Kind::Dir {
                    fs::set_permissions(&f, fs::Permissions::from_mode(n.mode))?;
                }
            }
        }
        for (p, n) in self.nodes.iter().rev() {
            if n.kind == Kind::Dir && !p.is_empty() {
                fs::set_permissions(full(p), fs::Permissions::from_mode(n.mode | dir_or))?;
            }
        }
        Ok(())
    }

    /// Identity of the tree independent of inode numbers: inode numbers are replaced by the
    /// index of the first path that names the inode.
    pub fn canonical(&self) -> Tree {
        let mut first: BTreeMap<u64, u64> = BTreeMap::new();
        let mut t = self.clone();
        for (i, (_, n)) in t.nodes.iter_mut().enumerate() {
            let id = *first.entry(n.ino).or_insert(i as u64);
            n.ino = if n.kind == Kind::Dir { i as u64 } else { id };
        }
        t
    }

    /// Hex digest of the canonical form.
    pub fn digest(&self) -> String {
        let b = self.canonical().encode();
        format!("{:016x}", proto::rec::hash_bytes(0x7472_6565, &b))
    }
}

fn read_xattrs(p: &Path) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut out = BTreeMap::new();
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let mut buf = vec![0u8; 65536];
    let n =
        unsafe { libc::llistxattr(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if n <= 0 {
        return out;
    }
    for name in buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
    {
        if !name.starts_with(b"user.") {
            continue;
        }
        let cn = CString::new(name).unwrap();
        let mut v = vec![0u8; 65536];
        let l = unsafe {
            libc::lgetxattr(
                c.as_ptr(),
                cn.as_ptr(),
                v.as_mut_ptr() as *mut libc::c_void,
                v.len(),
            )
        };
        if l >= 0 {
            v.truncate(l as usize);
            out.insert(name.to_vec(), v);
        }
    }
    out
}

pub fn set_xattr(p: &Path, k: &[u8], v: &[u8]) -> io::Result<()> {
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let ck = CString::new(k).map_err(|_| io::Error::other("xattr name with NUL"))?;
    if unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            ck.as_ptr(),
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Describe the first difference between two trees (None: equal), comparing kind, mode,
/// owner, contents, xattrs and link identity (inode numbers compared directly when `by_ino`,
/// else canonically).
pub fn diff(a: &Tree, b: &Tree, by_ino: bool) -> Option<String> {
    let (a, b) = if by_ino {
        (a.clone(), b.clone())
    } else {
        (a.canonical(), b.canonical())
    };
    let show = |p: &[u8]| {
        if p.is_empty() {
            "/".to_string()
        } else {
            String::from_utf8_lossy(p).into_owned()
        }
    };
    for p in a.nodes.keys().chain(b.nodes.keys()) {
        match (a.nodes.get(p), b.nodes.get(p)) {
            (Some(_), None) => return Some(format!("{}: only in the first tree", show(p))),
            (None, Some(_)) => return Some(format!("{}: only in the second tree", show(p))),
            (Some(x), Some(y)) => {
                if x.kind != y.kind {
                    return Some(format!(
                        "{}: kind {} vs {}",
                        show(p),
                        x.kind.name(),
                        y.kind.name()
                    ));
                }
                if x.ino != y.ino && x.kind != Kind::Dir {
                    return Some(format!("{}: inode {} vs {}", show(p), x.ino, y.ino));
                }
                if x.kind != Kind::Symlink
                    && !p.is_empty()
                    && (x.mode != y.mode || x.uid != y.uid || x.gid != y.gid)
                {
                    return Some(format!(
                        "{}: mode/owner {:o} {}:{} vs {:o} {}:{}",
                        show(p),
                        x.mode,
                        x.uid,
                        x.gid,
                        y.mode,
                        y.uid,
                        y.gid
                    ));
                }
                if let Some(at) = x.data.first_difference(&y.data) {
                    return Some(format!(
                        "{}: contents differ (sizes {} vs {}, first at byte {at})",
                        show(p),
                        x.data.len(),
                        y.data.len()
                    ));
                }
                if x.xattrs != y.xattrs {
                    return Some(format!("{}: xattrs differ", show(p)));
                }
            }
            (None, None) => unreachable!(),
        }
    }
    None
}
