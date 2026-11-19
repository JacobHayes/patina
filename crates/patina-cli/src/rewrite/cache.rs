//! Plans for a run with `--preempt points`: made on the host, once per file and patina build,
//! kept in the plan cache, and answered to the runtime by the launcher's broker
//! (`launcher::plans`, protocol in `proto::plan`).
//!
//! The cache is `$XDG_CACHE_HOME/patina/plans/` (default `~/.cache/patina/plans/`), on the host
//! only: no sandbox mounts it, and the runtime gets a read-only descriptor of one plan file at a
//! time from the broker. An entry is `<file SHA-256>-<build key>.plan`, the plan exactly as
//! `Plan::to_bytes` writes it, and `.ok` beside it: the plan file's inode, size and
//! change time when it was written and verified, and the SHA-256 of its bytes (the change time,
//! which no program can set back, moves with any write). A plan is
//! a cache, never an input: deleting one changes nothing but time.
//!
//! - A hit is checked cheaply: the header (magic, version, machine, the file's SHA-256, this
//!   build, the cell) and the length the header implies, and the plan file's identity against
//!   its `.ok`. A plan whose identity changed (anything wrote it) is hashed whole and used only
//!   if its bytes are still the ones verified; otherwise it is made again.
//! - A miss makes the plan (`make_plan`) and runs the independent verifier on it before it is
//!   written; a plan the verifier rejects is not used (the file runs unpatched, named in the
//!   report). Files that get no plan have a `.none` entry with the reason. A miss holds the
//!   entry's `.lock` (`flock`) while it makes the entry: another process that misses the same
//!   file waits for it and then finds the entry, so concurrent runs (a sweep's) make each plan
//!   once. A plan is made on up to the planner's threads (`par`), the same bytes on any number.
//! - The SHA-256 of a file is kept under its identity (device, inode, size, change time) in
//!   `$XDG_CACHE_HOME/patina/sha256/`, as for programs (`config::sha256_file`).
//! - Size: at most `CACHE_MAX` bytes of plans; writing one that passes it removes the least
//!   recently used plans (by their `.ok`'s modification time, renewed at each use) down to
//!   three quarters of it, and any partly written plan whose writer is gone.
//! - Making plans that takes more than a moment says so once on stderr (`Notice`).

use super::elf::Elf;
use super::par::Par;
use super::plan::{CELL, MAGIC, PAGE, VERSION};
use crate::cli::Res;
use proto::plan::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The plan cache's size bound.
pub const CACHE_MAX: u64 = 4 << 30;
/// Files larger than this get no plan (they would be read whole on the host).
pub const FILE_MAX: u64 = 1 << 30;

/// A name for a temporary file beside `p`, unique to this process and call.
fn tmp_name(p: &Path, ext: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    p.with_extension(format!("{ext}{}-{n}", std::process::id()))
}

/// One file the run mapped executable, for `result.json`'s `rewrite.images`.
#[derive(Clone, Debug)]
pub struct ImageReport {
    /// The path the runtime named (the program's view).
    pub path: String,
    pub sha256: String,
    /// `planned`, or why not: `not-elf`, `refused`, `unverified`, `empty`.
    pub status: &'static str,
    pub why: String,
    /// The plan's counts (`rewrite --plan`'s report): bytes of text, proven, extent and dark
    /// code, sites found and patched per class.
    pub counts: Vec<(String, u64)>,
    /// `hit`, `made`, or `rebuilt` (an entry was found changed and made again).
    pub cache: &'static str,
    /// Wall time of making the plan (0 for a hit).
    pub ms: u64,
}

/// What the broker answers for one file.
#[derive(Clone)]
enum Entry {
    Plan {
        file: Arc<File>,
        hdr: [u64; REPLY_WORDS],
        /// (link address, file offset, file size) of each load segment.
        loads: Arc<Vec<(u64, u64, u64)>>,
        report: ImageReport,
    },
    None(u64, ImageReport),
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}

fn key(m: &fs::Metadata) -> Key {
    Key {
        dev: m.dev(),
        ino: m.ino(),
        size: m.size(),
        ctime: (m.ctime(), m.ctime_nsec()),
    }
}

/// The run's plans: the cache, and what this process has answered already.
pub struct Planner {
    dir: PathBuf,
    build: String,
    par: Par,
    notice: Arc<Notice>,
    known: Mutex<HashMap<Key, Entry>>,
    /// Files the runtime asked for, in the order first asked.
    reported: Mutex<Vec<ImageReport>>,
    seen: Mutex<std::collections::HashSet<Key>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn le(d: &[u8], o: usize, n: usize) -> u64 {
    let mut v = [0u8; 8];
    v[..n].copy_from_slice(&d[o..o + n]);
    u64::from_le_bytes(v)
}

/// The fixed part of a plan's header: magic 8, version 4, machine 4, SHA-256 32, cell,
/// trampolines' address and span 8 each, then the counts of page runs, trampoline runs, sites,
/// entries, counts and the build's bytes, 4 each.
const FIXED: usize = 96;

/// Check the header of the plan file `f` (length `len`) for the file `sha` and build `build`,
/// and find what the runtime needs: the reply's words but `R_STATUS` and `R_VADDR`, and where
/// the counts start.
fn header(f: &File, len: u64, sha: &[u8; 32], build: &str) -> Res<([u64; REPLY_WORDS], u64)> {
    let mut h = [0u8; FIXED];
    f.read_exact_at(&mut h, 0).map_err(|e| e.to_string())?;
    let (np, nt, ns, ne, nb) = (
        le(&h, 72, 4),
        le(&h, 76, 4),
        le(&h, 80, 4),
        le(&h, 84, 4),
        le(&h, 92, 4),
    );
    let span = le(&h, 64, 8);
    if &h[..8] != MAGIC
        || le(&h, 8, 4) != VERSION as u64
        || le(&h, 12, 4) != super::HOST_MACHINE as u64
        || h[16..48] != sha[..]
        || le(&h, 48, 8) != CELL
        || nb != build.len() as u64
        || np + nt > len / PAGE
        || ns > len
        || ne > len
        || !span.is_multiple_of(PAGE)
    {
        return Err("header".into());
    }
    let mut rest = vec![0u8; nb as usize + RUN_BYTES * (np + nt) as usize];
    f.read_exact_at(&mut rest, FIXED as u64)
        .map_err(|e| e.to_string())?;
    if &rest[..nb as usize] != build.as_bytes() {
        return Err("build".into());
    }
    let runs = FIXED as u64 + nb;
    let truns = runs + (RUN_BYTES as u64) * np;
    let sites = truns + (RUN_BYTES as u64) * nt;
    let entries = sites + (SITE_BYTES as u64) * ns;
    let counts = entries + (ENTRY_BYTES as u64) * ne;
    let mut end = counts;
    let mut hdr = None;
    let mut tlast = 0;
    for k in 0..(np + nt) as usize {
        let r = &rest[nb as usize + RUN_BYTES * k..];
        let (va, n, off) = (le(r, 0, 8), le(r, 8, 8), le(r, 16, 8));
        let tramp = k >= np as usize;
        if off % PAGE != 0
            || va % PAGE != 0
            || n % PAGE != 0
            || off < end
            || n == 0
            || (tramp && (va < tlast || va.saturating_add(n) > span))
        {
            return Err("page directory".into());
        }
        if tramp {
            tlast = va + n;
        }
        hdr.get_or_insert(off);
        end = off + n;
    }
    if end != len {
        return Err("length".into());
    }
    let mut w = [0u64; REPLY_WORDS];
    w[R_HDR] = hdr.unwrap_or(end);
    w[R_RUNS] = runs;
    w[R_NRUNS] = np;
    w[R_SITES] = sites;
    w[R_NSITES] = ns;
    w[R_TRAMP_VADDR] = le(&h, 56, 8);
    w[R_TRAMP_LEN] = span;
    w[R_TRUNS] = truns;
    w[R_NTRUNS] = nt;
    w[R_ENTRIES] = entries;
    w[R_NENTRIES] = ne;
    Ok((w, counts))
}

fn read_counts(f: &File, from: u64, to: u64) -> Vec<(String, u64)> {
    let mut b = vec![0u8; to.saturating_sub(from) as usize];
    if f.read_exact_at(&mut b, from).is_err() {
        return vec![];
    }
    let mut out = vec![];
    let mut p = 0;
    while p + 2 <= b.len() {
        let n = le(&b, p, 2) as usize;
        if n == 0 || p + 2 + n + 8 > b.len() {
            break;
        }
        let k = String::from_utf8_lossy(&b[p + 2..p + 2 + n]).to_string();
        out.push((k, le(&b, p + 2 + n, 8)));
        p += 2 + n + 8;
    }
    out
}

/// The executable load segments of an ELF file of this host's machine: (link address, file offset, file size). Only
/// those: a request is for an executable mapping, and the page it starts at can also hold the
/// end of the read-only segment before (lld's layout).
fn loads(f: &File) -> Option<Vec<(u64, u64, u64)>> {
    let mut eh = [0u8; 64];
    f.read_exact_at(&mut eh, 0).ok()?;
    let (phoff, phnum) = (le(&eh, 0x20, 8), le(&eh, 0x38, 2) as usize);
    if &eh[..4] != b"\x7fELF"
        || le(&eh, 0x12, 2) != super::HOST_MACHINE as u64
        || le(&eh, 0x36, 2) != 56
        || phnum > 4096
    {
        return None;
    }
    let mut ph = vec![0u8; 56 * phnum];
    f.read_exact_at(&mut ph, phoff).ok()?;
    Some(
        ph.chunks(56)
            .filter(|p| le(p, 0, 4) == 1 && le(p, 4, 4) & 1 != 0)
            .map(|p| (le(p, 0x10, 8), le(p, 8, 8), le(p, 0x20, 8)))
            .collect(),
    )
}

/// The link address the mapping offset `off` (page-aligned) holds: in the load segment whose
/// file range that page belongs to.
fn vaddr_of(loads: &[(u64, u64, u64)], off: u64) -> u64 {
    loads
        .iter()
        .find(|&&(_, o, n)| (o & !(PAGE - 1)) <= off && off < o + n.max(1))
        .map_or(u64::MAX, |&(v, o, _)| v.wrapping_sub(o).wrapping_add(off))
}

/// The plan cache's directory.
pub fn dir() -> PathBuf {
    crate::launch::cache_dir().join("plans")
}

/// An exclusive `flock` on the file `p` (created), held until it is dropped; `None` if it
/// cannot be had (no cache directory). `wait` is called once before blocking on another
/// holder. A lock file is only removed by a holder of it (`unlink_held`), so a lock had on a
/// file that is no longer `p` is let go and `p` locked again.
fn lock(p: &Path, wait: impl FnOnce()) -> Option<File> {
    let mut wait = Some(wait);
    loop {
        let f = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(p)
            .ok()?;
        let fd = f.as_raw_fd();
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            if let Some(w) = wait.take() {
                w();
            }
            while unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return None;
                }
            }
        }
        if still(&f, p) {
            return Some(f);
        }
    }
}

/// Is the open file `f` still the file at `p`?
fn still(f: &File, p: &Path) -> bool {
    match (f.metadata(), fs::metadata(p)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// An exclusive `flock` on the file `p` (created) if no one holds it now.
fn lock_now(p: &Path) -> Option<File> {
    let f = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(p)
        .ok()?;
    let held = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    (held && still(&f, p)).then_some(f)
}

/// Remove the lock file `p` while holding it (a process waiting on it then locks the new one).
fn unlink_held(p: &Path, _held: &File) {
    let _ = fs::remove_file(p);
}

/// A file's part of a planning period: begun at most once, ended when dropped.
struct BusyGuard<'a> {
    notice: &'a Arc<Notice>,
    begun: std::cell::Cell<bool>,
}

impl<'a> BusyGuard<'a> {
    fn new(notice: &'a Arc<Notice>) -> BusyGuard<'a> {
        BusyGuard {
            notice,
            begun: std::cell::Cell::new(false),
        }
    }

    fn begin(&self, path: &str, dir: &Path) {
        if !self.begun.replace(true) {
            self.notice.begin(path, dir);
        }
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        if self.begun.get() {
            self.notice.end();
        }
    }
}

/// The one line that says plans are being made, once a planning period has lasted `after`:
/// a second on a terminal, else ten (a log gets it only for a long wait). Printed at most
/// once per process, to stderr only, and never after the plans it names are made.
struct Notice {
    state: Mutex<NoticeState>,
    done: Condvar,
}

#[derive(Default)]
struct NoticeState {
    /// Files being made (or waited for) now; files begun in this period; the first's name.
    busy: usize,
    files: usize,
    first: String,
    said: bool,
    /// Planning periods begun: a watcher stops when its own has ended.
    period: u64,
}

impl Notice {
    fn after() -> Duration {
        use std::io::IsTerminal;
        if std::io::stderr().is_terminal() {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(10)
        }
    }

    /// A file's plan is being made (or waited for) until `end`.
    fn begin(self: &Arc<Self>, path: &str, dir: &Path) {
        let mut st = self.state.lock().unwrap();
        st.busy += 1;
        st.files += 1;
        if st.busy > 1 || st.said {
            return;
        }
        st.files = 1;
        st.period += 1;
        let period = st.period;
        st.first = Path::new(path)
            .file_name()
            .map_or(path.to_string(), |n| n.to_string_lossy().to_string());
        let (me, dir) = (self.clone(), dir.to_path_buf());
        let deadline = Instant::now() + Notice::after();
        // A period with nothing more to say ends its watcher at once: the line is never
        // printed after the plans are made.
        let _ = std::thread::Builder::new()
            .name("patina-plan-note".into())
            .spawn(move || {
                let mut st = me.state.lock().unwrap();
                loop {
                    if st.busy == 0 || st.said || st.period != period {
                        return;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    st = me.done.wait_timeout(st, deadline - now).unwrap().0;
                }
                st.said = true;
                let more = match st.files {
                    1 => String::new(),
                    n => format!(
                        " and {} more {}",
                        n - 1,
                        if n == 2 { "file" } else { "files" }
                    ),
                };
                eprintln!(
                    "patina: --preempt points: planning {}{more}, once: plans are kept in {}",
                    st.first,
                    dir.display()
                );
            });
    }

    fn end(&self) {
        let mut st = self.state.lock().unwrap();
        st.busy -= 1;
        if st.busy == 0 {
            self.done.notify_all();
        }
    }
}

impl Planner {
    /// Plans made on up to `threads` threads at once (more: sooner, never other bytes).
    pub fn new(build: &str, threads: usize) -> Planner {
        Planner {
            dir: dir(),
            build: build.to_string(),
            par: Par::new(threads).on(crate::launch::allowed_cpus()),
            notice: Arc::new(Notice {
                state: Mutex::new(NoticeState::default()),
                done: Condvar::new(),
            }),
            known: Mutex::new(HashMap::new()),
            reported: Mutex::new(vec![]),
            seen: Mutex::new(Default::default()),
        }
    }

    fn base(&self, sha: &str) -> PathBuf {
        let b: String = hex(&Sha256::digest(self.build.as_bytes()))[..16].to_string();
        self.dir.join(format!("{sha}-{b}"))
    }

    /// The SHA-256 of the file `f` (identity `m`), kept under its identity; and its bytes, if
    /// they were read for it.
    fn sha(&self, f: &File, m: &fs::Metadata) -> Res<([u8; 32], Option<Vec<u8>>)> {
        let at = crate::launch::cache_dir()
            .join("sha256")
            .join(format!("{}-{}", m.dev(), m.ino()));
        let k = format!("{} {}.{}", m.size(), m.ctime(), m.ctime_nsec());
        if let Some(h) = fs::read_to_string(&at).ok().and_then(|t| {
            let (kk, h) = t.rsplit_once(' ')?;
            (kk == k && h.len() == 64).then(|| h.to_string())
        }) {
            let mut out = [0u8; 32];
            for (i, o) in out.iter_mut().enumerate() {
                *o = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
            }
            return Ok((out, None));
        }
        let mut data = vec![0u8; m.size() as usize];
        f.read_exact_at(&mut data, 0).map_err(|e| e.to_string())?;
        let h: [u8; 32] = Sha256::digest(&data).into();
        let tmp = tmp_name(&at, "");
        let _ = fs::create_dir_all(at.parent().unwrap())
            .and_then(|_| fs::write(&tmp, format!("{k} {}", hex(&h))))
            .and_then(|_| fs::rename(&tmp, &at));
        Ok((h, Some(data)))
    }

    /// The cached plan at `base`, if its entry is sound.
    fn cached(&self, base: &Path, sha: &[u8; 32]) -> Option<(File, [u64; REPLY_WORDS], u64)> {
        let f = File::open(base.with_extension("plan")).ok()?;
        let m = f.metadata().ok()?;
        let ok = fs::read_to_string(base.with_extension("ok")).ok()?;
        let w: Vec<&str> = ok.split_whitespace().collect();
        let (hdr, counts) = header(&f, m.size(), sha, &self.build).ok()?;
        let same = w.len() == 4
            && w[0] == m.ino().to_string()
            && w[1] == m.size().to_string()
            && w[2] == format!("{}.{}", m.ctime(), m.ctime_nsec());
        if !same {
            // Written since it was verified, or copied: its bytes must be the ones verified.
            let mut d = vec![0u8; m.size() as usize];
            f.read_exact_at(&mut d, 0).ok()?;
            if w.len() != 4 || hex(&Sha256::digest(&d)) != w[3] {
                return None;
            }
            self.seal(base, &f, w[3]);
        }
        // The least recently used go first when the cache is full.
        let _ = File::options()
            .append(true)
            .open(base.with_extension("ok"))
            .and_then(|o| o.set_modified(std::time::SystemTime::now()));
        Some((f, hdr, counts))
    }

    /// Write the `.ok` of the plan `f` at `base` (its identity and digest), whole then renamed.
    fn seal(&self, base: &Path, f: &File, digest: &str) {
        let Ok(m) = f.metadata() else { return };
        let tmp = tmp_name(base, "ok");
        let line = format!(
            "{} {} {}.{} {digest}\n",
            m.ino(),
            m.size(),
            m.ctime(),
            m.ctime_nsec()
        );
        let _ = fs::write(&tmp, line).and_then(|_| fs::rename(&tmp, base.with_extension("ok")));
    }

    /// Make, verify and keep the plan of `elf`; the plan file, opened read-only.
    fn make(&self, base: &Path, elf: &Elf) -> Result<(File, u128), (u64, String)> {
        let t0 = Instant::now();
        let (plan, bytes, bad) =
            super::plan_verified(elf, &self.build, &self.par).map_err(|e| (NONE_REFUSED, e))?;
        if plan.sites.is_empty() && plan.entries.is_empty() {
            return Err((NONE_EMPTY, "no site".into()));
        }
        if let Some(b) = bad.first() {
            return Err((
                NONE_UNVERIFIED,
                format!(
                    "the plan failed verification ({} findings; first: {b})",
                    bad.len()
                ),
            ));
        }
        drop(plan);
        let tmp = tmp_name(base, "plan");
        let (written, digest) = self.par.join(
            || {
                fs::create_dir_all(&self.dir)
                    .and_then(|_| fs::write(&tmp, &bytes))
                    .and_then(|_| File::open(&tmp))
            },
            || hex(&Sha256::digest(&bytes)),
        );
        let ms = t0.elapsed().as_millis();
        // The `.ok` after the rename (which moves the change time): until it is there, the
        // entry is not used.
        let kept = written
            .and_then(|f| fs::rename(&tmp, base.with_extension("plan")).map(|_| f))
            .inspect(|f| self.seal(base, f, &digest));
        let file = match kept {
            Ok(f) => {
                self.evict(base);
                f
            }
            Err(_) => {
                // No cache (read-only or full): the plan lives in an unlinked file for this run.
                let _ = fs::remove_file(&tmp);
                tempfile_with(&bytes).map_err(|e| (NONE_REFUSED, e))?
            }
        };
        Ok((file, ms))
    }

    /// Keep the cache under `CACHE_MAX`: remove the least recently used plans but `keep`.
    fn evict(&self, keep: &Path) {
        let Ok(rd) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut plans: Vec<(std::time::SystemTime, u64, PathBuf)> = rd
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let ext = p.extension()?.to_str()?;
                if ext != "plan" {
                    // A plan being written (`tmp_name`) whose entry no writer holds: left by
                    // a process that was killed.
                    if ext.starts_with("plan")
                        && ext[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
                    {
                        let l = p.with_extension("lock");
                        if let Some(held) = lock_now(&l) {
                            let _ = fs::remove_file(&p);
                            if !p.with_extension("plan").exists() {
                                unlink_held(&l, &held);
                            }
                        }
                    }
                    return None;
                }
                let n = e.metadata().ok()?.len();
                let used = fs::metadata(p.with_extension("ok"))
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                Some((used, n, p))
            })
            .collect();
        let mut total: u64 = plans.iter().map(|p| p.1).sum();
        if total <= CACHE_MAX {
            return;
        }
        plans.sort();
        for (_, n, p) in plans {
            if total <= CACHE_MAX / 4 * 3 {
                break;
            }
            if p == keep.with_extension("plan") {
                continue;
            }
            // An entry another process is making or sealing is left to it.
            let l = p.with_extension("lock");
            let Some(held) = lock_now(&l) else {
                continue;
            };
            let _ = fs::remove_file(p.with_extension("ok"));
            if fs::remove_file(&p).is_ok() {
                total -= n;
            }
            unlink_held(&l, &held);
        }
    }

    fn entry(&self, f: &File, m: &fs::Metadata, path: &str) -> Res<Entry> {
        // Nothing is read whole before the file is a 64-bit ELF file with executable load
        // segments, of a size the host reads.
        let loads = loads(f).filter(|l| !l.is_empty() && m.size() <= FILE_MAX);
        let (sha, read) = match loads {
            Some(_) => self.sha(f, m)?,
            None => ([0; 32], None),
        };
        let mut report = ImageReport {
            path: path.to_string(),
            sha256: hex(&sha),
            status: "planned",
            why: String::new(),
            counts: vec![],
            cache: "hit",
            ms: 0,
        };
        let none = |why: u64, text: String, mut r: ImageReport| {
            r.status = match why {
                NONE_NOT_ELF => "not-elf",
                NONE_REFUSED => "refused",
                NONE_UNVERIFIED => "unverified",
                _ => "empty",
            };
            r.why = text;
            Entry::None(why, r)
        };
        let Some(loads) = loads else {
            let why = format!(
                "not a 64-bit ELF file with executable segments of at most {FILE_MAX} bytes"
            );
            return Ok(none(NONE_NOT_ELF, why, report));
        };
        let base = self.base(&report.sha256);
        let known = |report: &ImageReport| -> Option<Res<Entry>> {
            let t = fs::read_to_string(base.with_extension("none")).ok()?;
            let (w, text) = t.split_once(' ')?;
            let w = w.parse().ok()?;
            Some(Ok(none(w, text.trim_end().to_string(), report.clone())))
        };
        if let Some(e) = known(&report) {
            return e;
        }
        let mut found = self.cached(&base, &sha);
        // A miss: made here while this process holds the entry's lock, unless another process
        // that held it first made it meanwhile.
        let mut _held = None;
        let busy = BusyGuard::new(&self.notice);
        if found.is_none() {
            let _ = fs::create_dir_all(&self.dir);
            _held = lock(&base.with_extension("lock"), || busy.begin(path, &self.dir));
            if let Some(e) = known(&report) {
                return e;
            }
            found = self.cached(&base, &sha);
            if found.is_none() {
                busy.begin(path, &self.dir);
            }
        }
        let (file, hdr, counts) = match found {
            Some(c) => c,
            None => {
                if base.with_extension("plan").exists() {
                    report.cache = "rebuilt";
                } else {
                    report.cache = "made";
                }
                let data = match read {
                    Some(d) => d,
                    None => {
                        let mut data = vec![0u8; m.size() as usize];
                        f.read_exact_at(&mut data, 0).map_err(|e| e.to_string())?;
                        if Sha256::digest(&data)[..] != sha[..] {
                            return Err(format!("{path}: changed while being planned"));
                        }
                        data
                    }
                };
                let elf = match Elf::parse_hashed(&data, sha) {
                    Ok(e) => e,
                    Err(e) => return Ok(none(NONE_NOT_ELF, e, report)),
                };
                match self.make(&base, &elf) {
                    Ok((file, ms)) => {
                        report.ms = ms as u64;
                        let len = file.metadata().map_err(|e| e.to_string())?.len();
                        let (hdr, counts) = header(&file, len, &sha, &self.build)
                            .map_err(|e| format!("{path}: the plan just made: {e}"))?;
                        (file, hdr, counts)
                    }
                    Err((why, text)) => {
                        let _ = fs::create_dir_all(&self.dir).and_then(|_| {
                            fs::write(base.with_extension("none"), format!("{why} {text}\n"))
                        });
                        return Ok(none(why, text, report));
                    }
                }
            }
        };
        report.counts = read_counts(&file, counts, hdr[R_HDR]);
        Ok(Entry::Plan {
            file: Arc::new(file),
            hdr,
            loads: Arc::new(loads),
            report,
        })
    }

    fn lookup(&self, f: &File, path: &str) -> Res<(Key, Entry)> {
        let m = f.metadata().map_err(|e| format!("{path}: {e}"))?;
        let k = key(&m);
        if let Some(e) = self.known.lock().unwrap().get(&k) {
            return Ok((k, e.clone()));
        }
        let e = self.entry(f, &m, path)?;
        self.known.lock().unwrap().insert(k, e.clone());
        Ok((k, e))
    }

    /// The broker's answer for a mapping of the file `f` (named `path` by the program) at the
    /// file offset `off`: the reply's words and the plan file to send with them.
    pub fn answer(
        &self,
        f: &File,
        off: u64,
        path: &str,
    ) -> Res<([u64; REPLY_WORDS], Option<File>)> {
        let (k, e) = self.lookup(f, path)?;
        let report = match &e {
            Entry::Plan { report, .. } | Entry::None(_, report) => report,
        };
        if self.seen.lock().unwrap().insert(k) {
            self.reported.lock().unwrap().push(report.clone());
        }
        match e {
            Entry::None(why, _) => {
                let mut w = [0u64; REPLY_WORDS];
                w[R_STATUS] = why;
                Ok((w, None))
            }
            Entry::Plan {
                file, hdr, loads, ..
            } => {
                let mut w = hdr;
                w[R_STATUS] = OK;
                w[R_VADDR] = vaddr_of(&loads, off);
                let dup = file.try_clone().map_err(|e| format!("{path}: {e}"))?;
                Ok((w, Some(dup)))
            }
        }
    }

    /// Plan `path` ahead of the run (the launcher's pre-pass): errors are left for the
    /// broker to meet again.
    pub fn warm(&self, path: &Path) {
        if let Ok(f) = File::open(path) {
            let _ = self.lookup(&f, &path.to_string_lossy());
        }
    }

    /// The files the runtime asked for, in order, as `result.json` lists them.
    pub fn images(&self) -> Vec<serde_json::Value> {
        self.reported
            .lock()
            .unwrap()
            .iter()
            .map(ImageReport::json)
            .collect()
    }
}

/// A sealed memory file holding `bytes`: nothing can write it after this.
fn tempfile_with(bytes: &[u8]) -> Res<File> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    let name = c"patina-plan";
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(format!("plan: memfd: {}", std::io::Error::last_os_error()));
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes).map_err(|e| format!("plan: {e}"))?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(format!("plan: seal: {}", std::io::Error::last_os_error()));
    }
    Ok(f)
}

/// The program and the shared libraries it needs (`DT_NEEDED`, followed through `DT_RUNPATH`
/// or `DT_RPATH` with `$ORIGIN`, then the system's directories) and its interpreter: what the
/// pre-pass plans before the sandbox starts, so a first run plans them in parallel. A file not
/// found here is planned when the runtime asks for it.
pub fn closure(program: &Path) -> Vec<PathBuf> {
    #[cfg(target_arch = "x86_64")]
    const MULTIARCH: &str = "x86_64-linux-gnu";
    #[cfg(target_arch = "aarch64")]
    const MULTIARCH: &str = "aarch64-linux-gnu";
    let (lib, usr) = (format!("/lib/{MULTIARCH}"), format!("/usr/lib/{MULTIARCH}"));
    let dirs: [&str; 4] = [&lib, &usr, "/lib64", "/usr/lib"];
    let mut out: Vec<PathBuf> = vec![];
    let mut todo = vec![program.to_path_buf()];
    while let Some(p) = todo.pop() {
        // One file once, whatever path names it (`/lib64/ld-linux-x86-64.so.2` is a link).
        let p = fs::canonicalize(&p).unwrap_or(p);
        if out.contains(&p) || out.len() > 256 {
            continue;
        }
        let Ok(data) = fs::read(&p) else { continue };
        out.push(p.clone());
        let Ok(d) = needed(&data) else { continue };
        let origin = p
            .parent()
            .unwrap_or(Path::new("/"))
            .to_string_lossy()
            .to_string();
        if let Some(i) = d.interp {
            todo.push(PathBuf::from(i));
        }
        for n in d.needed {
            let dirs = d
                .runpath
                .iter()
                .flat_map(|r| r.split(':'))
                .map(|r| r.replace("$ORIGIN", &origin).replace("${ORIGIN}", &origin))
                .chain(dirs.iter().map(|s| s.to_string()));
            for dir in dirs {
                let c = Path::new(&dir).join(&n);
                if c.is_file() {
                    todo.push(c);
                    break;
                }
            }
        }
    }
    out
}

struct Needed {
    interp: Option<String>,
    needed: Vec<String>,
    runpath: Option<String>,
}

fn needed(d: &[u8]) -> Res<Needed> {
    let g = |o: usize, n: usize| -> Res<u64> {
        d.get(o..o + n)
            .map(|_| le(d, o, n))
            .ok_or_else(|| "short".to_string())
    };
    if d.get(..4) != Some(b"\x7fELF") || d.get(4) != Some(&2) {
        return Err("not ELF".into());
    }
    let (phoff, phnum) = (g(0x20, 8)? as usize, g(0x38, 2)? as usize);
    let mut loads = vec![];
    let (mut dynamic, mut interp) = (None, None);
    for i in 0..phnum {
        let p = phoff + 56 * i;
        let (t, off, va, fsz) = (g(p, 4)?, g(p + 8, 8)?, g(p + 16, 8)?, g(p + 32, 8)?);
        match t {
            1 => loads.push((va, off, fsz)),
            2 => dynamic = Some((off as usize, fsz as usize)),
            3 => {
                let s = d.get(off as usize..(off + fsz) as usize).ok_or("interp")?;
                interp = Some(
                    String::from_utf8_lossy(s)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    let file_of = |va: u64| -> Option<usize> {
        loads
            .iter()
            .find(|&&(v, _, n)| va >= v && va < v + n)
            .map(|&(v, o, _)| (o + va - v) as usize)
    };
    let mut r = Needed {
        interp,
        needed: vec![],
        runpath: None,
    };
    let Some((doff, dsz)) = dynamic else {
        return Ok(r);
    };
    let (mut strtab, mut names, mut rp) = (None, vec![], None);
    for k in 0..dsz / 16 {
        let (tag, val) = (g(doff + 16 * k, 8)?, g(doff + 16 * k + 8, 8)?);
        match tag {
            0 => break,
            1 => names.push(val),
            5 => strtab = Some(val),
            15 | 29 => rp = Some(val),
            _ => {}
        }
    }
    let Some(st) = strtab.and_then(file_of) else {
        return Ok(r);
    };
    let s = |o: u64| -> Option<String> {
        let b = d.get(st + o as usize..)?;
        let n = b.iter().position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(&b[..n]).to_string())
    };
    r.needed = names.into_iter().filter_map(s).collect();
    r.runpath = rp.and_then(s);
    Ok(r)
}

impl ImageReport {
    fn get(&self, k: &str) -> u64 {
        self.counts
            .iter()
            .find(|(n, _)| n == k)
            .map_or(0, |(_, v)| *v)
    }

    /// `result.json`'s entry for this image: what `--preempt points` did to it.
    pub fn json(&self) -> serde_json::Value {
        let pct = |a: u64, b: u64| (1000.0 * a as f64 / b.max(1) as f64).round() / 10.0;
        let (mut found, mut covered) = (0, 0);
        for c in super::class::Class::ALL {
            let n = |o: &str| self.get(&format!("{}.{o}", c.name()));
            found += n("found");
            covered += n("in-place") + n("moved") + n("shared") + n("grouped");
        }
        let n = |o: &str| self.get(&format!("back-branch.{o}"));
        let mut v = serde_json::json!({
            "path": self.path,
            "sha256": self.sha256,
            "status": self.status,
        });
        if !self.why.is_empty() {
            v["why"] = self.why.clone().into();
        }
        if self.status == "planned" {
            let text = self.get("text-bytes");
            v["text_bytes"] = text.into();
            v["dark_pct"] = pct(self.get("dark-bytes") + self.get("tainted-bytes"), text).into();
            v["sites"] = found.into();
            v["patches"] = self.get("patches").into();
            v["covered_pct"] = pct(covered, found).into();
            v["back_edges_covered_pct"] = pct(
                n("in-place") + n("moved") + n("shared") + n("grouped"),
                n("found"),
            )
            .into();
            v["cpuid_patched"] = self.get("cpuid-patched").into();
            v["cpuid_unpatched"] = self.get("cpuid-unpatched").into();
            v["cache"] = self.cache.into();
            v["rewrite_ms"] = self.ms.into();
        }
        v
    }
}

/// `patina cache [clear]`: where the plans are, how many and how large (of `CACHE_MAX`); with
/// `clear`, delete them (a plan is only a cache: the next run makes it again).
pub fn main(a: &crate::cli::Args) -> Res<std::process::ExitCode> {
    let d = dir();
    let clear = match a.positional.as_slice() {
        [] => false,
        [c] if c == "clear" => true,
        other => return Err(format!("patina cache: unexpected {}", other.join(" "))),
    };
    let (mut plans, mut bytes, mut freed) = (0u64, 0u64, 0u64);
    for e in fs::read_dir(&d).into_iter().flatten().flatten() {
        let p = e.path();
        let n = e.metadata().map_or(0, |m| m.len());
        let lockfile = p.extension().is_some_and(|x| x == "lock");
        if p.extension().is_some_and(|x| x == "plan") {
            plans += 1;
            bytes += n;
        }
        if clear && !lockfile && fs::remove_file(&p).is_ok() {
            freed += n;
        }
    }
    // The lock files last, each while held: one a process holds stays (its plan, being made,
    // lands after the clear).
    if clear {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "lock") {
                if let Some(held) = lock_now(&p) {
                    unlink_held(&p, &held);
                }
            }
        }
    }
    let size = crate::report::bytes;
    if a.json() {
        let mut v = serde_json::json!({
            "dir": d,
            "plans": plans,
            "bytes": bytes,
            "max_bytes": CACHE_MAX,
        });
        if clear {
            v["cleared_bytes"] = freed.into();
        }
        println!("{v}");
    } else if clear {
        println!("cleared {}: {plans} plans, {}", d.display(), size(freed));
    } else {
        println!(
            "{}: {plans} plans, {} (at most {}, the least recently used removed first)",
            d.display(),
            size(bytes),
            size(CACHE_MAX)
        );
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Plan the files of `closure(program)`, the largest first, on the planner's threads.
pub fn warm_all(planner: &Planner, program: &Path) {
    let mut files: Vec<(u64, PathBuf)> = closure(program)
        .into_iter()
        .map(|p| (fs::metadata(&p).map_or(0, |m| m.len()), p))
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    planner.par.each(&files, |_, (_, f)| planner.warm(f));
}
