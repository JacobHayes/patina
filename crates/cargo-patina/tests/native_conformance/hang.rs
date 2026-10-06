//! Guest journal and process-state observation for positively confirmed hangs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a watched guest's journal, state and kernel activity must stay
/// unchanged before its hang is confirmed. A completed leg's slowest step is
/// a single call; one second of nothing is no step.
const HANG_QUIET: Duration = Duration::from_secs(1);

/// How often a watched guest is looked at.
const HANG_LOOK: Duration = Duration::from_millis(100);

/// One look at a patina guest: its journal (`patina_dst_conformance::journal`)
/// and its scheduling state — per-task state letters, system time and
/// voluntary context switches, which move whenever it makes a kernel call
/// (blocked or spinning in user space, they stand still). User time is left
/// out: a spinning guest burns it without progress.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GuestLook {
    pid: u32,
    started: bool,
    journal_len: u64,
    tasks: Vec<(char, u64, u64)>,
}

/// Confirms a declared hang positively, or not at all. From `within` after
/// the leg began it looks at the guest every [`HANG_LOOK`]; a hang is
/// confirmed once the guest has started (the journal's start marker) and a
/// look equal to the first of the current window lasts [`HANG_QUIET`]. Any
/// change starts a new window, so a slow but progressing leg is never
/// confirmed and keeps the normal run deadline.
pub(super) struct HangWatch {
    began: Instant,
    binary: PathBuf,
    /// The journal's link-time address and the lowest segment address.
    symbol: u64,
    lowest: u64,
    window: Option<(Instant, GuestLook)>,
    next_look: Instant,
    /// The journal's bytes once the hang is confirmed.
    pub(super) journal: Option<Vec<u8>>,
    pub(super) last_seen: String,
}

impl HangWatch {
    pub(super) fn new(within: Duration, binary: &Path) -> Result<HangWatch, String> {
        use object::{Object, ObjectSegment, ObjectSymbol};
        let data = std::fs::read(binary).map_err(|error| format!("read {binary:?}: {error}"))?;
        let file =
            object::File::parse(&*data).map_err(|error| format!("parse {binary:?}: {error}"))?;
        let symbol = file
            .symbols()
            .find(|symbol| symbol.name() == Ok(patina_dst_conformance::journal::SYMBOL))
            .map(|symbol| symbol.address())
            .ok_or_else(|| format!("{binary:?} has no journal symbol"))?;
        let lowest = file
            .segments()
            .map(|segment| segment.address())
            .min()
            .unwrap_or(0);
        let binary = binary
            .canonicalize()
            .map_err(|error| format!("canonicalize {binary:?}: {error}"))?;
        let now = Instant::now();
        Ok(HangWatch {
            began: now,
            binary,
            symbol,
            lowest,
            window: None,
            next_look: now + within,
            journal: None,
            last_seen: "never looked (the watch starts at the gap's `within`)".into(),
        })
    }

    /// The early-stop hook of the leg's run: true once the hang is confirmed.
    pub(super) fn confirmed(&mut self, supervisor: u32) -> bool {
        let now = Instant::now();
        if now < self.next_look {
            return false;
        }
        self.next_look = now + HANG_LOOK;
        let Some(look) = self.look(supervisor) else {
            self.window = None;
            return false;
        };
        self.last_seen = format!(
            "{look:?} at {:?} into the leg (changed since the window began: {})",
            now.duration_since(self.began),
            self.window.as_ref().is_none_or(|(_, first)| *first != look)
        );
        match &self.window {
            Some((since, first)) if *first == look && look.started => {
                if now.duration_since(*since) < HANG_QUIET {
                    return false;
                }
                self.last_seen = format!(
                    "{look:?} unchanged for {:?}, {:?} into the leg",
                    now.duration_since(*since),
                    now.duration_since(self.began)
                );
                self.journal = self.journal_bytes(look.pid, look.journal_len);
                self.journal.is_some()
            }
            _ => {
                self.window = Some((now, look));
                false
            }
        }
    }

    /// The supervisor's child running the probe binary, looked at once.
    fn look(&mut self, supervisor: u32) -> Option<GuestLook> {
        let pid = std::fs::read_dir("/proc")
            .ok()?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .find(|pid| {
                stat_fields(&format!("/proc/{pid}/stat"))
                    .is_some_and(|fields| fields.get(1) == Some(&supervisor.to_string()))
                    && std::fs::read_link(format!("/proc/{pid}/exe"))
                        .ok()
                        .as_deref()
                        == Some(self.binary.as_path())
            });
        let Some(pid) = pid else {
            self.last_seen = "no guest process yet (still starting)".into();
            return None;
        };
        let header = self.read(pid, 0, 16)?;
        let started = u64::from_ne_bytes(header[..8].try_into().unwrap())
            == patina_dst_conformance::journal::STARTED;
        let journal_len = u64::from_ne_bytes(header[8..].try_into().unwrap());
        let mut tasks = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/{pid}/task")).ok()? {
            let task = entry.ok()?.path();
            let fields = stat_fields(&task.join("stat").display().to_string())?;
            let state = fields.first()?.chars().next()?;
            let stime = fields.get(12)?.parse().ok()?;
            let voluntary = std::fs::read_to_string(task.join("status"))
                .ok()?
                .lines()
                .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))?
                .trim()
                .parse()
                .ok()?;
            tasks.push((state, stime, voluntary));
        }
        tasks.sort();
        Some(GuestLook {
            pid,
            started,
            journal_len,
            tasks,
        })
    }

    /// The journal's bytes `[..len]`, read from the guest's memory.
    fn journal_bytes(&self, pid: u32, len: u64) -> Option<Vec<u8>> {
        if len == patina_dst_conformance::journal::OVERFLOWED {
            return None;
        }
        self.read(pid, patina_dst_conformance::journal::BYTES_AT, len as usize)
    }

    /// `len` bytes at `offset` into the guest's journal (`/proc/<pid>/mem`: the
    /// test process is the guest's ancestor, which Yama's ptrace scope 1
    /// allows).
    fn read(&self, pid: u32, offset: u64, len: usize) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let binary = self.binary.display().to_string();
        let start = maps.lines().find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 6 && fields[2] == "00000000" && fields[5] == binary)
                .then(|| u64::from_str_radix(fields[0].split('-').next().unwrap_or(""), 16).ok())?
        })?;
        let address = start - (self.lowest & !0xfff) + self.symbol + offset;
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
        mem.seek(SeekFrom::Start(address)).ok()?;
        let mut bytes = vec![0; len];
        mem.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
}

/// The fields of a `/proc/…/stat` line after the command name (which may
/// hold spaces): state first, then the parent pid.
fn stat_fields(path: &str) -> Option<Vec<String>> {
    let line = std::fs::read_to_string(path).ok()?;
    let rest = &line[line.rfind(')')? + 1..];
    Some(rest.split_whitespace().map(str::to_string).collect())
}
