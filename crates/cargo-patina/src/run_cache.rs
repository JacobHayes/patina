//! What the supervisor derives from an executable's bytes, kept on disk by
//! content so the next run of the same bytes does not derive it again.
//!
//! Every run of a native guest reads the whole executable several times over:
//! the pre-run gate decodes all of its code, a recording or replay hashes it
//! with SHA-256, and the instrumentation and Go-meter
//! scans search it for markers. Test suites and campaigns run one build
//! hundreds of times, so those reads cost more than the guest does.
//!
//! An entry is addressed by the BLAKE3 digest of the exact bytes it describes,
//! which is computed afresh on every run from the bytes the run then uses: an
//! executable changed in place, whatever its size, timestamps or inode, has
//! another digest and is judged again. Entries live under a directory named by
//! the running `cargo-patina`'s own build ID, so a rebuilt supervisor, whose
//! gate may judge differently, never reads an older one's results; a
//! supervisor without a build ID keeps nothing. Everything here is
//! best-effort: an entry that cannot be read or written is derived again.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use patina_dst_trace::Sha256Digest;
use sha2::{Digest, Sha256};

/// A file's bytes, mapped read-only, and their BLAKE3 digest once asked for.
pub(crate) struct Image {
    map: memmap2::Mmap,
    digest: OnceLock<String>,
}

impl Image {
    pub(crate) fn map(file: &fs::File) -> std::io::Result<Self> {
        // SAFETY: the mapping is private and read-only. The bytes are those of
        // an executable about to run (or of the running supervisor) and are not
        // expected to change while it is mapped; one rewritten in place would
        // change the bytes read here, as reading it into memory could too, and
        // one truncated faults the supervisor before any guest starts.
        let map = unsafe { memmap2::Mmap::map(file)? };
        Ok(Self {
            map,
            digest: OnceLock::new(),
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.map
    }

    /// The BLAKE3 digest of [`Self::bytes`], in hex: the address of every
    /// cache entry about them.
    pub(crate) fn digest(&self) -> &str {
        self.digest
            .get_or_init(|| blake3::hash(&self.map).to_hex().to_string())
    }

    /// The SHA-256 of [`Self::bytes`], from the cache when these bytes were
    /// hashed before.
    pub(crate) fn sha256(&self) -> Sha256Digest {
        self.remember("sha256", || {
            Ok::<_, std::convert::Infallible>(Sha256Digest(Sha256::digest(self.bytes()).into()))
        })
        .unwrap_or_else(|never| match never {})
    }

    /// The `fact` [`Self::bytes`] give `derive`, from the cache when it was
    /// derived from these bytes before. A failure is not remembered.
    pub(crate) fn remember<T, E>(
        &self,
        fact: &str,
        derive: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let name = format!("{}.{fact}", self.digest());
        if let Some(value) = load(&name).and_then(|text| serde_json::from_str(&text).ok()) {
            return Ok(value);
        }
        let value = derive()?;
        if let Ok(text) = serde_json::to_string(&value) {
            self.store_unchanged(&name, &text);
        }
        Ok(value)
    }

    /// Store `value` as the cache entry `name` about these bytes, unless they
    /// changed while it was derived: the file can be rewritten in place under
    /// the mapping, and an entry must describe the bytes its name addresses.
    pub(crate) fn store_unchanged(&self, name: &str, value: &str) {
        if blake3::hash(&self.map).to_hex().as_str() == self.digest() {
            store(name, value);
        }
    }
}

/// The cache entry `name`, if this supervisor stored one.
pub(crate) fn load(name: &str) -> Option<String> {
    fs::read_to_string(dir()?.join(name)).ok()
}

/// Store `value` as the cache entry `name`, replacing it whole.
fn store(name: &str, value: &str) {
    if !file_size_limit_admits(value.len()) {
        return;
    }
    let Some(dir) = dir() else { return };
    if !dir.exists() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
        if let Some(parent) = dir.parent() {
            prune(parent, dir);
        }
    }
    let Ok(mut staged) = tempfile::NamedTempFile::new_in(dir) else {
        return;
    };
    if std::io::Write::write_all(&mut staged, value.as_bytes()).is_ok() {
        let _ = staged.persist(dir.join(name));
    }
}

/// Whether the process's file size limit lets it write a file of `len` bytes.
/// A run under a lower limit would otherwise die of `SIGXFSZ` writing an entry
/// it could do without, before it reports anything.
#[cfg(unix)]
fn file_size_limit_admits(len: usize) -> bool {
    #[repr(C)]
    struct Rlimit {
        current: u64,
        maximum: u64,
    }
    const RLIMIT_FSIZE: i32 = 1;
    unsafe extern "C" {
        fn getrlimit(resource: i32, limit: *mut Rlimit) -> i32;
    }
    let mut limit = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `limit` is a writable rlimit.
    unsafe { getrlimit(RLIMIT_FSIZE, &mut limit) == 0 && limit.current >= len as u64 }
}

#[cfg(not(unix))]
fn file_size_limit_admits(_len: usize) -> bool {
    true
}

/// `<patina cache>/run-cache/<build ID of this cargo-patina>`.
fn dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let build_id = crate::supervisor_identity::build_id()?;
        let root = crate::shim_build::patina_cache_root().ok()?;
        Some(root.join("run-cache").join(build_id))
    })
    .as_deref()
}

/// How long another supervisor's entries outlive its last new one.
const KEEP_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// Remove the other supervisors' entry directories that gained no entry for
/// [`KEEP_IDLE`]. Each development build of `cargo-patina` has its own, so
/// without this they would pile up.
fn prune(root: &Path, own: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let idle = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| now.duration_since(modified).unwrap_or_default() > KEEP_IDLE);
        if idle && path != own {
            let _ = fs::remove_dir_all(&path);
        }
    }
}
