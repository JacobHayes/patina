//! The disks of a run a sweep keeps. A run writes each boot's (and each machine
//! disk's) final tree as `live.tree` and the tree a crash left as the directory `post-crash/`;
//! they are most of a run directory's size, and every reader in the run itself (the next
//! boot, loss attribution, the operation log's self-check, the checker) has used them
//! by the time the run ends. A sweep keeping a run (`sweep::cut`, not `--keep all`) packs
//! them: `live.tree.zst` and `post-crash.tree.zst`, zstd frames of the tree archive
//! (`tree::Tree::encode`), several times smaller (3 to 20 times on database-like trees).
//! `post-crash/` stays a directory in a run a checker reads (its own outcome ok: `report --recheck`
//! judges it again, and a checker run on it by hand reads what the run's did). Every reader
//! takes either form (`live`, `post_crash`).

use super::tree::Tree;
use std::fs;
use std::path::{Path, PathBuf};

pub const LIVE: &str = "live.tree";
pub const LIVE_PACKED: &str = "live.tree.zst";
pub const POST: &str = "post-crash";
pub const POST_PACKED: &str = "post-crash.tree.zst";

fn compress(raw: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(raw, ruzstd::encoding::CompressionLevel::Fastest)
}

/// The bytes of a zstd frame, `p` naming it in an error.
fn decompress(b: &[u8], p: &Path) -> Result<Vec<u8>, String> {
    let mut d = ruzstd::decoding::StreamingDecoder::new(b)
        .map_err(|e| format!("{}: not a packed tree: {e}", p.display()))?;
    let mut out = vec![];
    std::io::Read::read_to_end(&mut d, &mut out)
        .map_err(|e| format!("{}: not a packed tree: {e}", p.display()))?;
    Ok(out)
}

fn read_packed(p: &Path) -> Result<Tree, String> {
    let b = fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Tree::decode(&decompress(&b, p)?).map_err(|e| format!("{}: {e}", p.display()))
}

/// Whether boot (or machine disk) directory `bdir` holds the tree it ended with.
pub fn has_live(bdir: &Path) -> bool {
    bdir.join(LIVE).is_file() || bdir.join(LIVE_PACKED).is_file()
}

/// The tree boot (or machine disk) directory `bdir` ended with.
pub fn live(bdir: &Path) -> Result<Tree, String> {
    let raw = bdir.join(LIVE);
    if raw.is_file() || !bdir.join(LIVE_PACKED).is_file() {
        return Tree::read_archive(&raw);
    }
    read_packed(&bdir.join(LIVE_PACKED))
}

/// The tree the crash that ended `bdir` left (the next one started from), if it is kept.
pub fn post_crash(bdir: &Path) -> Result<Option<Tree>, String> {
    let dir = bdir.join(POST);
    if dir.is_dir() {
        return Tree::from_dir(&dir)
            .map(Some)
            .map_err(|e| format!("{}: {e}", dir.display()));
    }
    let p = bdir.join(POST_PACKED);
    if p.is_file() {
        return read_packed(&p).map(Some);
    }
    Ok(None)
}

/// Write `raw` compressed to `to`, checking that it reads back whole first: the original goes
/// only once its packed form is known to hold it.
fn write_packed(raw: &[u8], to: &Path) -> Result<(), String> {
    let packed = compress(raw);
    if decompress(&packed, to)? != raw {
        return Err(format!(
            "{}: the packed tree does not read back",
            to.display()
        ));
    }
    fs::write(to, &packed).map_err(|e| format!("{}: {e}", to.display()))
}

/// Pack the trees of boot (or machine disk) directory `bdir`: `live.tree` to
/// `live.tree.zst`, and with `post` `post-crash/` to `post-crash.tree.zst`. Packing again is
/// a no-op; a pack stopped midway leaves both forms, and readers take the unpacked one.
pub fn pack(bdir: &Path, post: bool) -> Result<(), String> {
    let raw = bdir.join(LIVE);
    if raw.is_file() {
        let b = fs::read(&raw).map_err(|e| format!("{}: {e}", raw.display()))?;
        write_packed(&b, &bdir.join(LIVE_PACKED))?;
        fs::remove_file(&raw).map_err(|e| format!("{}: {e}", raw.display()))?;
    }
    let dir = bdir.join(POST);
    if post && dir.is_dir() {
        let t = Tree::from_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        write_packed(&t.encode(), &bdir.join(POST_PACKED))?;
        fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Pack every boot of run `run` (`pack`), a few at a time; one that fails stays as it
/// was.
pub fn pack_run(run: &Path, post: bool) {
    // Packing costs about as much CPU as the run that wrote the trees: four at once keep a
    // sweep's event loop from falling behind its jobs (a 30 MB tree holds about 100 MB while
    // it is packed).
    for some in bdirs(run).chunks(4) {
        std::thread::scope(|s| {
            for bdir in some {
                s.spawn(move || pack(bdir, post));
            }
        });
    }
}

/// Every boot directory of run `run` that can hold trees: main's, then each
/// machine's.
pub fn bdirs(run: &Path) -> Vec<PathBuf> {
    let mut v = super::check::boots(run);
    let mut names: Vec<PathBuf> = fs::read_dir(run.join("machine"))
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    names.sort();
    for n in names {
        v.extend(super::check::boots(&n));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run directory holding one boot with a live tree and a post-crash tree, and an
    /// boot of machine `a` with a live tree: packed, each reads back as it was written,
    /// smaller by a wide margin; `post-crash/` packed only when asked.
    #[test]
    fn packed_trees_read_back_as_written() {
        let base = std::env::var_os("PATINA_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let run = base.join(format!("patina-kept-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&run);
        let (bdir, machine) = (run.join("boot-1"), run.join("machine/a/boot-1"));
        fs::create_dir_all(&bdir).unwrap();
        fs::create_dir_all(&machine).unwrap();
        let src = run.join("src");
        fs::create_dir_all(src.join("d")).unwrap();
        let rows: Vec<u8> = (0..20_000)
            .flat_map(|i| format!("row {i:08} status=active\n").into_bytes())
            .collect();
        fs::write(src.join("db"), &rows).unwrap();
        fs::write(src.join("d/f"), b"x").unwrap();
        std::os::unix::fs::symlink("db", src.join("l")).unwrap();
        let live = Tree::from_dir(&src).unwrap();
        fs::write(bdir.join(LIVE), live.encode()).unwrap();
        fs::write(machine.join(LIVE), live.encode()).unwrap();
        fs::remove_file(src.join("d/f")).unwrap();
        Tree::from_dir(&src)
            .unwrap()
            .write_dir(&bdir.join(POST))
            .unwrap();
        let post = Tree::from_dir(&bdir.join(POST)).unwrap();
        let raw = fs::metadata(bdir.join(LIVE)).unwrap().len();
        pack_run(&run, false);
        for d in [&bdir, &machine] {
            assert!(!d.join(LIVE).exists() && d.join(LIVE_PACKED).is_file());
            assert_eq!(super::live(d).unwrap(), live);
        }
        assert!(fs::metadata(bdir.join(LIVE_PACKED)).unwrap().len() * 4 < raw);
        assert!(bdir.join(POST).is_dir() && !bdir.join(POST_PACKED).exists());
        pack_run(&run, true);
        assert!(!bdir.join(POST).exists() && bdir.join(POST_PACKED).is_file());
        assert_eq!(post_crash(&bdir).unwrap(), Some(post));
        assert_eq!(post_crash(&machine).unwrap(), None);
        assert_eq!(super::live(&bdir).unwrap(), live);
        fs::remove_dir_all(&run).unwrap();
    }
}
