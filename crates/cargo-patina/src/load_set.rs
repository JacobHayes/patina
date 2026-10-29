//! The images a native guest's loader maps, discovered before it runs.
//!
//! The audit judges each reference by the image it binds to, so it needs the
//! images the loader will search, in its order. On Linux the program's own
//! loader enumerates them (`PT_INTERP --list`, under the empty environment the
//! guest is started with), so search paths, the cache, hardware-capability
//! directories and `/etc/ld.so.preload` are the loader's own answer, never an
//! emulation. Listing maps the images and runs none of their code; the one
//! thing that runs code before that, a `DT_AUDIT` module, is refused first.
//!
//! The roles follow from the images: the loader, glibc's own libraries (they
//! define `GLIBC_*` symbol versions) and the vDSO are the host; every other
//! library is application code, audited as the executable is. A host preload
//! list, and any image the loader maps that no `DT_NEEDED` edge reaches, are
//! refused: the loader would search them ahead of the program's own images.

use crate::CliError;
use patina_dst_target::{ImageRole, LoadSet, LoadedImage, elf_load_request};
use patina_dst_trace::Sha256Digest;
use std::borrow::Cow;
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// The load set of `binary`, whose bytes are `bytes`.
pub(crate) fn discover<'data>(
    binary: &Path,
    bytes: &'data [u8],
) -> Result<LoadSet<'data>, CliError> {
    let name = binary.display().to_string();
    let refuse = |reason: String| {
        CliError(format!(
            "refusing to certify {name}: the images its loader maps cannot be established: {reason}"
        ))
    };
    let request = elf_load_request(bytes).map_err(|error| CliError(error.to_string()))?;
    let Some(request) = request else {
        // Mach-O: its dylibs are not resolved yet, and every import is judged
        // by name as one that binds into them.
        return Ok(LoadSet::executable_only(name, bytes));
    };
    if request.audit_modules {
        return Err(refuse(
            "it names loader audit modules (DT_AUDIT/DT_DEPAUDIT), which the loader runs before \
             anything else, listing included"
                .into(),
        ));
    }
    let Some(interpreter) = request.interpreter.clone() else {
        if request.needed.is_empty() {
            return Ok(LoadSet::executable_only(name, bytes));
        }
        return Err(refuse(
            "it needs shared libraries but names no loader (PT_INTERP)".into(),
        ));
    };
    let loader = read(Path::new(&interpreter)).map_err(refuse)?;
    let loader_request = elf_load_request(&loader)
        .map_err(|error| refuse(format!("{interpreter}: {error}")))?
        .unwrap_or_default();
    if !loader_request
        .soname
        .as_deref()
        .is_some_and(|soname| soname.starts_with("ld-linux"))
    {
        return Err(refuse(format!(
            "its loader {interpreter} is not glibc's, whose listing this audit reads"
        )));
    }
    // The loader searches preloads before every dependency, so a preload that
    // is also a dependency moves ahead of the images that name it.
    if let Some(preloaded) = std::fs::read_to_string(HOST_PRELOADS)
        .ok()
        .as_deref()
        .and_then(|list| preloads(list).next().map(str::to_owned))
    {
        return Err(refuse(format!(
            "the host preloads {preloaded} ({HOST_PRELOADS}), which its loader searches before \
             the program's own dependencies"
        )));
    }
    // A bare file name would send the loader searching its library path.
    let binary = std::path::absolute(binary)
        .map_err(|error| refuse(format!("cannot resolve its path: {error}")))?;
    let listed = list(&interpreter, &binary).map_err(refuse)?;
    let mut images: Vec<Discovered> = Vec::new();
    for entry in listed {
        let bytes = read(&entry.path).map_err(refuse)?;
        let request = elf_load_request(&bytes)
            .map_err(|error| refuse(format!("{}: {error}", entry.path.display())))?
            .unwrap_or_default();
        images.push(Discovered {
            listed: entry.name,
            path: entry.path,
            bytes,
            request,
        });
    }
    // The loader's search order: the executable, then its dependencies
    // breadth-first, each once, wherever it is first needed.
    let find = |needed: &str| {
        images.iter().position(|image| {
            image.listed == needed
                || image.request.soname.as_deref() == Some(needed)
                || image.path == Path::new(needed)
        })
    };
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<String> = request.needed.iter().cloned().collect();
    while let Some(needed) = queue.pop_front() {
        let index = find(&needed)
            .ok_or_else(|| refuse(format!("the loader did not list {needed}, a dependency")))?;
        if seen.insert(index) {
            order.push(index);
            queue.extend(images[index].request.needed.iter().cloned());
        }
    }
    if let Some(preloaded) = (0..images.len()).find(|index| !seen.contains(index)) {
        return Err(refuse(format!(
            "the loader maps {}, which no dependency names (a preload)",
            images[preloaded].path.display()
        )));
    }
    let loader_path = std::fs::canonicalize(&interpreter).ok();
    let mut set = vec![LoadedImage {
        name,
        bytes: Cow::Borrowed(bytes),
        role: ImageRole::Executable,
    }];
    let mut images: Vec<Option<Discovered>> = images.into_iter().map(Some).collect();
    for index in order {
        let image = images[index].take().expect("each image is ordered once");
        let host = image.request.glibc
            || std::fs::canonicalize(&image.path).ok() == loader_path && loader_path.is_some();
        set.push(LoadedImage {
            name: image.listed,
            bytes: Cow::Owned(image.bytes),
            role: if host {
                ImageRole::Host
            } else {
                ImageRole::Library
            },
        });
    }
    // The kernel maps the vDSO into every process; it is the host's, and
    // searched after everything the program names.
    if let Some(vdso) = vdso() {
        set.push(LoadedImage {
            name: "linux-vdso.so.1".into(),
            bytes: Cow::Owned(vdso),
            role: ImageRole::Host,
        });
    }
    LoadSet::new(set).map_err(|error| CliError(error.to_string()))
}

/// The SHA-256 of every image but the executable, in search order, named.
pub(crate) fn library_digests(load_set: &LoadSet<'_>) -> Vec<(String, Sha256Digest)> {
    use sha2::{Digest, Sha256};
    load_set
        .images()
        .iter()
        .skip(1)
        .map(|image| {
            (
                image.name.clone(),
                Sha256Digest(Sha256::digest(&image.bytes).into()),
            )
        })
        .collect()
}

/// The host's preload list, which glibc's loader reads under any environment.
const HOST_PRELOADS: &str = "/etc/ld.so.preload";

/// The objects a preload list names: whitespace- or colon-separated, with
/// `#` comments.
fn preloads(list: &str) -> impl Iterator<Item = &str> {
    list.lines()
        .map(|line| line.split_once('#').map_or(line, |(before, _)| before))
        .flat_map(|line| line.split(|c: char| c.is_whitespace() || c == ':'))
        .filter(|name| !name.is_empty())
}

struct Discovered {
    listed: String,
    path: PathBuf,
    bytes: Vec<u8>,
    request: patina_dst_target::ElfLoadRequest,
}

/// One image the loader listed with a path.
struct Listed {
    /// The name the listing shows it under: the dependency name, or the path
    /// for the loader itself.
    name: String,
    path: PathBuf,
}

/// The images `interpreter --list binary` maps, under an empty environment
/// (the guest's), the vDSO excluded.
fn list(interpreter: &str, binary: &Path) -> Result<Vec<Listed>, String> {
    let output = std::process::Command::new(interpreter)
        .arg("--list")
        .arg(binary)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("cannot run its loader {interpreter}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!(
            "its loader {interpreter} could not list it ({}): {}{}",
            output.status,
            stdout.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_listing(&stdout)
}

/// Parse a loader listing: `name => path (address)`, `path (address)`, or a
/// pathless `name (address)` for the vDSO. A path may be relative.
fn parse_listing(listing: &str) -> Result<Vec<Listed>, String> {
    let mut listed = Vec::new();
    for line in listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let line = line.rsplit_once(" (").map_or(line, |(before, _)| before);
        let (name, path) = match line.split_once(" => ") {
            Some((name, path)) => (name, path),
            None => (line, line),
        };
        if path == "not found" {
            return Err(format!("the loader cannot find {name}"));
        }
        // The pathless vDSO; a relative path (an rpath of `.`) is the
        // loader's own answer, relative to the directory the guest starts in.
        if !path.contains('/') {
            continue;
        }
        listed.push(Listed {
            name: name.to_owned(),
            path: PathBuf::from(path),
        });
    }
    Ok(listed)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// This process's vDSO image: the one the kernel maps into the guest too.
fn vdso() -> Option<Vec<u8>> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let line = maps.lines().find(|line| line.ends_with("[vdso]"))?;
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    // SAFETY: the kernel maps the vDSO readable for the process's lifetime;
    // the range is the mapping /proc/self/maps names.
    Some(unsafe { std::slice::from_raw_parts(start as *const u8, end - start) }.to_vec())
}

#[cfg(test)]
mod tests;
