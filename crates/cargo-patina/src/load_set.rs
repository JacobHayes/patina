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
//! On macOS the images are each Mach-O image's dylib load commands, followed
//! from the executable the way dyld resolves them (`@rpath`,
//! `@executable_path`, `@loader_path`). `libSystem` and the `/usr/lib/system`
//! libraries it re-exports are the host; an application library on disk is
//! audited as the executable is; one dyld maps from its shared cache has no
//! file to audit, and a reference bound into it is refused. Whether a host
//! image exports a name is asked of this process's own dyld, which maps the
//! same shared cache the guest will.
//!
//! The roles follow from the images: the loader, glibc's own libraries (they
//! define `GLIBC_*` symbol versions) and the vDSO are the host; every other
//! library is application code, audited as the executable is. A host preload
//! list, and any image the loader maps that no `DT_NEEDED` edge reaches, are
//! refused: the loader would search them ahead of the program's own images.

use crate::CliError;
use patina_dst_target::{
    ImageRole, LoadSet, LoadedImage, MachOLoadRequest, elf_load_request, macho_load_request,
};
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
        return match macho_load_request(bytes).map_err(|error| CliError(error.to_string()))? {
            Some(request) => discover_macho(binary, name.clone(), bytes, request).map_err(refuse),
            None => Ok(LoadSet::executable_only(name, bytes)),
        };
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
    let mut set = vec![LoadedImage::new(
        name,
        Cow::Borrowed(bytes),
        ImageRole::Executable,
    )];
    let mut images: Vec<Option<Discovered>> = images.into_iter().map(Some).collect();
    for index in order {
        let image = images[index].take().expect("each image is ordered once");
        let host = image.request.glibc
            || std::fs::canonicalize(&image.path).ok() == loader_path && loader_path.is_some();
        set.push(LoadedImage::new(
            image.listed,
            Cow::Owned(image.bytes),
            if host {
                ImageRole::Host
            } else {
                ImageRole::Library
            },
        ));
    }
    // The kernel maps the vDSO into every process; it is the host's, and
    // searched after everything the program names.
    if let Some(vdso) = vdso() {
        set.push(LoadedImage::new(
            "linux-vdso.so.1",
            Cow::Owned(vdso),
            ImageRole::Host,
        ));
    }
    LoadSet::new(set).map_err(|error| CliError(error.to_string()))
}

/// What one Mach-O install name resolves to.
enum Resolved {
    /// A dylib on disk, with its slice for the guest's architecture.
    File(PathBuf, Vec<u8>),
    /// A platform library, by the path dyld finds it at.
    Host(String),
    /// A library dyld maps from its shared cache, by path.
    SharedCache(String),
    Missing,
}

/// The architecture dyld loads dylibs for: the executable's CPU type and
/// subtype (capability bits masked).
#[derive(Clone, Copy)]
struct Arch {
    cputype: u32,
    cpusubtype: u32,
}

/// One Mach-O image whose dylibs are still to be followed.
struct Pending {
    index: usize,
    request: MachOLoadRequest,
    /// The directory `@loader_path` names.
    loader_dir: PathBuf,
    /// The `@rpath` search list it inherits: its own `LC_RPATH`s, then those
    /// of the images that loaded it.
    rpaths: Vec<PathBuf>,
}

/// The images dyld maps for a Mach-O executable, by install name.
fn discover_macho<'data>(
    binary: &Path,
    name: String,
    bytes: &'data [u8],
    request: MachOLoadRequest,
) -> Result<LoadSet<'data>, String> {
    let binary = std::fs::canonicalize(binary)
        .map_err(|error| format!("cannot resolve its path: {error}"))?;
    let executable_dir = binary.parent().unwrap_or(Path::new("/")).to_path_buf();
    let expand = |path: &str, loader_dir: &Path| -> PathBuf {
        if let Some(rest) = path.strip_prefix("@executable_path") {
            PathBuf::from(format!("{}{rest}", executable_dir.display()))
        } else if let Some(rest) = path.strip_prefix("@loader_path") {
            PathBuf::from(format!("{}{rest}", loader_dir.display()))
        } else {
            PathBuf::from(path)
        }
    };
    let arch = macho_arch(bytes).ok_or("it is not a 64-bit Mach-O image")?;
    let mut images = vec![LoadedImage::new(
        name,
        Cow::Borrowed(bytes),
        ImageRole::Executable,
    )];
    let mut by_key: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let rpaths = request
        .rpaths
        .iter()
        .map(|rpath| expand(rpath, &executable_dir))
        .collect();
    let mut queue = VecDeque::from([Pending {
        index: 0,
        request,
        loader_dir: executable_dir.clone(),
        rpaths,
    }]);
    while let Some(pending) = queue.pop_front() {
        let mut dependencies = Vec::new();
        for dylib in &pending.request.dylibs {
            let install = dylib.install_name.as_str();
            // dyld tries each expansion in turn, the shared cache included,
            // and passes over a file built for another architecture.
            let resolved = if let Some(rest) = install.strip_prefix("@rpath/") {
                let mut found = Resolved::Missing;
                for rpath in &pending.rpaths {
                    found = resolve_path(&rpath.join(rest), arch)?;
                    if !matches!(found, Resolved::Missing) {
                        break;
                    }
                }
                found
            } else {
                resolve_path(&expand(install, &pending.loader_dir), arch)?
            };
            let (key, image) = match resolved {
                Resolved::Missing if dylib.weak => {
                    dependencies.push(None);
                    continue;
                }
                Resolved::Missing => {
                    return Err(format!("dyld cannot find {install}, a dependency"));
                }
                Resolved::File(path, bytes) => {
                    let path = std::fs::canonicalize(&path).unwrap_or(path);
                    (path.display().to_string(), Some((path, bytes)))
                }
                Resolved::Host(path) => (path, None),
                Resolved::SharedCache(path) => (path, None),
            };
            if let Some(index) = by_key.get(&key) {
                dependencies.push(Some(*index));
                continue;
            }
            let index = images.len();
            by_key.insert(key.clone(), index);
            dependencies.push(Some(index));
            match image {
                Some((path, bytes)) => {
                    let request = macho_load_request(&bytes)
                        .map_err(|error| format!("{}: {error}", path.display()))?
                        .ok_or_else(|| {
                            format!("{} is not a 64-bit Mach-O image", path.display())
                        })?;
                    let loader_dir = path.parent().unwrap_or(Path::new("/")).to_path_buf();
                    let mut rpaths: Vec<PathBuf> = request
                        .rpaths
                        .iter()
                        .map(|rpath| expand(rpath, &loader_dir))
                        .collect();
                    rpaths.extend(pending.rpaths.iter().cloned());
                    images.push(LoadedImage::new(
                        install,
                        Cow::Owned(bytes),
                        ImageRole::Library,
                    ));
                    queue.push_back(Pending {
                        index,
                        request,
                        loader_dir,
                        rpaths,
                    });
                }
                None => images.push(LoadedImage::new(
                    key.clone(),
                    Cow::Owned(shared_cache_identity(&key).into_bytes()),
                    if host_install_name(&key) {
                        ImageRole::Host
                    } else {
                        ImageRole::SharedCache
                    },
                )),
            }
        }
        images[pending.index].dependencies = dependencies;
    }
    let set = LoadSet::new(images).map_err(|error| error.to_string())?;
    Ok(match host_export_oracle() {
        Some(oracle) => set.with_export_oracle(oracle),
        None => set,
    })
}

/// The architecture of a thin 64-bit Mach-O image.
fn macho_arch(bytes: &[u8]) -> Option<Arch> {
    use object::read::macho::{MachHeader, MachOFile64};
    let file = MachOFile64::<object::Endianness>::parse(bytes).ok()?;
    let header = file.macho_header();
    Some(Arch {
        cputype: header.cputype(file.endian()),
        cpusubtype: header.cpusubtype(file.endian()) & !object::macho::CPU_SUBTYPE_MASK,
    })
}

/// A dylib's slice for `arch`: the file itself when it is thin and built
/// for the guest's CPU, the universal file's slice of the guest's subtype,
/// else of its CPU type; `None` when dyld would pass over the file.
fn thin_slice(bytes: Vec<u8>, arch: Arch) -> Result<Option<Vec<u8>>, String> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
    if let Some(thin) = macho_arch(&bytes) {
        return Ok((thin.cputype == arch.cputype).then_some(bytes));
    }
    type Slice<'a> = (u32, u32, Result<&'a [u8], object::Error>);
    let slices: Vec<Slice<'_>> = if let Ok(fat) = MachOFatFile32::parse(&*bytes) {
        fat.arches()
            .iter()
            .map(|a| (a.cputype(), a.cpusubtype(), a.data(&*bytes)))
            .collect()
    } else if let Ok(fat) = MachOFatFile64::parse(&*bytes) {
        fat.arches()
            .iter()
            .map(|a| (a.cputype(), a.cpusubtype(), a.data(&*bytes)))
            .collect()
    } else {
        return Err("not a 64-bit Mach-O image".into());
    };
    let subtype = |slice: &&Slice<'_>| slice.1 & !object::macho::CPU_SUBTYPE_MASK;
    let same_cpu = || slices.iter().filter(|slice| slice.0 == arch.cputype);
    let Some(slice) = same_cpu()
        .find(|slice| subtype(slice) == arch.cpusubtype)
        .or_else(|| same_cpu().next())
    else {
        return Ok(None);
    };
    match &slice.2 {
        Ok(data) if macho_arch(data).is_some() => Ok(Some(data.to_vec())),
        Ok(_) => Err("its slice is not a 64-bit Mach-O image".into()),
        Err(error) => Err(error.to_string()),
    }
}

/// Whether an install name is the platform's: `libSystem` and the
/// `/usr/lib/system` libraries it re-exports.
fn host_install_name(install: &str) -> bool {
    install == "/usr/lib/libSystem.B.dylib" || install.starts_with("/usr/lib/system/")
}

/// Where dyld finds a dylib path: the platform's own libraries, the shared
/// cache, else a file on disk with a slice for the guest.
fn resolve_path(path: &Path, arch: Arch) -> Result<Resolved, String> {
    let name = path.display().to_string();
    if host_install_name(&name) {
        return Ok(Resolved::Host(name));
    }
    if in_shared_cache(&name) {
        return Ok(Resolved::SharedCache(name));
    }
    if path.is_file() {
        let bytes = read(path)?;
        if let Some(slice) =
            thin_slice(bytes, arch).map_err(|reason| format!("{name}: {reason}"))?
        {
            return Ok(Resolved::File(path.to_path_buf(), slice));
        }
    }
    Ok(Resolved::Missing)
}

#[cfg(target_os = "macos")]
fn in_shared_cache(install: &str) -> bool {
    unsafe extern "C" {
        fn _dyld_shared_cache_contains_path(path: *const std::ffi::c_char) -> bool;
    }
    let Ok(path) = std::ffi::CString::new(install) else {
        return false;
    };
    // SAFETY: a NUL-terminated path; the call only reads it.
    unsafe { _dyld_shared_cache_contains_path(path.as_ptr()) }
}

#[cfg(not(target_os = "macos"))]
fn in_shared_cache(_install: &str) -> bool {
    false
}

/// What stands in for an image with no file: its install name and the
/// shared cache dyld maps it from, so a different OS build is a different
/// load set.
fn shared_cache_identity(install: &str) -> String {
    format!("dyld-shared-cache {} {install}", shared_cache_uuid())
}

#[cfg(target_os = "macos")]
fn shared_cache_uuid() -> String {
    unsafe extern "C" {
        fn _dyld_get_shared_cache_uuid(uuid: *mut u8) -> bool;
    }
    let mut uuid = [0u8; 16];
    // SAFETY: dyld writes 16 bytes into the buffer.
    if unsafe { _dyld_get_shared_cache_uuid(uuid.as_mut_ptr()) } {
        uuid.iter().map(|byte| format!("{byte:02x}")).collect()
    } else {
        "none".into()
    }
}

#[cfg(not(target_os = "macos"))]
fn shared_cache_uuid() -> String {
    "none".into()
}

/// Whether a host or shared-cache image exports a C name, asked of this
/// process's dyld: the image opened (without loading anything when it is
/// already mapped, `RTLD_NOLOAD`) and searched alone, with its re-exports
/// (`RTLD_FIRST`), as a two-level binding searches it.
#[cfg(target_os = "macos")]
fn host_export_oracle() -> Option<patina_dst_target::ExportOracle> {
    Some(patina_dst_target::ExportOracle::new(|image, symbol| {
        let image = std::ffi::CString::new(image).ok()?;
        let symbol = std::ffi::CString::new(symbol).ok()?;
        // SAFETY: NUL-terminated strings; RTLD_NOLOAD returns a handle only to
        // an image already mapped, so no initializer runs.
        unsafe {
            let mut handle = libc::dlopen(
                image.as_ptr(),
                libc::RTLD_LAZY | libc::RTLD_NOLOAD | libc::RTLD_FIRST,
            );
            // A shared-cache image this process has not mapped (libc++, a
            // framework) is mapped from the same cache the guest will use;
            // its initializers run here, in the supervisor, never in the guest.
            if handle.is_null() {
                handle = libc::dlopen(image.as_ptr(), libc::RTLD_LAZY | libc::RTLD_FIRST);
            }
            if handle.is_null() {
                return None;
            }
            let found = !libc::dlsym(handle, symbol.as_ptr()).is_null();
            libc::dlclose(handle);
            Some(found)
        }
    }))
}

#[cfg(not(target_os = "macos"))]
fn host_export_oracle() -> Option<patina_dst_target::ExportOracle> {
    None
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
