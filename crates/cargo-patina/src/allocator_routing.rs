//! The link arguments that route Rust's allocator entry points through the
//! shim's arena router (`crates/patina-native-shim/src/arena.rs`), so the
//! runtime's own allocations never land on the guest's heap.
//!
//! The entry points' names are mangled with a hash of the compiler's version,
//! so they are read from the shim archive, which the guest's own compiler
//! built: its allocator shim defines them. Each is wrapped (`--wrap`), and a
//! small object (`c/patina_allocator_routing.S`, compiled with the names'
//! prefix) defines its wrapper as a jump to the shim's `patina_route_*` router
//! and the `patina_guest_*` name the router calls as a jump to its real
//! definition. Code, not linker symbol assignments: every linker that
//! implements `--wrap` (GNU ld, gold, lld, mold) links it alike. Linux only:
//! Darwin's linker has no `--wrap`, and Darwin's heap placement is the host's
//! anyway, so a Darwin link routes nothing.

use std::ffi::OsString;
use std::path::Path;

use crate::CliError;

/// The routing object's source.
pub(super) const PATINA_ALLOCATOR_ROUTING_S: &str = include_str!("../c/patina_allocator_routing.S");

/// The allocator entry points, as the length-prefixed final path segment of
/// their mangled names (the routing object names each one's router).
const ENTRY_POINTS: [&str; 4] = [
    "12___rust_alloc",
    "14___rust_dealloc",
    "14___rust_realloc",
    "19___rust_alloc_zeroed",
];

/// The mangled-name prefix of one compiler's allocator entry points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AllocatorRouting {
    /// `_RNvCs<hash>_7___rustc`: everything before an entry point's name, or
    /// `None` where the platform routes nothing.
    prefix: Option<String>,
}

impl AllocatorRouting {
    /// The routing for the compiler that built `staticlib`, from the archive's
    /// symbol index.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn read(_staticlib: &Path) -> Result<Self, CliError> {
        Ok(Self { prefix: None })
    }

    /// The routing for the compiler that built `staticlib`, from the archive's
    /// symbol index.
    #[cfg(target_os = "linux")]
    pub(super) fn read(staticlib: &Path) -> Result<Self, CliError> {
        let refuse = |reason: String| {
            CliError(format!(
                "reading the allocator entry points from the shim archive {}: {reason}",
                staticlib.display()
            ))
        };
        let file = std::fs::File::open(staticlib).map_err(|error| refuse(error.to_string()))?;
        let data = object::ReadCache::new(file);
        let archive = object::read::archive::ArchiveFile::parse(&data)
            .map_err(|error| refuse(error.to_string()))?;
        let symbols = archive
            .symbols()
            .map_err(|error| refuse(error.to_string()))?
            .ok_or_else(|| refuse("the archive has no symbol index".to_owned()))?;
        let mut names = Vec::new();
        for symbol in symbols {
            let symbol = symbol.map_err(|error| refuse(error.to_string()))?;
            names.push(String::from_utf8_lossy(symbol.name()).into_owned());
        }
        Self::from_names(&names).ok_or_else(|| {
            refuse("it defines no complete set of Rust allocator entry points".to_owned())
        })
    }

    /// The routing whose four entry points all appear among `names`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn from_names(names: &[String]) -> Option<Self> {
        let prefix = names.iter().find_map(|name| {
            name.strip_suffix(ENTRY_POINTS[0])
                .filter(|prefix| prefix.starts_with("_RNv") && prefix.ends_with("7___rustc"))
        })?;
        ENTRY_POINTS
            .iter()
            .all(|entry| names.iter().any(|name| *name == format!("{prefix}{entry}")))
            .then(|| Self {
                prefix: Some(prefix.to_owned()),
            })
    }

    /// The defines the routing object compiles under, or `None` where the
    /// platform routes nothing (and links no routing object).
    pub(super) fn defines(&self) -> Option<Vec<String>> {
        let prefix = self.prefix.as_ref()?;
        Some(vec![format!("-DPATINA_RUST_ALLOC_PREFIX={prefix}")])
    }

    /// The compiler-driver arguments that route the entry points, given the
    /// routing `object` compiled under [`Self::defines`] and the shim archive
    /// `staticlib`: each entry point's wrap, the object, and the archive again
    /// after it, so a single-pass archive scan finds the routers the object
    /// jumps to wherever the link put the archive first.
    pub(super) fn linker_args(&self, object: &Path, staticlib: &Path) -> Vec<OsString> {
        let Some(prefix) = &self.prefix else {
            return Vec::new();
        };
        let mut args: Vec<OsString> = ENTRY_POINTS
            .iter()
            .map(|entry| format!("-Wl,--wrap={prefix}{entry}").into())
            .collect();
        args.push(object.into());
        args.push(staticlib.into());
        args
    }

    /// [`Self::linker_args`] as rustc `-C` values.
    pub(super) fn link_args(&self, object: &Path, staticlib: &Path) -> Vec<OsString> {
        self.linker_args(object, staticlib)
            .into_iter()
            .map(|arg| {
                let mut value = OsString::from("link-arg=");
                value.push(arg);
                value
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(entries: &[&str]) -> Vec<String> {
        let mut names = vec!["patina_shutdown".to_owned(), "_RNvCs1_3foo3bar".to_owned()];
        names.extend(
            entries
                .iter()
                .map(|entry| format!("_RNvCsdtSMxSA38aw_7___rustc{entry}")),
        );
        names
    }

    #[test]
    fn every_entry_point_is_wrapped_and_the_object_links_before_the_archive_again() {
        let routing = AllocatorRouting::from_names(&names(&ENTRY_POINTS)).expect("a complete set");
        let (object, staticlib) = (Path::new("routing.o"), Path::new("libshim.a"));
        let args = routing.link_args(object, staticlib);
        for entry in ENTRY_POINTS {
            let wrap = format!("link-arg=-Wl,--wrap=_RNvCsdtSMxSA38aw_7___rustc{entry}");
            assert!(args.contains(&OsString::from(wrap)), "{entry}");
        }
        let tail: Vec<_> = args.iter().rev().take(2).rev().cloned().collect();
        assert_eq!(
            tail,
            [
                OsString::from("link-arg=routing.o"),
                OsString::from("link-arg=libshim.a")
            ]
        );
        let defines = routing.defines().expect("defines");
        assert_eq!(
            defines,
            ["-DPATINA_RUST_ALLOC_PREFIX=_RNvCsdtSMxSA38aw_7___rustc"]
        );
    }

    #[test]
    fn a_platform_without_routing_links_nothing() {
        let none = AllocatorRouting { prefix: None };
        assert_eq!(none.defines(), None);
        assert!(none.link_args(Path::new("o"), Path::new("a")).is_empty());
    }

    /// The routing object, assembled for this host: every function it
    /// defines starts with the architecture's landing pad, and its property
    /// note marks it compatible with the control-flow protections, so it
    /// neither faults under enforcement nor strips the marking from a link.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn every_routing_entry_is_a_landing_pad_and_the_object_says_so() {
        use object::{Object, ObjectSection, ObjectSymbol};
        let (pad, property, features): (&[u8], u32, u32) = if cfg!(target_arch = "x86_64") {
            (&[0xf3, 0x0f, 0x1e, 0xfa], 0xc000_0002, 0x3)
        } else {
            (&0xd503_245fu32.to_le_bytes(), 0xc000_0000, 0x3)
        };
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("routing.S");
        let built = dir.path().join("routing.o");
        std::fs::write(&source, PATINA_ALLOCATOR_ROUTING_S).unwrap();
        let routing = AllocatorRouting::from_names(&names(&ENTRY_POINTS)).unwrap();
        let status = std::process::Command::new(std::env::var_os("CC").unwrap_or("cc".into()))
            .args(routing.defines().unwrap())
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&built)
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&built).unwrap();
        let file = object::File::parse(&*bytes).unwrap();
        let text = file.section_by_name(".text").unwrap().data().unwrap();
        let functions: Vec<_> = file
            .symbols()
            .filter(|symbol| symbol.is_definition() && symbol.kind() == object::SymbolKind::Text)
            .collect();
        assert_eq!(functions.len(), 2 * ENTRY_POINTS.len());
        for symbol in functions {
            let at = symbol.address() as usize;
            assert_eq!(&text[at..at + pad.len()], pad, "{:?}", symbol.name());
        }
        let note = file
            .section_by_name(".note.gnu.property")
            .unwrap()
            .data()
            .unwrap();
        let word =
            |index: usize| u32::from_le_bytes(note[index * 4..index * 4 + 4].try_into().unwrap());
        // namesz, descsz, type, "GNU\0", then the property: type, size, value.
        assert_eq!((word(2), &note[12..16]), (5, &b"GNU\0"[..]));
        assert_eq!((word(4), word(5), word(6)), (property, 4, features));
    }

    #[test]
    fn an_incomplete_set_is_no_routing() {
        for missing in 0..ENTRY_POINTS.len() {
            let mut some = ENTRY_POINTS.to_vec();
            some.remove(missing);
            assert_eq!(AllocatorRouting::from_names(&names(&some)), None);
        }
    }
}
