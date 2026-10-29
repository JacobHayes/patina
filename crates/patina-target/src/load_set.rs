//! The images a program's loader maps, in the order it searches them.
//!
//! The audit judges a reference by where it binds at load, so it needs the
//! images that can satisfy it. `cargo-patina` discovers them (on Linux by
//! asking the program's own loader) and hands them here; this module only
//! holds them and reads the dynamic-table facts discovery needs.

use crate::TargetError;
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

/// What an image in the load set is to the audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageRole {
    /// The audited executable, first in the search order.
    Executable,
    /// An application library: audited as the executable is, its code
    /// scanned and its references judged by where they bind.
    Library,
    /// The platform runtime (the loader, glibc's own libraries, the vDSO;
    /// on macOS `libSystem` and the `/usr/lib/system` libraries it
    /// re-exports). Its code is the host's; a reference that binds into it is
    /// judged by the effect policy, by name.
    Host,
    /// An application library dyld maps from its shared cache (`libc++`,
    /// `libiconv`, the frameworks). There is no file to read, so neither its
    /// code nor its own bindings can be audited: a reference that binds into
    /// it is refused by name. `bytes` hold the shared cache's identity.
    SharedCache,
}

/// One image the loader maps.
#[derive(Clone, Debug)]
pub struct LoadedImage<'data> {
    /// How diagnostics name the image: the dependency name that loaded it, or
    /// the executable's path.
    pub name: String,
    /// The image's bytes; for an image with no file (a Mach-O host or
    /// shared-cache image), an identity of what the loader maps instead.
    pub bytes: Cow<'data, [u8]>,
    pub role: ImageRole,
    /// Mach-O: the load set index of the image each of this image's dylib
    /// load commands names, in ordinal order (ordinal 1 first); `None` for a
    /// weak dylib dyld does not find. Empty for ELF and for images whose own
    /// bindings are not judged.
    pub dependencies: Vec<Option<usize>>,
}

impl<'data> LoadedImage<'data> {
    /// An image with no Mach-O dependency map.
    pub fn new(name: impl Into<String>, bytes: Cow<'data, [u8]>, role: ImageRole) -> Self {
        Self {
            name: name.into(),
            bytes,
            role,
            dependencies: Vec::new(),
        }
    }
}

/// Whether a host image exports a C symbol: `Some(true)` or `Some(false)`
/// when the platform answers, `None` when it cannot (an image it cannot
/// open). Mach-O host images have no file to read, so the supervisor asks the
/// platform's own loader.
#[derive(Clone)]
pub struct ExportOracle(Arc<ExportAnswer>);

/// `(image name, C symbol name)` to whether the image exports it.
type ExportAnswer = dyn Fn(&str, &str) -> Option<bool> + Send + Sync;

impl ExportOracle {
    /// An oracle answering `(image name, C symbol name)`.
    pub fn new(answer: impl Fn(&str, &str) -> Option<bool> + Send + Sync + 'static) -> Self {
        Self(Arc::new(answer))
    }

    pub(crate) fn exports(&self, image: &str, symbol: &str) -> Option<bool> {
        (self.0)(image, symbol)
    }
}

impl fmt::Debug for ExportOracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportOracle")
    }
}

/// The images a program loads, in the loader's symbol search order: the
/// executable first, then its dependencies breadth-first.
#[derive(Clone, Debug)]
pub struct LoadSet<'data> {
    images: Vec<LoadedImage<'data>>,
    oracle: Option<ExportOracle>,
}

impl<'data> LoadSet<'data> {
    /// A load set from images in search order. The first, and only the first,
    /// is the executable.
    pub fn new(images: Vec<LoadedImage<'data>>) -> Result<Self, TargetError> {
        let mut roles = images.iter().map(|image| image.role);
        if roles.next() != Some(ImageRole::Executable)
            || roles.any(|role| role == ImageRole::Executable)
        {
            return Err(TargetError::UnreadableLoadSet(
                "a load set starts with its one executable".into(),
            ));
        }
        Ok(Self {
            images,
            oracle: None,
        })
    }

    /// This load set, whose host images' exports `oracle` answers for.
    pub fn with_export_oracle(mut self, oracle: ExportOracle) -> Self {
        self.oracle = Some(oracle);
        self
    }

    pub(crate) fn oracle(&self) -> Option<&ExportOracle> {
        self.oracle.as_ref()
    }

    /// The load set of an executable the loader maps alone: one with no
    /// interpreter and no dependencies (static), or an image no loader
    /// listing is read for.
    pub fn executable_only(name: impl Into<String>, bytes: &'data [u8]) -> Self {
        Self {
            images: vec![LoadedImage::new(
                name,
                Cow::Borrowed(bytes),
                ImageRole::Executable,
            )],
            oracle: None,
        }
    }

    pub fn images(&self) -> &[LoadedImage<'data>] {
        &self.images
    }

    pub fn executable(&self) -> &LoadedImage<'data> {
        &self.images[0]
    }
}

/// What an ELF image's program and dynamic headers ask of the loader.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElfLoadRequest {
    /// `PT_INTERP`: the loader the kernel starts for this image.
    pub interpreter: Option<String>,
    /// `DT_NEEDED`, in order.
    pub needed: Vec<String>,
    pub soname: Option<String>,
    /// `DT_AUDIT`/`DT_DEPAUDIT`: modules the loader runs before it maps
    /// anything else, so before the audit could see what they do.
    pub audit_modules: bool,
    /// `DT_FILTER`/`DT_AUXILIARY`: lookups redirected to another object, which
    /// this audit does not model.
    pub filters: bool,
    /// `DF_1_INITFIRST`: glibc runs this image's initializers before the
    /// executable's preinit array, where the shim arms its containment.
    pub init_first: bool,
    /// The image defines a `GLIBC_*` symbol version: it is part of glibc
    /// (libc, libm, the loader, ...), whose code is the host's.
    pub glibc: bool,
}

/// Read [`ElfLoadRequest`] from an ELF image. `Ok(None)` for another format.
/// An image the audit cannot read is refused here, before its dependencies are
/// listed: its dynamic table is read through its section headers.
pub fn elf_load_request(bytes: &[u8]) -> Result<Option<ElfLoadRequest>, TargetError> {
    use object::read::elf::{ElfFile64, ProgramHeader};
    if object::File::parse(bytes).is_ok_and(|file| crate::native_audit::unauditable_elf(&file)) {
        return Err(TargetError::UnauditableElf);
    }
    let Ok(elf) = ElfFile64::<object::Endianness>::parse(bytes) else {
        return match object::File::parse(bytes) {
            Ok(_) => Ok(None),
            Err(error) => Err(TargetError::Parse(error)),
        };
    };
    let endian = elf.endian();
    let mut request = ElfLoadRequest::default();
    for header in elf.elf_program_headers() {
        if let Some(path) = header
            .interpreter(endian, bytes)
            .map_err(TargetError::Parse)?
        {
            request.interpreter = Some(String::from_utf8_lossy(path).into_owned());
        }
    }
    let table = elf.elf_dynamic_table().map_err(TargetError::Parse)?;
    let string = |val: u64| -> Result<String, TargetError> {
        let offset = u32::try_from(val)
            .map_err(|_| TargetError::UnreadableLoadSet("a dynamic string past 4 GiB".into()))?;
        table
            .strings()
            .get(offset)
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .map_err(|()| {
                TargetError::UnreadableLoadSet("a dynamic string outside its table".into())
            })
    };
    for entry in &table {
        match entry.tag {
            object::elf::DT_NEEDED => request.needed.push(string(entry.val)?),
            object::elf::DT_SONAME => request.soname = Some(string(entry.val)?),
            object::elf::DT_AUDIT | object::elf::DT_DEPAUDIT => request.audit_modules = true,
            object::elf::DT_FILTER | object::elf::DT_AUXILIARY => request.filters = true,
            object::elf::DT_FLAGS_1 => {
                request.init_first |= entry.val & u64::from(object::elf::DF_1_INITFIRST) != 0;
            }
            _ => {}
        }
    }
    request.glibc = defined_versions(&elf)?
        .iter()
        .any(|name| name.starts_with(b"GLIBC_"));
    Ok(Some(request))
}

/// The names of the symbol versions an image defines (`SHT_GNU_VERDEF`).
fn defined_versions<'data>(
    elf: &object::read::elf::ElfFile64<'data, object::Endianness>,
) -> Result<Vec<&'data [u8]>, TargetError> {
    let endian = elf.endian();
    let sections = elf.elf_section_table();
    let Some((mut definitions, link)) = sections
        .gnu_verdef(endian, elf.data())
        .map_err(TargetError::Parse)?
    else {
        return Ok(Vec::new());
    };
    let strings = sections
        .strings(endian, elf.data(), link)
        .map_err(TargetError::Parse)?;
    let mut names = Vec::new();
    while let Some((_, mut auxiliaries)) = definitions.next().map_err(TargetError::Parse)? {
        if let Some(auxiliary) = auxiliaries.next().map_err(TargetError::Parse)? {
            names.push(
                auxiliary
                    .name(endian, strings)
                    .map_err(TargetError::Parse)?,
            );
        }
    }
    Ok(names)
}

/// One dylib a Mach-O image's load commands name, in ordinal order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachODylib {
    /// The install name as recorded (`/usr/lib/libSystem.B.dylib`,
    /// `@rpath/libfoo.dylib`, ...).
    pub install_name: String,
    /// `LC_LOAD_WEAK_DYLIB`: dyld skips it when it is missing.
    pub weak: bool,
    /// `LC_REEXPORT_DYLIB`: its exports are this image's too.
    pub reexport: bool,
}

/// What a Mach-O image's load commands ask of dyld.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachOLoadRequest {
    /// The dylibs it links, in ordinal order.
    pub dylibs: Vec<MachODylib>,
    /// `LC_RPATH`, in order.
    pub rpaths: Vec<String>,
    /// `LC_ID_DYLIB`: a dylib's own install name.
    pub install_name: Option<String>,
}

/// Read [`MachOLoadRequest`] from a 64-bit Mach-O image. `Ok(None)` for
/// another format.
pub fn macho_load_request(bytes: &[u8]) -> Result<Option<MachOLoadRequest>, TargetError> {
    use object::macho;
    use object::read::macho::{MachHeader, MachOFile64};
    let Ok(file) = MachOFile64::<object::Endianness>::parse(bytes) else {
        return Ok(None);
    };
    let endian = file.endian();
    let mut request = MachOLoadRequest::default();
    let mut commands = file
        .macho_header()
        .load_commands(endian, bytes, 0)
        .map_err(TargetError::Parse)?;
    while let Some(command) = commands.next().map_err(TargetError::Parse)? {
        let text = |name| -> Result<String, TargetError> {
            Ok(
                String::from_utf8_lossy(command.string(endian, name).map_err(TargetError::Parse)?)
                    .into_owned(),
            )
        };
        if let Some(dylib) = command.dylib().map_err(TargetError::Parse)? {
            let flags = command
                .dylib_use_flags(endian, dylib)
                .map_err(TargetError::Parse)?;
            let kind = command.cmd();
            request.dylibs.push(MachODylib {
                install_name: text(dylib.dylib.name)?,
                weak: kind == macho::LC_LOAD_WEAK_DYLIB
                    || flags.is_some_and(|flags| flags & macho::DYLIB_USE_WEAK_LINK != 0),
                reexport: kind == macho::LC_REEXPORT_DYLIB
                    || flags.is_some_and(|flags| flags & macho::DYLIB_USE_REEXPORT != 0),
            });
        } else if command.cmd() == macho::LC_ID_DYLIB {
            let dylib: &macho::DylibCommand<_> = command.data().map_err(TargetError::Parse)?;
            request.install_name = Some(text(dylib.dylib.name)?);
        } else if command.cmd() == macho::LC_RPATH {
            let rpath: &macho::RpathCommand<_> = command.data().map_err(TargetError::Parse)?;
            request.rpaths.push(text(rpath.path)?);
        }
    }
    Ok(Some(request))
}
