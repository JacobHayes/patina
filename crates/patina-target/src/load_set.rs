//! The images a program's loader maps, in the order it searches them.
//!
//! The audit judges a reference by where it binds at load, so it needs the
//! images that can satisfy it. `cargo-patina` discovers them (on Linux by
//! asking the program's own loader) and hands them here; this module only
//! holds them and reads the dynamic-table facts discovery needs.

use crate::TargetError;
use std::borrow::Cow;

/// What an image in the load set is to the audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageRole {
    /// The audited executable, first in the search order.
    Executable,
    /// An application library: audited as the executable is, its code
    /// scanned and its references judged by where they bind.
    Library,
    /// The platform runtime (the loader, glibc's own libraries, the vDSO).
    /// Its code is the host's; a reference that binds into it is judged by
    /// the effect policy, by name.
    Host,
}

/// One image the loader maps.
#[derive(Clone, Debug)]
pub struct LoadedImage<'data> {
    /// How diagnostics name the image: the dependency name that loaded it, or
    /// the executable's path.
    pub name: String,
    pub bytes: Cow<'data, [u8]>,
    pub role: ImageRole,
}

/// The images a program loads, in the loader's symbol search order: the
/// executable first, then its dependencies breadth-first.
#[derive(Clone, Debug)]
pub struct LoadSet<'data> {
    images: Vec<LoadedImage<'data>>,
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
        Ok(Self { images })
    }

    /// The load set of an executable the loader maps alone: one with no
    /// interpreter and no dependencies (static), or a format whose libraries
    /// this audit does not yet resolve (Mach-O).
    pub fn executable_only(name: impl Into<String>, bytes: &'data [u8]) -> Self {
        Self {
            images: vec![LoadedImage {
                name: name.into(),
                bytes: Cow::Borrowed(bytes),
                role: ImageRole::Executable,
            }],
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
