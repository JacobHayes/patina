use super::*;

/// The listing's three line shapes: a dependency with its path, the loader by
/// its path, and the pathless vDSO, which the listing skips.
#[test]
fn a_listing_names_each_mapped_image_by_its_dependency_name() {
    let listed = parse_listing(
        "\tlinux-vdso.so.1 (0x00007ffd)\n\
         \tlibgcc_s.so.1 => /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f01)\n\
         \t/lib64/ld-linux-x86-64.so.2 (0x00007f02)\n",
    )
    .expect("parses");
    let named: Vec<(&str, &Path)> = listed
        .iter()
        .map(|entry| (entry.name.as_str(), entry.path.as_path()))
        .collect();
    assert_eq!(
        named,
        [
            (
                "libgcc_s.so.1",
                Path::new("/usr/lib/x86_64-linux-gnu/libgcc_s.so.1")
            ),
            (
                "/lib64/ld-linux-x86-64.so.2",
                Path::new("/lib64/ld-linux-x86-64.so.2")
            ),
        ]
    );
}

/// A dependency the loader cannot find refuses: the program would not start.
#[test]
fn a_dependency_the_loader_cannot_find_refuses() {
    assert!(parse_listing("\tlibmissing.so.1 => not found\n").is_err());
}

/// A library found through a relative rpath is listed by its relative path.
#[test]
fn a_relative_library_path_is_kept() {
    let listed = parse_listing("\tlibhelper.so => ./libhelper.so (0x00007f01)\n").expect("parses");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, Path::new("./libhelper.so"));
}

/// A host preload list names objects separated by whitespace or colons, with
/// comments ignored; an empty or comment-only list names none.
#[test]
fn a_preload_list_names_its_objects() {
    let names: Vec<&str> =
        preloads("# hardening\n/lib/a.so /lib/b.so:/lib/c.so # trailing\n\n").collect();
    assert_eq!(names, ["/lib/a.so", "/lib/b.so", "/lib/c.so"]);
    assert_eq!(preloads("# nothing\n  \n").next(), None);
}

const ARM64: u32 = 0x0100_000c;
const X86_64: u32 = 0x0100_0007;
const ARM64E: u32 = 2;

/// A thin 64-bit Mach-O dylib header for `cputype`/`cpusubtype`, tagged so
/// a test can tell slices apart.
fn thin(cputype: u32, cpusubtype: u32, tag: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in [0xfeed_facf, cputype, cpusubtype, 6, 0, 0, 0, 0] {
        bytes.extend_from_slice(&u32::to_le_bytes(field));
    }
    bytes.push(tag);
    bytes
}

/// A universal file of `slices`.
fn universal(slices: &[Vec<u8>]) -> Vec<u8> {
    let mut header = Vec::new();
    for field in [0xcafe_babe, slices.len() as u32] {
        header.extend_from_slice(&field.to_be_bytes());
    }
    let mut offset = 4096usize;
    let mut body = Vec::new();
    for slice in slices {
        let arch = super::macho_arch(slice).unwrap();
        for field in [
            arch.cputype,
            arch.cpusubtype,
            offset as u32,
            slice.len() as u32,
            12,
        ] {
            header.extend_from_slice(&field.to_be_bytes());
        }
        body.resize(offset - 4096, 0);
        body.extend_from_slice(slice);
        offset = (4096 + body.len()).next_multiple_of(4096);
    }
    header.resize(4096, 0);
    header.extend_from_slice(&body);
    header
}

fn arm64(cpusubtype: u32) -> super::Arch {
    super::Arch {
        cputype: ARM64,
        cpusubtype,
    }
}

#[test]
fn a_dylib_built_for_another_cpu_is_passed_over() {
    let x86 = thin(X86_64, 3, 1);
    assert_eq!(super::thin_slice(x86, arm64(0)).unwrap(), None);
    let fat = universal(&[thin(X86_64, 3, 1)]);
    assert_eq!(super::thin_slice(fat, arm64(0)).unwrap(), None);
}

#[test]
fn a_universal_dylib_yields_the_guests_subtype_else_its_cpu() {
    let fat = universal(&[
        thin(X86_64, 3, 1),
        thin(ARM64, ARM64E, 2),
        thin(ARM64, 0, 3),
    ]);
    let tag = |arch| {
        *super::thin_slice(fat.clone(), arch)
            .unwrap()
            .unwrap()
            .last()
            .unwrap()
    };
    assert_eq!(tag(arm64(0)), 3);
    assert_eq!(tag(arm64(ARM64E)), 2);
    let fat = universal(&[thin(ARM64, ARM64E, 2)]);
    let slice = super::thin_slice(fat, arm64(0)).unwrap().unwrap();
    assert_eq!(slice.last(), Some(&2));
}

#[test]
fn a_rpath_candidate_for_another_cpu_falls_through_to_the_next() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("libfoo.dylib");
    std::fs::write(&path, thin(X86_64, 3, 1)).unwrap();
    assert!(matches!(
        super::resolve_path(&path, arm64(0)).unwrap(),
        super::Resolved::Missing
    ));
    std::fs::write(&path, thin(ARM64, 0, 3)).unwrap();
    assert!(matches!(
        super::resolve_path(&path, arm64(0)).unwrap(),
        super::Resolved::File(..)
    ));
}

/// An `@rpath` expansion dyld finds in its shared cache resolves there, not
/// to "missing", though no file is on disk.
#[cfg(target_os = "macos")]
#[test]
fn a_path_in_the_shared_cache_resolves_there() {
    let arch = super::macho_arch(&thin(ARM64, 0, 0)).unwrap();
    assert!(matches!(
        super::resolve_path(Path::new("/usr/lib/libc++.1.dylib"), arch).unwrap(),
        super::Resolved::SharedCache(_)
    ));
    assert!(matches!(
        super::resolve_path(Path::new("/usr/lib/libSystem.B.dylib"), arch).unwrap(),
        super::Resolved::Host(_)
    ));
}
