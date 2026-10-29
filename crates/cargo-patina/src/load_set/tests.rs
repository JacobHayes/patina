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
