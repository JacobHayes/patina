//! `/proc/self/fd`: each descriptor's magic link, read and walked through.

use super::*;

/// The lines a run of `proc_fd_probe.rs` prints.
fn answers(stdout: &[u8]) -> Vec<&str> {
    text(stdout)
        .lines()
        .filter(|line| line.starts_with("PROC_FD "))
        .collect()
}

/// RED before: an `O_PATH|O_NOFOLLOW` open of a symlink was a named deny
/// (`ENOSYS`), and procfs had no `fd` directory, so a `connect` through a
/// pinned socket's `/proc/self/fd/<n>` was `ENOENT`. Under patina the probe
/// answers as the host does: links read the node's current path or the
/// pseudo-filesystem's name, a walk through one reaches the held node after
/// a rename and after an unlink, and the directory lists the open numbers.
#[test]
fn descriptor_links_reach_the_held_node_as_the_host_does() {
    let native = native_stdout("proc_fd_probe.rs");
    let g = Guest::assert_build("proc_fd_probe.rs");
    let out = g.assert_run_success(1, &[]);
    assert!(!answers(&native).is_empty(), "{}", text(&native));
    assert_eq!(answers(&out.stdout), answers(&native));
}
