//! Path and directory calls racing another thread: each call is one step
//! into the kernel, where other threads run before it and never between the
//! lookups that find a node and the operation on it.

use super::*;

/// The answer `path_race_probe.rs` prints for each race, under every seed
/// tried: a poll sees the name another thread creates, and lets a runnable
/// peer run whatever the path, `stat` never answers an unfollowed symlink,
/// and a directory read never lists a description `dup2` replaced and
/// reports access to the directory it listed.
const PATH_RACE_ANSWERS: [(&str, &str); 5] = [
    ("poll", "seen"),
    ("starve", "none"),
    ("stat_swap", "0"),
    ("getdents_dup2", "stale=0 failed=0"),
    ("getdents_notify", "0"),
];

/// RED before, each on its own: a call whose path walk failed took no
/// scheduling point, so a thread polling `stat` for a missing name kept the
/// baton and never saw the other thread create it, and a path answered with
/// no walk (an empty or overlong one, a device node, a namespace file) took
/// none at all, so polling it starved a runnable peer; `stat` took a scheduling
/// point between the walk and its query of the walked path, so a symlink
/// renamed over the name in between answered `S_IFLNK`; and a `getdents64`
/// took its scheduling point after it resolved the descriptor, so a `dup2`
/// in between left it reading a description already let go (`EBADF`), or
/// installing the old directory's snapshot under the number `dup2` gave to
/// the other one, and it reported access to the directory the number named
/// before that scheduling point while it listed the one named after it.
#[test]
fn path_and_directory_calls_are_one_step_against_other_threads() {
    let g = Guest::assert_build("path_race_probe.rs");
    let mut wrong = Vec::new();
    for seed in 1..=3 {
        for (mode, expected) in PATH_RACE_ANSWERS {
            let env = format!("PATH_RACE_MODE={mode}");
            let out = g.assert_run_success(seed, &["--env", &env]).stdout;
            let prefix = format!("NATIVE_PATH_RACE {mode} ");
            let answer = assert_unique_line_payload(&out, &prefix);
            if answer != expected {
                wrong.push(format!(
                    "{mode} under seed {seed}: {answer}, not {expected}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
