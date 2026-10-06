//! Generate the staged C translation unit and its routing table from owned data.
use std::fmt::Write;
use std::path::Path;

use crate::symbol_metadata::Symbol;

// This inventory owns both staging and compilation. Order is significant:
// the slices share static helpers in one translation unit.
const FAMILIES: &[&str] = &[
    "core",
    "init",
    "time",
    "thread_sync",
    "signal_process",
    "stdio",
    "darwin",
    "dlsym",
];

pub fn generate(out: &Path, symbols: &[Symbol]) {
    let mut umbrella = String::from("/* Generated from build_support.rs. */\n");
    let mut sources = String::from(
        "/// Staged family slices and generated routing metadata.\npub const POSIX_C_FAMILY_SOURCES: &[(&str, &str)] = &[\n",
    );
    for family in FAMILIES {
        if *family == "dlsym" {
            umbrella.push_str("#include \"posix/dlsym_routes.h\"\n");
            sources.push_str("(\"posix/dlsym_routes.h\", include_str!(concat!(env!(\"OUT_DIR\"), \"/dlsym_routes.h\"))),\n");
        }
        writeln!(umbrella, "#include \"posix/{family}.c\"").unwrap();
        writeln!(sources, "(\"posix/{family}.c\", include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/c/posix/{family}.c\"))),").unwrap();
        println!("cargo:rerun-if-changed=c/posix/{family}.c");
    }
    sources.push_str("(\"posix/darwin_traps.h\", include_str!(concat!(env!(\"OUT_DIR\"), \"/darwin_traps.h\"))),\n");
    sources.push_str("];\n");
    let mut darwin_traps =
        String::from("/* Deny wrappers generated from the symbol inventory. */\n");
    for row in symbols {
        let macro_name = match row.deny_class.as_deref() {
            Some("macos-framework") => "PATINA_FRAMEWORK_TRAP",
            Some("host-introspection") => "PATINA_INTROSPECTION_TRAP",
            _ => continue,
        };
        writeln!(darwin_traps, "{macro_name}({})", row.name).unwrap();
    }
    std::fs::write(out.join("darwin_traps.h"), darwin_traps).unwrap();
    let mut ordinary = Vec::new();
    let mut x86 = Vec::new();
    let mut assembly = Vec::new();
    let mut assembly_x86 = Vec::new();
    for row in symbols {
        if !row.linux || !row.routed || row.name == "__wrap_dlsym" {
            continue;
        }
        if matches!(
            row.name.as_str(),
            "exit"
                | "raise"
                | "fork"
                | "execvp"
                | "waitpid"
                | "setsid"
                | "setgid"
                | "setuid"
                | "setpgid"
                | "setgroups"
                | "posix_spawnp"
                | "posix_spawn_file_actions_init"
                | "posix_spawn_file_actions_adddup2"
                | "posix_spawn_file_actions_destroy"
                | "posix_spawnattr_init"
                | "posix_spawnattr_destroy"
                | "posix_spawnattr_setflags"
                | "posix_spawnattr_setpgroup"
                | "posix_spawnattr_setsigdefault"
                | "kill"
                | "sigaction"
                | "signal"
                | "pthread_sigmask"
                | "sigprocmask"
                | "sigpending"
                | "sigaltstack"
                | "pause"
                | "sigsuspend"
                | "sigtimedwait"
                | "sigwaitinfo"
                | "sigwait"
                | "sigqueue"
                | "strsignal"
                | "psignal"
                | "pthread_kill"
                | "killpg"
                | "siginterrupt"
                | "tgkill"
                | "tkill"
                | "pidfd_open"
                | "pidfd_getfd"
                | "pidfd_send_signal"
                | "process_madvise"
                | "process_mrelease"
                | "process_vm_readv"
                | "process_vm_writev"
                | "pidfd_getpid"
                | "pidfd_spawnp"
                | "posix_spawn_file_actions_addchdir_np"
                | "posix_spawn_file_actions_addchdir"
                | "waitid"
                | "__libc_current_sigrtmax"
                | "signalfd"
                | "__open64_2"
                | "__open_2"
                | "__openat64_2"
                | "__openat_2"
                | "__readlink_chk"
                | "__readlinkat_chk"
                | "access"
                | "chdir"
                | "chmod"
                | "chown"
                | "closedir"
                | "creat"
                | "dirfd"
                | "faccessat"
                | "fallocate"
                | "fallocate64"
                | "fchdir"
                | "fchmod"
                | "fchmodat"
                | "fchown"
                | "fchownat"
                | "fdopendir"
                | "fgetxattr"
                | "flistxattr"
                | "fremovexattr"
                | "fsetxattr"
                | "fstat"
                | "fstat64"
                | "fstatat"
                | "fstatat64"
                | "fstatfs"
                | "fstatfs64"
                | "fstatvfs"
                | "fstatvfs64"
                | "futimens"
                | "futimes"
                | "futimesat"
                | "getcwd"
                | "getdents64"
                | "getxattr"
                | "lchown"
                | "lgetxattr"
                | "link"
                | "linkat"
                | "listxattr"
                | "llistxattr"
                | "lremovexattr"
                | "lsetxattr"
                | "lstat"
                | "lstat64"
                | "lutimes"
                | "mkdir"
                | "mkdirat"
                | "mkfifo"
                | "mkfifoat"
                | "mknod"
                | "mknodat"
                | "opendir"
                | "posix_fadvise"
                | "posix_fadvise64"
                | "posix_fallocate"
                | "posix_fallocate64"
                | "readdir"
                | "readdir64"
                | "readdir64_r"
                | "readdir_r"
                | "readlink"
                | "readlinkat"
                | "realpath"
                | "removexattr"
                | "rename"
                | "renameat"
                | "renameat2"
                | "rewinddir"
                | "rmdir"
                | "seekdir"
                | "setxattr"
                | "stat"
                | "stat64"
                | "statfs"
                | "statfs64"
                | "statvfs"
                | "statvfs64"
                | "statx"
                | "symlink"
                | "symlinkat"
                | "telldir"
                | "truncate"
                | "truncate64"
                | "umask"
                | "unlink"
                | "unlinkat"
                | "utime"
                | "utimensat"
                | "utimes"
                | "socket"
                | "socketpair"
                | "bind"
                | "connect"
                | "listen"
                | "accept"
                | "accept4"
                | "getsockname"
                | "getpeername"
                | "shutdown"
                | "setsockopt"
                | "getsockopt"
                | "sendto"
                | "send"
                | "recvfrom"
                | "recv"
                | "sendmsg"
                | "recvmsg"
                | "sendmmsg"
                | "recvmmsg"
                | "__recv_chk"
                | "__recvfrom_chk"
                | "if_nametoindex"
                | "getaddrinfo"
                | "freeaddrinfo"
                | "getifaddrs"
                | "freeifaddrs"
                | "pread64"
                | "pwrite64"
                | "__read"
                | "__write"
                | "__read_chk"
                | "__pread_chk"
                | "__pread64_chk"
                | "copy_file_range"
                | "sendfile"
                | "sendfile64"
                | "dup3"
                | "close_range"
                | "preadv64"
                | "pwritev64"
                | "fdatasync"
                | "lseek64"
                | "ftruncate64"
                | "pipe2"
                | "tcgetattr"
                | "tcsetattr"
                | "tcflush"
                | "tcdrain"
                | "posix_openpt"
                | "grantpt"
                | "unlockpt"
                | "ptsname_r"
                | "ptsname"
                | "ttyname_r"
                | "ttyname"
                | "__ptsname_r_chk"
                | "__ttyname_r_chk"
                | "openpty"
                | "isatty"
                | "read"
                | "write"
                | "pread"
                | "pwrite"
                | "flock"
                | "close"
                | "dup"
                | "dup2"
                | "writev"
                | "readv"
                | "preadv"
                | "pwritev"
                | "lseek"
                | "fsync"
                | "ftruncate"
                | "pipe"
                | "epoll_create1"
                | "epoll_ctl"
                | "epoll_wait"
                | "epoll_pwait"
                | "eventfd"
                | "ppoll"
                | "select"
                | "pselect"
                | "__poll_chk"
                | "__ppoll_chk"
                | "poll"
                | "getpid"
                | "getppid"
                | "gettid"
                | "__res_init"
                | "res_init"
                | "uname"
                | "sched_yield"
                | "sched_getcpu"
                | "sched_setaffinity"
                | "getuid"
                | "geteuid"
                | "getgid"
                | "getegid"
                | "sysconf"
                | "getrusage"
                | "sysinfo"
                | "getrlimit"
                | "setrlimit"
                | "getrlimit64"
                | "setrlimit64"
                | "sched_getaffinity"
                | "gethostname"
                | "getpwuid_r"
                | "setpwent"
                | "endpwent"
                | "getpwent"
                | "mount"
                | "umount2"
                | "pivot_root"
                | "open_tree"
                | "move_mount"
                | "fsopen"
                | "fsconfig"
                | "fsmount"
                | "fspick"
                | "mount_setattr"
                | "acct"
                | "vhangup"
                | "swapon"
                | "swapoff"
                | "reboot"
                | "init_module"
                | "delete_module"
                | "quotactl"
                | "iopl"
                | "ioperm"
                | "unshare"
                | "setns"
                | "chroot"
                | "mmap"
                | "mmap64"
                | "munmap"
                | "msync"
                | "mprotect"
                | "mlock"
                | "mlock2"
                | "munlock"
                | "mlockall"
                | "munlockall"
                | "memfd_create"
                | "getentropy"
                | "getrandom"
                | "getenv"
                | "setenv"
                | "unsetenv"
                | "clearenv"
                | "putenv"
                | "secure_getenv"
                | "syscall"
                | "fcntl"
                | "fcntl64"
                | "mremap"
                | "ioctl"
                | "ptrace"
                | "prctl"
                | "printf"
                | "fprintf"
                | "open"
                | "openat"
                | "open64"
                | "openat64"
                | "__open"
                | "__open64"
        ) {
            if row.only_x86 {
                assembly_x86.push(row.name.as_str());
            } else {
                assembly.push(row.name.as_str());
            }
        } else if row.only_x86 {
            x86.push(row.name.as_str());
        } else {
            ordinary.push(row.name.as_str());
        }
    }
    let mut routing = String::from("/* Generated from the symbol registry. */\n#ifdef __linux__\n");
    for (name, mut rows) in [
        ("PATINA_ROUTED", ordinary),
        ("PATINA_ROUTED_X86_64", x86),
        ("PATINA_ROUTED_ASM", assembly),
        ("PATINA_ROUTED_ASM_X86_64", assembly_x86),
    ] {
        rows.sort_unstable();
        write!(routing, "#define {name}(X)").unwrap();
        for row in rows {
            write!(routing, " \\\n    X({row})").unwrap();
        }
        routing.push('\n');
    }
    routing.push_str("#endif\n");
    std::fs::write(out.join("patina_posix.c"), umbrella).unwrap();
    std::fs::write(out.join("posix_sources.rs"), sources).unwrap();
    std::fs::write(out.join("dlsym_routes.h"), routing).unwrap();
}
