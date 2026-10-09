//! Clock and timer libc contracts. Darwin interval timer doors refuse by name.
use super::inventory::s;
use super::{Platform, Serves, SymbolRow, SymbolStatus};
symbol_rows! {
    s(
        "clock_gettime",
        Platform::Both,
        Serves::Syscalls(&["clock_gettime"]),
        SymbolStatus::Partial,
    ),
    s(
        "time",
        Platform::Both,
        Serves::Syscalls(&["time", "clock_gettime"]),
        SymbolStatus::Modeled,
    ),
    s(
        "gettimeofday",
        Platform::Both,
        Serves::Syscalls(&["gettimeofday"]),
        SymbolStatus::Modeled,
    ),
    s(
        "nanosleep",
        Platform::Both,
        Serves::Syscalls(&["nanosleep"]),
        SymbolStatus::Modeled,
    ),
    s(
        "clock_nanosleep",
        Platform::Linux,
        Serves::Syscalls(&["clock_nanosleep"]),
        SymbolStatus::Partial,
    ),
    s(
        "sleep",
        Platform::Both,
        Serves::Syscalls(&["nanosleep"]),
        SymbolStatus::Modeled,
    ),
    s(
        "localtime_r",
        Platform::Both,
        Serves::LibcOnly,
        SymbolStatus::Partial,
    ),
    s("setitimer", Platform::Both, Serves::Syscalls(&["setitimer"]), SymbolStatus::Partial),
    s("getitimer", Platform::Both, Serves::Syscalls(&["getitimer"]), SymbolStatus::Partial),
    s("alarm", Platform::Both, Serves::Syscalls(&["setitimer"]), SymbolStatus::Partial),
    s("ualarm", Platform::Both, Serves::Syscalls(&["setitimer"]), SymbolStatus::Partial),
    s("timer_create", Platform::Linux, Serves::Syscalls(&["timer_create"]), SymbolStatus::Partial),
    s("timer_settime", Platform::Linux, Serves::Syscalls(&["timer_settime"]), SymbolStatus::Modeled),
    s("timer_gettime", Platform::Linux, Serves::Syscalls(&["timer_gettime"]), SymbolStatus::Modeled),
    s("timer_delete", Platform::Linux, Serves::Syscalls(&["timer_delete"]), SymbolStatus::Modeled),
    s("timer_getoverrun", Platform::Linux, Serves::Syscalls(&["timer_getoverrun"]), SymbolStatus::Modeled),
    s("timerfd_create", Platform::Linux, Serves::Syscalls(&["timerfd_create"]), SymbolStatus::Modeled),
    s("timerfd_settime", Platform::Linux, Serves::Syscalls(&["timerfd_settime"]), SymbolStatus::Modeled),
    s("timerfd_gettime", Platform::Linux, Serves::Syscalls(&["timerfd_gettime"]), SymbolStatus::Modeled),
    s("__setitimer", Platform::Linux, Serves::Syscalls(&["setitimer"]), SymbolStatus::Modeled),
    s("__getitimer", Platform::Linux, Serves::Syscalls(&["getitimer"]), SymbolStatus::Modeled),
    s("__timerfd_settime", Platform::Linux, Serves::Syscalls(&["timerfd_settime"]), SymbolStatus::Modeled),
    s("__timerfd_gettime", Platform::Linux, Serves::Syscalls(&["timerfd_gettime"]), SymbolStatus::Modeled),
    s("___timer_create", Platform::Linux, Serves::Syscalls(&["timer_create"]), SymbolStatus::Partial),
    s("___timer_delete", Platform::Linux, Serves::Syscalls(&["timer_delete"]), SymbolStatus::Modeled),
    s("___timer_getoverrun", Platform::Linux, Serves::Syscalls(&["timer_getoverrun"]), SymbolStatus::Modeled),
    #[cfg(target_arch = "x86_64")]
    s("___timer_settime_new", Platform::Linux, Serves::Syscalls(&["timer_settime"]), SymbolStatus::Modeled),
    #[cfg(target_arch = "x86_64")]
    s("___timer_gettime_new", Platform::Linux, Serves::Syscalls(&["timer_gettime"]), SymbolStatus::Modeled),
    #[cfg(target_arch = "aarch64")]
    s("___timer_settime64", Platform::Linux, Serves::Syscalls(&["timer_settime"]), SymbolStatus::Modeled),
    #[cfg(target_arch = "aarch64")]
    s("___timer_gettime64", Platform::Linux, Serves::Syscalls(&["timer_gettime"]), SymbolStatus::Modeled),
}
