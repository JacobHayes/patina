/*
 * Core: feature macros, the headers and layout assertions the C seams share,
 * and the acting-cancellation glue.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
#define _GNU_SOURCE 1
#endif

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "patina_native.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifdef __linux__
#include <linux/if_link.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <ucontext.h>
/* Layouts the Rust adapters declare themselves. */
_Static_assert(sizeof(struct statvfs) == 112 && offsetof(struct statvfs, f_type) == 88, "Rust Statvfs layout");
_Static_assert(sizeof(struct statvfs64) == 112 && offsetof(struct statvfs64, f_type) == 88, "Rust Statvfs64 layout");
_Static_assert(sizeof(struct rtnl_link_stats) == 96 && offsetof(struct rtnl_link_stats, rx_nohandler) == 92, "Rust LinkStats layout");
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/vm_statistics.h>
/* Layouts the Rust adapters declare themselves. */
_Static_assert(sizeof(pthread_mutex_t) == 64 && offsetof(pthread_mutex_t, __sig) == 0 && _PTHREAD_RECURSIVE_MUTEX_SIG_init == 0x32AAABA2, "Rust recursive stream mutex initializer");
_Static_assert(sizeof(struct vm_statistics64) == 248 && _Alignof(struct vm_statistics64) == 8 && offsetof(struct vm_statistics64, wire_count) == 12 && HOST_VM_INFO64_COUNT == 62, "Rust VmStatistics64 SDK layout");
_Static_assert(sizeof(struct task_basic_info_32) == 32 && _Alignof(struct task_basic_info_32) == 4 && offsetof(struct task_basic_info_32, user_time) == 12, "Rust Basic32 layout");
_Static_assert(sizeof(struct task_basic_info_64) == 40 && _Alignof(struct task_basic_info_64) == 4 && offsetof(struct task_basic_info_64, user_time) == 20, "Rust Basic64 layout");
#ifdef __aarch64__
_Static_assert(TASK_BASIC_INFO_64 == 18 && sizeof(struct task_basic_info_64_2) == 40 && offsetof(struct task_basic_info_64_2, user_time) == 20, "Rust arm64 Basic64 flavor");
#else
_Static_assert(TASK_BASIC_INFO_64 == 5, "Rust x86 Basic64 flavor");
#endif
#endif

#ifdef __linux__
/*
 * A thread ends: with pthread_exit's value, or with PTHREAD_CANCELED when it
 * acts on a cancellation (glibc's __do_cancel). The model takes the value,
 * then glibc's own pthread_exit unwinds, called here in C once no Rust frame
 * is left on the stack: its forced unwind could not cross one.
 */
__attribute__((noreturn)) static void patina_exit_thread(void *value) {
    patina_host_pthread_exit_fn host_exit = patina_thread_exiting(value);
    host_exit(value);
}

__attribute__((noreturn)) static void patina_act_on_cancel(void) {
    patina_exit_thread(PTHREAD_CANCELED);
}

/*
 * A cancellation point the model acts at, as glibc's cancellable syscalls
 * are: a pending cancel acts at the entry, and one that arrives while the
 * thread waits inside acts as the wait returns.
 */
#define PATINA_CANCEL_ENTER(outer)            \
    int32_t outer = patina_cancel_enter();    \
    if (outer < 0) patina_act_on_cancel()
#define PATINA_CANCEL_LEAVE(outer)                               \
    do {                                                         \
        if (patina_cancel_leave(outer) < 0) patina_act_on_cancel(); \
    } while (0)
#endif
