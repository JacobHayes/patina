/* The syscall doors to moving the thread pointer (x86_64): the shim finds its
 * own per-thread state through the FS base, so patina refuses each by name
 * (category thread-pointer). Named cases:
 *
 *   tp-set-fs     arch_prctl(ARCH_SET_FS) to a base other than the thread's
 *                 own.
 *   tp-write-ldt  modify_ldt(0x11) writing a present 32-bit data segment
 *                 based at a live address: a descriptor a plain `mov fs`
 *                 could load. (An entry the kernel stores zeroed is not
 *                 refused; thread/tls writes one.)
 *
 * Natively each call succeeds and the case prints that it returned.
 */
#define _GNU_SOURCE
#include <asm/ldt.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __x86_64__
#error "thread_pointer_syscalls.c is x86_64 only"
#endif

#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define LDT_WRITE 0x11

static int tp_set_fs(void) {
    unsigned long fs = 0;
    assert(syscall(SYS_arch_prctl, ARCH_GET_FS, &fs) == 0);
    syscall(SYS_arch_prctl, ARCH_SET_FS, fs + 4096);
    puts("TP_SET_FS_RETURNED");
    return 0;
}

static int tp_write_ldt(void) {
    static unsigned long target;
    struct user_desc desc;
    memset(&desc, 0, sizeof desc);
    desc.entry_number = 0;
    desc.base_addr = (unsigned int)(uintptr_t)&target;
    desc.limit = 0xfffff;
    desc.seg_32bit = 1;
    desc.limit_in_pages = 1;
    desc.useable = 1;
    syscall(SYS_modify_ldt, LDT_WRITE, &desc, sizeof desc);
    puts("TP_WRITE_LDT_RETURNED");
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "tp-set-fs") == 0) return tp_set_fs();
    if (strcmp(argv[1], "tp-write-ldt") == 0) return tp_write_ldt();
    fprintf(stderr, "unknown case %s\n", argv[1]);
    return 2;
}
