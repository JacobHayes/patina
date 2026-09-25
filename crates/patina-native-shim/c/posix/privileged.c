/*
 * The privileged rows' libc faces: glibc's wrappers of mount, the descriptor
 * mount API, pivot_root, process accounting, the terminal hangup, swap,
 * reboot, kernel modules, quotas, I/O ports, namespaces, tracing and chroot.
 * Each enters the one model of its row through the SUD dispatcher
 * (`patina_sud_dispatch`, answered from the virtual credential in
 * src/sud/privileged/), so the libc, `syscall(2)` and raw vehicles cannot
 * disagree; a wrapper only reshapes the raw `-errno` into `-1`/`errno` and
 * supplies what glibc's wrapper supplies itself (reboot's magic numbers,
 * ptrace's peek word).
 */
#ifdef __linux__
int mount(const char *source, const char *target, const char *type, unsigned long flags,
          const void *data) {
    return signal_result(patina_sud_dispatch(SYS_mount, (uintptr_t)source, (uintptr_t)target,
        (uintptr_t)type, (uint64_t)flags, (uintptr_t)data, 0, 0));
}
int umount2(const char *target, int flags) {
    return signal_result(patina_sud_dispatch(SYS_umount2, (uintptr_t)target,
        (uint64_t)(int64_t)flags, 0, 0, 0, 0, 0));
}
int pivot_root(const char *new_root, const char *put_old) {
    return signal_result(patina_sud_dispatch(SYS_pivot_root, (uintptr_t)new_root,
        (uintptr_t)put_old, 0, 0, 0, 0, 0));
}
int open_tree(int dirfd, const char *path, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_open_tree, (uint64_t)(int64_t)dirfd,
        (uintptr_t)path, (uint64_t)flags, 0, 0, 0, 0));
}
int move_mount(int from_dirfd, const char *from_path, int to_dirfd, const char *to_path,
               unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_move_mount, (uint64_t)(int64_t)from_dirfd,
        (uintptr_t)from_path, (uint64_t)(int64_t)to_dirfd, (uintptr_t)to_path,
        (uint64_t)flags, 0, 0));
}
int fsopen(const char *fs_name, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_fsopen, (uintptr_t)fs_name, (uint64_t)flags,
        0, 0, 0, 0, 0));
}
int fsconfig(int fd, unsigned int cmd, const char *key, const void *value, int aux) {
    return signal_result(patina_sud_dispatch(SYS_fsconfig, (uint64_t)(int64_t)fd,
        (uint64_t)cmd, (uintptr_t)key, (uintptr_t)value, (uint64_t)(int64_t)aux, 0, 0));
}
int fsmount(int fd, unsigned int flags, unsigned int attr_flags) {
    return signal_result(patina_sud_dispatch(SYS_fsmount, (uint64_t)(int64_t)fd,
        (uint64_t)flags, (uint64_t)attr_flags, 0, 0, 0, 0));
}
int fspick(int dirfd, const char *path, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_fspick, (uint64_t)(int64_t)dirfd,
        (uintptr_t)path, (uint64_t)flags, 0, 0, 0, 0));
}
/* `struct mount_attr` is opaque here: the row reads it through the pointer. */
int mount_setattr(int dirfd, const char *path, unsigned int flags, void *attr, size_t size) {
    return signal_result(patina_sud_dispatch(SYS_mount_setattr, (uint64_t)(int64_t)dirfd,
        (uintptr_t)path, (uint64_t)flags, (uintptr_t)attr, (uint64_t)size, 0, 0));
}
int acct(const char *path) {
    return signal_result(patina_sud_dispatch(SYS_acct, (uintptr_t)path, 0, 0, 0, 0, 0, 0));
}
int vhangup(void) {
    return signal_result(patina_sud_dispatch(SYS_vhangup, 0, 0, 0, 0, 0, 0, 0));
}
int swapon(const char *path, int flags) {
    return signal_result(patina_sud_dispatch(SYS_swapon, (uintptr_t)path,
        (uint64_t)(int64_t)flags, 0, 0, 0, 0, 0));
}
int swapoff(const char *path) {
    return signal_result(patina_sud_dispatch(SYS_swapoff, (uintptr_t)path, 0, 0, 0, 0, 0, 0));
}
/* glibc's reboot(howto) passes both magic numbers itself. */
int reboot(int howto) {
    return signal_result(patina_sud_dispatch(SYS_reboot, 0xfee1deadu, 672274793u,
        (uint64_t)(int64_t)howto, 0, 0, 0, 0));
}
int init_module(void *image, unsigned long length, const char *params) {
    return signal_result(patina_sud_dispatch(SYS_init_module, (uintptr_t)image,
        (uint64_t)length, (uintptr_t)params, 0, 0, 0, 0));
}
int delete_module(const char *name, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_delete_module, (uintptr_t)name,
        (uint64_t)flags, 0, 0, 0, 0, 0));
}
int quotactl(int cmd, const char *special, int id, char *addr) {
    return signal_result(patina_sud_dispatch(SYS_quotactl, (uint64_t)(int64_t)cmd,
        (uintptr_t)special, (uint64_t)(int64_t)id, (uintptr_t)addr, 0, 0, 0));
}
#ifdef __x86_64__
int iopl(int level) {
    return signal_result(patina_sud_dispatch(SYS_iopl, (uint64_t)(int64_t)level, 0, 0, 0, 0,
        0, 0));
}
int ioperm(unsigned long from, unsigned long count, int turn_on) {
    return signal_result(patina_sud_dispatch(SYS_ioperm, (uint64_t)from, (uint64_t)count,
        (uint64_t)(int64_t)turn_on, 0, 0, 0, 0));
}
#endif
int unshare(int flags) {
    return signal_result(patina_sud_dispatch(SYS_unshare, (uint64_t)(int64_t)flags, 0, 0, 0,
        0, 0, 0));
}
int setns(int fd, int nstype) {
    return signal_result(patina_sud_dispatch(SYS_setns, (uint64_t)(int64_t)fd,
        (uint64_t)(int64_t)nstype, 0, 0, 0, 0, 0));
}
/*
 * glibc's `long ptrace(enum __ptrace_request, ...)`: the pid, address and data
 * are variadic; for PTRACE_PEEKTEXT/PEEKDATA/PEEKUSER (1-3) glibc hands the
 * kernel its own word as the data and answers the word read, with errno 0.
 */
long ptrace(int request, ...) {
    va_list ap;
    va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    long word = 0;
    int peek = request > 0 && request < 4;
    if (peek) data = &word;
    long result = patina_sud_dispatch(SYS_ptrace, (uint64_t)(int64_t)request,
        (uint64_t)(int64_t)pid, (uintptr_t)addr, (uintptr_t)data, 0, 0, 0);
    patina_signal_deliver();
    result = dispatch_result(result);
    if (result >= 0 && peek) {
        errno = 0;
        return word;
    }
    return result;
}
int chroot(const char *path) {
    return signal_result(patina_sud_dispatch(SYS_chroot, (uintptr_t)path, 0, 0, 0, 0, 0, 0));
}
#else
/*
 * XNU checks the superuser before it looks the path up
 * (bsd/vfs/vfs_syscalls.c `chroot`): the virtual identity is refused.
 * macOS has no virtual credential; the identity is the registry's.
 */
int chroot(const char *path) {
    (void)path;
    return patina_refuse(EPERM);
}
#endif
