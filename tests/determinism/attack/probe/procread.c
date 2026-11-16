/* determinism hardening attack guest: read every path given on the command line (or a built-in list) in full;
 * print length and a hash, and the content when -v. Also readlink each. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static const char *def[] = {
 "/proc/self/maps","/proc/self/smaps","/proc/self/stat","/proc/self/status","/proc/self/statm","/proc/self/cgroup",
 "/proc/self/mountinfo","/proc/self/mounts","/proc/mounts","/proc/self/cmdline","/proc/self/environ","/proc/self/comm",
 "/proc/self/auxv","/proc/self/limits","/proc/self/sched","/proc/self/io","/proc/self/oom_score","/proc/self/oom_score_adj",
 "/proc/self/timerslack_ns","/proc/self/wchan","/proc/self/attr/current","/proc/self/fdinfo/0","/proc/self/fdinfo/1",
 "/proc/self/ns/net","/proc/self/ns/pid","/proc/self/loginuid","/proc/self/sessionid","/proc/self/personality",
 "/proc/self/syscall","/proc/self/stack","/proc/self/mem","/proc/self/pagemap","/proc/self/numa_maps","/proc/self/coredump_filter",
 "/proc/self/task","/proc/thread-self/stat","/proc/self/setgroups","/proc/self/uid_map","/proc/self/gid_map",
 "/proc/cpuinfo","/proc/meminfo","/proc/stat","/proc/uptime","/proc/loadavg","/proc/version","/proc/filesystems",
 "/proc/sys/kernel/osrelease","/proc/sys/kernel/pid_max","/proc/sys/kernel/random/uuid","/proc/sys/kernel/random/boot_id",
 "/proc/sys/kernel/random/entropy_avail","/proc/sys/kernel/ns_last_pid","/proc/sys/kernel/hostname","/proc/sys/kernel/ostype",
 "/proc/sys/kernel/version","/proc/sys/kernel/threads-max","/proc/sys/kernel/cap_last_cap","/proc/sys/kernel/ngroups_max",
 "/proc/sys/vm/overcommit_memory","/proc/sys/vm/max_map_count","/proc/sys/fs/pipe-max-size","/proc/sys/fs/nr_open",
 "/proc/sys/fs/file-max","/proc/sys/fs/file-nr","/proc/sys/net/core/somaxconn","/proc/pressure/cpu","/proc/pressure/memory",
 "/proc/self/net/unix","/proc/net/unix","/proc/self/net/dev","/proc/sys/kernel/yama/ptrace_scope","/proc/sys/kernel/seccomp/actions_avail",
 "/proc/zoneinfo","/proc/vmstat","/proc/buddyinfo","/proc/swaps","/proc/diskstats","/proc/interrupts","/proc/self/clear_refs",
 "/sys/devices/system/cpu/online","/sys/devices/system/cpu/possible","/sys/devices/system/cpu/present",
 "/sys/kernel/mm/transparent_hugepage/enabled","/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
 "/sys/kernel/mm/transparent_hugepage/defrag","/sys/kernel/mm/transparent_hugepage/shmem_enabled",
 "/sys/fs/cgroup/cpu.max","/sys/fs/cgroup/memory.max","/sys/devices/system/cpu/cpu0/cache/index0/size",
 "/sys/devices/system/node/online","/sys/devices/system/cpu/cpu0/topology/core_id","/sys/kernel/random/uuid",
 "/dev/shm","/dev/null","/dev/zero","/dev/full","/dev/random","/dev/urandom","/dev/tty","/dev/stdin","/dev/stdout",
 "/dev/fd/0","/dev/fd/3000","/proc/self/fd/3000","/proc/self/fd/3001","/proc/1/stat","/proc/1/mem","/proc/2/stat",
 "/proc/self/root/usr","/proc/self/cwd","/proc/self/exe","/etc/hostname","/etc/machine-id","/etc/resolv.conf",
 "/var/lib/dbus/machine-id","/run","/home","/root","/cache",
 0};
static uint64_t fnv(const unsigned char *b, size_t n, uint64_t h) { for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ull; } return h; }
int main(int argc, char **argv) {
    int verbose = argc > 1 && !strcmp(argv[1], "-v");
    const char **list = def;
    if (argc > 1 + verbose) list = (const char **)argv + 1 + verbose;
    static unsigned char buf[1 << 20];
    for (int i = 0; list[i]; i++) {
        char lk[512]; ssize_t ln = readlink(list[i], lk, sizeof lk - 1);
        if (ln >= 0) { lk[ln] = 0; printf("%s -> %s\n", list[i], lk); }
        int fd = open(list[i], O_RDONLY | O_NONBLOCK);
        if (fd < 0) { printf("%s open errno %d\n", list[i], errno); continue; }
        size_t tot = 0; uint64_t h = 0xcbf29ce484222325ull; ssize_t n; int e = 0;
        if (!strcmp(list[i], "/dev/zero") || !strcmp(list[i], "/dev/urandom") || !strcmp(list[i], "/dev/random") || !strcmp(list[i], "/dev/full")) {
            n = read(fd, buf, 64); if (n > 0) { tot = n; h = fnv(buf, n, h); }
        } else {
            while ((n = read(fd, buf + (tot < sizeof buf / 2 ? tot : 0), 65536)) > 0) { h = fnv(buf + (tot < sizeof buf / 2 ? tot : 0), n, h); tot += n; if (tot > (64u << 20)) break; }
            if (n < 0) e = errno;
        }
        printf("%s len %zu hash %016llx err %d\n", list[i], tot, (unsigned long long)h, e);
        if (verbose && tot < sizeof buf / 2) { fwrite(buf, 1, tot, stdout); printf("\n----\n"); }
        close(fd);
    }
    return 0;
}
