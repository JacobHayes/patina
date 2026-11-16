// files /proc policy: open every listed path and print what the guest sees; the refused paths
// must answer ENOENT. Output is compared across runs, not against a native run.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void show(const char *p) {
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { printf("== %s open errno %d\n", p, errno); return; }
    struct stat st;
    fstat(fd, &st);
    printf("== %s fd %d mode %o ino %llu dev %llx size %lld\n", p, fd, st.st_mode, (unsigned long long)st.st_ino,
           (unsigned long long)st.st_dev, (long long)st.st_size);
    char buf[65536];
    long n, tot = 0;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        fwrite(buf, 1, n, stdout);
        tot += n;
    }
    printf("\n-- %ld bytes, last read %ld\n", tot, n);
    close(fd);
}

static void bytes(const char *p, int n) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) { printf("== %s open errno %d\n", p, errno); return; }
    unsigned char b[64];
    long r = read(fd, b, n);
    printf("== %s read %ld:", p, r);
    for (long i = 0; i < r; i++) printf(" %02x", b[i]);
    printf("\n");
    close(fd);
}

static void showlink(const char *p) {
    char b[4096];
    long r = readlink(p, b, sizeof b);
    if (r < 0) printf("== readlink %s errno %d\n", p, errno);
    else printf("== readlink %s %.*s\n", p, (int)r, b);
}

static void dir(const char *p) {
    DIR *d = opendir(p);
    if (!d) { printf("== opendir %s errno %d\n", p, errno); return; }
    struct dirent *e;
    while ((e = readdir(d))) printf("== dirent %s %s %llu %d\n", p, e->d_name, (unsigned long long)e->d_ino, e->d_type);
    closedir(d);
}

int main(void) {
    const char *files[] = {
        "/proc/self/maps", "/proc/self/smaps", "/proc/self/stat", "/proc/self/status", "/proc/self/statm",
        "/proc/self/cgroup", "/proc/self/mountinfo", "/proc/self/mounts", "/proc/self/cmdline",
        "/proc/self/environ", "/proc/self/comm", "/proc/2/stat", "/proc/cpuinfo", "/proc/meminfo", "/proc/stat",
        "/proc/uptime", "/proc/loadavg", "/proc/version", "/proc/mounts", "/proc/filesystems",
        "/proc/sys/kernel/osrelease", "/proc/sys/kernel/pid_max", "/proc/sys/kernel/random/uuid",
        "/proc/sys/kernel/random/uuid", "/proc/sys/kernel/random/boot_id", "/proc/sys/kernel/ngroups_max",
        "/proc/sys/vm/overcommit_memory", "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/possible",
        "/sys/devices/system/cpu/present", "/sys/kernel/mm/transparent_hugepage/enabled",
        "/sys/kernel/mm/transparent_hugepage/defrag", "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
        "/sys/kernel/mm/transparent_hugepage/shmem_enabled", "/dev/null",
        "/proc/self/fd/0", "/dev/stdin", "/proc/self/exe",
        // refused, and the terminal paths
        "/proc/1/environ", "/proc/kallsyms", "/sys/class/net", "/proc/self/root/etc/passwd", "/proc/self/cwd",
        "/proc/1/stat", "/work/../proc/self/../1/cmdline", "/dev/tty", "/dev/ptmx", "/dev/pts/0", "/dev/kmsg",
    };
    for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
        if (strcmp(files[i], "/proc/self/exe") == 0) bytes(files[i], 16);
        else show(files[i]);
    }
    bytes("/dev/urandom", 16);
    bytes("/dev/random", 16);
    bytes("/dev/zero", 8);
    int fd = open("/dev/full", O_WRONLY);
    errno = 0;
    long wr = write(fd, "x", 1);
    printf("== /dev/full fd %d write %ld errno %d\n", fd, wr, errno);
    close(fd);
    fd = open("/dev/shm/x", O_CREAT | O_RDWR, 0600);
    printf("== /dev/shm/x fd %d write %ld\n", fd, (long)write(fd, "shm", 3));
    close(fd);
    bytes("/dev/shm/x", 3);
    const char *links[] = {"/proc/self/exe", "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2", "/dev/stdin",
                           "/proc/self/cwd", "/proc/self", "/dev/fd/1"};
    for (unsigned i = 0; i < sizeof links / sizeof *links; i++) showlink(links[i]);
    fd = open("/proc/self/maps", O_RDONLY);
    char lp[64];
    snprintf(lp, sizeof lp, "/proc/self/fd/%d", fd);
    showlink(lp);
    struct stat st;
    printf("== stat /proc/self/status %d\n", stat("/proc/self/status", &st));
    printf("== stat mode %o ino %llu nlink %llu\n", st.st_mode, (unsigned long long)st.st_ino, (unsigned long long)st.st_nlink);
    printf("== access /proc/meminfo %d\n", access("/proc/meminfo", R_OK));
    int ac = access("/proc/1/environ", R_OK);
    printf("== access /proc/1/environ %d errno %d\n", ac, errno);
    dir("/proc/self/task");
    dir("/proc/self/fd");
    dir("/proc");
    return 0;
}
