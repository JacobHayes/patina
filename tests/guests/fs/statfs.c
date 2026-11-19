/* statfs, fstatfs and statvfs on every kind of mount the sandbox has: one line per call with
 * every field, so a field taken from the host (its RAM, a superblock's random id, a host
 * disk's free space) shows as a difference between runs. Then 1 MiB written to /dev/shm.
 * `statfs fill`: write /tmp full, then show the bytes written, the error and /tmp's statfs. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>

static void show(const char *what, int r, const struct statfs *s) {
    if (r != 0) {
        printf("%s r=%d\n", what, r);
        return;
    }
    int fsid[2];
    memcpy(fsid, &s->f_fsid, sizeof fsid);
    printf("%s type=%#lx bsize=%ld blocks=%lu bfree=%lu bavail=%lu files=%lu ffree=%lu fsid=%d:%d namelen=%ld frsize=%ld flags=%#lx\n",
           what, (unsigned long)s->f_type, (long)s->f_bsize, (unsigned long)s->f_blocks,
           (unsigned long)s->f_bfree, (unsigned long)s->f_bavail, (unsigned long)s->f_files,
           (unsigned long)s->f_ffree, fsid[0], fsid[1], (long)s->f_namelen, (long)s->f_frsize,
           (unsigned long)s->f_flags);
}

static void path(const char *p) {
    struct statfs s;
    char what[64];
    snprintf(what, sizeof what, "statfs %s", p);
    show(what, statfs(p, &s), &s);
}

static void fd(const char *what, int f) {
    struct statfs s;
    show(what, fstatfs(f, &s), &s);
}

static int fill(void) {
    static char buf[1 << 16];
    memset(buf, 'x', sizeof buf);
    int f = open("/tmp/fill", O_CREAT | O_WRONLY, 0644);
    long n = 0;
    ssize_t r;
    while ((r = write(f, buf, sizeof buf)) > 0)
        n += r;
    printf("filled %ld errno=%d\n", n, r < 0 ? errno : 0);
    path("/tmp");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    if (argc > 1 && strcmp(argv[1], "fill") == 0)
        return fill();
    const char *mounts[] = {"/", "/dev", "/dev/shm", "/dev/pts", "/work", "/tmp", "/guest", "/proc", "/usr"};
    for (size_t i = 0; i < sizeof mounts / sizeof *mounts; i++)
        path(mounts[i]);
    int p[2];
    if (pipe(p) == 0)
        fd("fstatfs pipe", p[0]);
    int m = memfd_create("m", 0);
    fd("fstatfs memfd", m);
    int d = open("/dev/shm", O_RDONLY | O_DIRECTORY);
    fd("fstatfs /dev/shm", d);
    struct statvfs v;
    if (statvfs("/", &v) == 0)
        printf("statvfs / bsize=%lu frsize=%lu blocks=%lu bfree=%lu bavail=%lu files=%lu ffree=%lu favail=%lu fsid=%lu flag=%#lx namemax=%lu\n",
               v.f_bsize, v.f_frsize, (unsigned long)v.f_blocks, (unsigned long)v.f_bfree,
               (unsigned long)v.f_bavail, (unsigned long)v.f_files, (unsigned long)v.f_ffree,
               (unsigned long)v.f_favail, v.f_fsid, v.f_flag, v.f_namemax);
    static char mib[1 << 20];
    memset(mib, 'x', sizeof mib);
    int f = open("/dev/shm/one-mib", O_CREAT | O_WRONLY, 0644);
    if (f < 0 || write(f, mib, sizeof mib) != (ssize_t)sizeof mib)
        printf("write /dev/shm/one-mib failed\n");
    close(f);
    printf("after 1 MiB in /dev/shm\n");
    path("/dev/shm");
    return 0;
}
