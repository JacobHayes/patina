/* sandbox hardening guest: path walks that leave the policy's view through symlinks, a working directory
 * of "/", magic links of the supervisor (PID 1) and relative names. Every attempt must be
 * refused; one line per attempt. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

static void r(const char *what, long v) { printf("%-44s r=%ld errno=%d\n", what, v, v < 0 ? errno : 0); }

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    symlink("/proc/1", "/work/p1");
    symlink("/proc", "/work/proc");
    symlink("p1/fd", "/work/p1fd");
    symlink("/work/loop2", "/work/loop1");
    symlink("/work/loop1", "/work/loop2");
    mkdir("/work/d", 0755);
    symlink("../p1", "/work/d/up");
    struct stat st;
    r("open /work/p1/fd/3001 rw", open("/work/p1/fd/3001", O_RDWR));
    r("open /work/p1/fd/3000 rw", open("/work/p1/fd/3000", O_RDWR));
    r("open /work/p1fd/3001", open("/work/p1fd/3001", O_RDONLY));
    r("open /work/d/up/fd/3001", open("/work/d/up/fd/3001", O_RDONLY));
    r("open /work/proc/1/fd/3001", open("/work/proc/1/fd/3001", O_RDONLY));
    r("stat /work/p1/fd/3001", stat("/work/p1/fd/3001", &st));
    r("truncate /work/p1/fd/3001", truncate("/work/p1/fd/3001", 0));
    r("open /work/p1/root/work (dir)", open("/work/p1/root/work", O_RDONLY | O_DIRECTORY));
    r("open /work/p1/exe", open("/work/p1/exe", O_RDONLY));
    r("open /work/loop1", open("/work/loop1", O_RDONLY));
    r("chdir /", chdir("/"));
    r("open proc/1/fd/3001 (cwd /)", open("proc/1/fd/3001", O_RDONLY));
    r("open proc/1/environ (cwd /)", open("proc/1/environ", O_RDONLY));
    r("stat proc/1/exe (cwd /)", stat("proc/1/exe", &st));
    char l[256];
    r("readlink proc/1/exe (cwd /)", readlink("proc/1/exe", l, sizeof l));
    r("open sys/kernel/notes (cwd /)", open("sys/kernel/notes", O_RDONLY));
    r("open work/p1/fd/3001 (cwd /)", open("work/p1/fd/3001", O_RDONLY));
    int root = open("/", O_RDONLY | O_DIRECTORY);
    r("openat(/, proc/1/fd/3001)", openat(root, "proc/1/fd/3001", O_RDONLY));
    r("openat(/, proc/self/fd/3001)", openat(root, "proc/self/fd/3001", O_RDONLY));
    int w = open("/work", O_RDONLY | O_DIRECTORY);
    r("openat(/work, p1/fd/3001)", openat(w, "p1/fd/3001", O_RDONLY));
    r("faccessat(/work, p1/environ)", faccessat(w, "p1/environ", R_OK, 0));
    r("getxattr /work/p1/exe", getxattr("/work/p1/exe", "user.x", l, sizeof l));
    r("mkdir /work/p1/x", mkdir("/work/p1/x", 0755));
    r("chdir /work/p1", chdir("/work/p1"));
    r("open environ after chdir", open("environ", O_RDONLY));
    chdir("/work");
    r("linkat p1/exe -> /work/patina", linkat(AT_FDCWD, "/work/p1/exe", AT_FDCWD, "/work/patina", AT_SYMLINK_FOLLOW));
    r("chmod /work/p1/fd/3001", chmod("/work/p1/fd/3001", 0600));
    r("utimensat /work/p1/fd/3001", utimensat(AT_FDCWD, "/work/p1/fd/3001", NULL, 0));
    r("open /work/p1/fd/3001 O_PATH", open("/work/p1/fd/3001", O_PATH));
    return 0;
}
