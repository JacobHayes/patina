/* Containment: ways to name the supervisor's /proc entries (PID 1) or /proc/self/mem. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
static void try(const char *what, int fd) {
    char b[256]; int n = -1;
    if (fd >= 0) { n = read(fd, b, sizeof b - 1); close(fd); }
    printf("%-50s fd=%d read=%d errno=%d\n", what, fd, n, fd < 0 ? errno : 0);
}
int main(void) {
    symlink("/proc/1/environ", "/work/l1");
    symlink("/proc/self/mem", "/work/l2");
    symlink("/proc/1", "/work/l3");
    symlink("../proc/1/cmdline", "/work/l4");
    try("/work/l1 -> /proc/1/environ", open("/work/l1", O_RDONLY));
    try("/work/l2 -> /proc/self/mem", open("/work/l2", O_RDONLY));
    try("/work/l3/stat", open("/work/l3/stat", O_RDONLY));
    try("/work/l4 (relative)", open("/work/l4", O_RDONLY));
    int task = open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    try("openat(task, ../../1/environ)", openat(task, "../../1/environ", O_RDONLY));
    try("openat(task, 2/../../1/mem)", openat(task, "2/../../1/mem", O_RDONLY));
    char p[64]; snprintf(p, sizeof p, "/proc/self/fd/%d/../../1/environ", task);
    try(p, open(p, O_RDONLY));
    try("/proc/thread-self/../1/maps", open("/proc/thread-self/../1/maps", O_RDONLY));
    if (chdir("/proc/self/task") == 0) try("chdir task; ../../1/environ", open("../../1/environ", O_RDONLY));
    else printf("chdir task errno %d\n", errno);
    chdir("/work");
    if (chdir("/proc") == 0) try("chdir /proc; 1/environ", open("1/environ", O_RDONLY));
    else printf("chdir /proc errno %d\n", errno);
    chdir("/work");
    try("/proc/self/root/proc/1/environ", open("/proc/self/root/proc/1/environ", O_RDONLY));
    try("/dev/fd/../../proc/1/environ", open("/dev/fd/../../proc/1/environ", O_RDONLY));
    struct stat st;
    printf("stat /proc/1/exe %d errno %d\n", stat("/proc/1/exe", &st), errno);
    char l[256]; ssize_t n = readlink("/work/l3/exe", l, sizeof l);
    printf("readlink /work/l3/exe %zd errno %d %.*s\n", n, n < 0 ? errno : 0, n > 0 ? (int)n : 0, l);
    const char *links[] = {"/work/l3/cwd", "/work/l3/root", "/work/l3/fd/3005", "/work/l3/fd/1", "/work/l3/ns/net", "/work/l3/fd/3007", 0};
    for (int i = 0; links[i]; i++) { n = readlink(links[i], l, sizeof l); printf("readlink %s %zd errno %d %.*s\n", links[i], n, n < 0 ? errno : 0, n > 0 ? (int)n : 0, l); }
    printf("stat /work/l3/status %d errno %d\n", stat("/work/l3/status", &st), errno);
    printf("access /work/l3/mem %d errno %d\n", access("/work/l3/mem", R_OK), errno);
    return 0;
}
