#include "patina_native.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* A shared file mapping across the crash model: a store through the mapping
 * is what a read returns (written back before the read), an in-process crash
 * rolls both the file and the mapping back to the durable image, and
 * msync(MS_SYNC) makes a store survive the next crash — through a shared view
 * only: msync of a private view makes nothing durable. */
int main(void) {
    char contents[8] = {0};
    if (patina_init_crash(7) != 0) return 10;
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 11;
    /* Every name on the path is made durable, so a crash keeps the file. */
    int root = open("/", O_RDONLY | O_DIRECTORY);
    if (root < 0 || fsync(root) != 0 || close(root) != 0) return 12;
    int fd = open("/state/mapped", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 17;
    if (pwrite(fd, "durable", 7, 0) != 7) return 13;
    if (ftruncate(fd, 4096) != 0) return 14;
    if (fsync(fd) != 0) return 15;
    int dir = open("/state", O_RDONLY | O_DIRECTORY);
    if (dir < 0 || fsync(dir) != 0 || close(dir) != 0) return 16;

    char *view = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (view == MAP_FAILED) return 20;
    if (memcmp(view, "durable", 7) != 0) return 21;
    memcpy(view, "stored!", 7);
    if (pread(fd, contents, 7, 0) != 7 || memcmp(contents, "stored!", 7) != 0) return 22;

    if (patina_crash() != 0) return 30;
    if (memcmp(view, "durable", 7) != 0) return 31;
    if (pread(fd, contents, 7, 0) != 7 || memcmp(contents, "durable", 7) != 0) return 32;

    memcpy(view, "synced!", 7);
    if (msync(view, 4096, MS_SYNC) != 0) return 40;
    if (patina_crash() != 0) return 41;
    if (memcmp(view, "synced!", 7) != 0) return 42;
    if (pread(fd, contents, 7, 0) != 7 || memcmp(contents, "synced!", 7) != 0) return 43;

    /* msync of a PRIVATE view syncs nothing: a write not yet synced is lost
     * at the next crash, as on Linux. */
    if (pwrite(fd, "private", 7, 0) != 7) return 44;
    char *copy = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (copy == MAP_FAILED) return 45;
    if (msync(copy, 4096, MS_SYNC) != 0) return 46;
    if (patina_crash() != 0) return 47;
    if (pread(fd, contents, 7, 0) != 7) return 48;
    if (munmap(copy, 4096) != 0) return 49;

    if (munmap(view, 4096) != 0 || close(fd) != 0) return 50;
    /* A file whose name never became durable is empty after the crash, its
     * open descriptor and its page cache alike. */
    int lost = open("/state/lost", O_CREAT | O_RDWR, 0600);
    if (lost < 0 || pwrite(lost, "gone", 4, 0) != 4) return 60;
    char *gone = mmap(NULL, 4096, PROT_READ, MAP_SHARED, lost, 0);
    if (gone == MAP_FAILED) return 61;
    if (patina_crash() != 0) return 62;
    struct stat status;
    if (fstat(lost, &status) != 0 || status.st_size != 0) return 63;
    if (munmap(gone, 4096) != 0 || close(lost) != 0) return 64;
    /* printf is the shim's captured stdio: print while the context is live,
     * then drain the capture to the real descriptors. */
    printf("NATIVE_MMAP_CRASH_RESULT contents=%.7s\n", contents);
    if (patina_flush_captured_stdio() != 0) return 51;
    if (patina_shutdown() != 0) return 52;
    return 0;
}
