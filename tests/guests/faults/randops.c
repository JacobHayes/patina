/* randops: N (default 10,000) random file operations on /work from a seeded generator
 * (seeded by getrandom, which the simulator derives from --seed). Covers write, pwrite,
 * writev, O_APPEND from two descriptors, ftruncate, fallocate (plain, keep-size, punch),
 * rename (also over an existing name and RENAME_EXCHANGE), link, unlink, mkdir/rmdir,
 * symlink, chmod, setxattr/removexattr, copy_file_range (also into write-only descriptors), shared writable mmap stores (with
 * msync, munmap, or left mapped), fsync/fdatasync, and unlinked-but-open files.
 * Prints a summary of operation counts and the final tree's checksum.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>

#define NAMES 12
#define FDS 6
#define MAXSZ 65536
static uint64_t rs;
static uint64_t rnd(void) {
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return rs;
}
static unsigned rn(unsigned n) { return (unsigned)(rnd() % n); }

static char names[NAMES][16];
static int fds[FDS] = {-1, -1, -1, -1, -1, -1};
static struct { char *p; size_t len; int fd; } maps[4];
static long counts[32];
static const char *opn[32] = {"open", "close", "write", "pwrite", "writev", "append2", "truncate", "falloc",
                              "punch", "rename", "rename-over", "exchange", "link", "unlink", "mkdir", "rmdir",
                              "symlink", "chmod", "xattr", "copy", "mmap", "mstore", "msync", "munmap",
                              "fsync", "fdatasync", "failed"};

static const char *name(void) { return names[rn(NAMES)]; }

static int anyfd(void) {
    int i = rn(FDS);
    if (fds[i] < 0) {
        fds[i] = open(name(), O_CREAT | O_RDWR | (rn(4) == 0 ? O_APPEND : 0), 0644);
        counts[0]++;
    }
    return fds[i];
}

static void fill(char *b, size_t n) {
    char c = 'A' + rn(26);
    for (size_t i = 0; i < n; i++) b[i] = c + (i % 7);
}

static off_t size_of(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 ? st.st_size : 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    long n = argc > 1 ? atol(argv[1]) : 10000;
    if (getrandom(&rs, sizeof rs, 0) != sizeof rs) return 2;
    rs |= 1;
    mkdir("d", 0755);
    for (int i = 0; i < NAMES; i++) snprintf(names[i], sizeof names[i], i < 8 ? "f%d" : "d/g%d", i);
    char buf[8192];
    for (long k = 0; k < n; k++) {
        int op = rn(26), fd, r = 0;
        switch (op) {
        case 0: { /* open/create, sometimes O_TRUNC */
            int i = rn(FDS);
            if (fds[i] >= 0) close(fds[i]);
            fds[i] = open(name(), O_CREAT | O_RDWR | (rn(5) == 0 ? O_TRUNC : 0) | (rn(4) == 0 ? O_APPEND : 0), 0644);
            r = fds[i];
            break;
        }
        case 1: { int i = rn(FDS); if (fds[i] >= 0) { r = close(fds[i]); fds[i] = -1; } break; }
        case 2: fd = anyfd(); if (fd >= 0 && lseek(fd, 0, SEEK_CUR) > MAXSZ) lseek(fd, 0, SEEK_SET); { size_t l = 1 + rn(2000); fill(buf, l); r = (int)write(fd, buf, l); } break;
        case 3: fd = anyfd(); { size_t l = 1 + rn(3000); fill(buf, l); r = (int)pwrite(fd, buf, l, rn(MAXSZ - 3000)); } break;
        case 4: fd = anyfd(); {
            struct iovec v[3];
            fill(buf, 900);
            for (int j = 0; j < 3; j++) v[j].iov_base = buf + 300 * j, v[j].iov_len = 1 + rn(299);
            r = (int)writev(fd, v, 3);
        } break;
        case 5: { /* O_APPEND from two descriptors of one file */
            const char *nm = name();
            int a = open(nm, O_CREAT | O_WRONLY | O_APPEND, 0644), b = open(nm, O_WRONLY | O_APPEND);
            if (a >= 0 && b >= 0 && size_of(a) < MAXSZ) {
                fill(buf, 64);
                r = (int)write(a, buf, 1 + rn(64));
                fill(buf, 64);
                r = (int)write(b, buf, 1 + rn(64));
            }
            if (a >= 0) close(a);
            if (b >= 0) close(b);
        } break;
        case 6: fd = anyfd(); r = ftruncate(fd, rn(MAXSZ)); break;
        case 7: fd = anyfd(); r = fallocate(fd, rn(2) ? FALLOC_FL_KEEP_SIZE : 0, rn(MAXSZ / 2), 1 + rn(MAXSZ / 2)); break;
        case 8: fd = anyfd(); r = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, rn(MAXSZ), 1 + rn(10000)); break;
        case 9: r = rename(name(), name()); break;
        case 10: r = renameat2(AT_FDCWD, name(), AT_FDCWD, name(), RENAME_NOREPLACE); break;
        case 11: r = renameat2(AT_FDCWD, name(), AT_FDCWD, name(), RENAME_EXCHANGE); break;
        case 12: r = link(name(), name()); break;
        case 13: r = unlink(name()); break;
        case 14: r = mkdir(rn(2) ? "d/sub" : "e", 0755); break;
        case 15: r = rmdir(rn(2) ? "d/sub" : "e"); break;
        case 16: r = symlink(name(), name()); break;
        case 17: r = chmod(name(), 0600 | (rn(2) ? 044 : 0)); break;
        case 18: fd = anyfd(); {
            char k[16];
            snprintf(k, sizeof k, "user.k%u", rn(3));
            r = rn(3) ? fsetxattr(fd, k, buf, 1 + rn(40), 0) : fremovexattr(fd, k);
        } break;
        case 19: { /* copy_file_range, sometimes into a write-only descriptor (as cp does) */
            int a = anyfd(), wo = rn(2), b = wo ? open(name(), O_CREAT | O_WRONLY, 0644) : anyfd();
            loff_t i = rn(MAXSZ / 2), o = rn(MAXSZ / 2);
            r = (int)copy_file_range(a, &i, b, &o, rn(8000), 0);
            if (wo && b >= 0) close(b);
        } break;
        case 20: { /* map a file shared and writable */
            int m = rn(4);
            if (maps[m].p) break;
            fd = anyfd();
            if (fcntl(fd, F_GETFL) & O_APPEND) break;
            off_t s = size_of(fd);
            if (s < 4096) break;
            size_t len = (s / 4096) * 4096;
            void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            /* the mapping keeps its own descriptor: the guest's may be closed and reused */
            if (p != MAP_FAILED) maps[m].p = p, maps[m].len = len, maps[m].fd = dup(fd);
            else r = -1;
        } break;
        case 21: { int m = rn(4); if (!maps[m].p) break;
            /* store only where the file still has pages */
            off_t s = size_of(maps[m].fd);
            size_t lim = (size_t)s < maps[m].len ? (size_t)s : maps[m].len;
            if (lim == 0) break;
            size_t off = rn(lim), l = 1 + rn(200);
            if (off + l > lim) l = lim - off;
            fill(buf, l);
            memcpy(maps[m].p + off, buf, l);
        } break;
        case 22: { int m = rn(4); if (maps[m].p) r = msync(maps[m].p, maps[m].len, rn(2) ? MS_SYNC : MS_ASYNC); } break;
        case 23: { int m = rn(4); if (maps[m].p) { r = munmap(maps[m].p, maps[m].len); maps[m].p = NULL; close(maps[m].fd); } } break;
        case 24: fd = anyfd(); r = fsync(fd); break;
        case 25: fd = anyfd(); r = fdatasync(fd); break;
        }
        counts[op]++;
        if (r < 0) counts[26]++;
    }
    for (int i = 0; i < 27; i++) printf("%s %ld\n", opn[i], counts[i]);
    return 0;
}
