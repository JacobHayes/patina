#define _GNU_SOURCE
#include "patina_native.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <unistd.h>

/* Virtual answers of the memory family that no host setting may reach, one
 * mode per argument:
 *   limits    RLIMIT_MEMLOCK is the virtual 8 MiB, lowered as an unprivileged
 *             process may, and mlock is judged against it (the test runs this
 *             with the host limit at zero); the other resources follow the
 *             same rule from their own virtual starting values;
 *   mprotect  a shared view that may not write refuses PROT_WRITE (EACCES)
 *             while a private copy takes it;
 *   huge      no hugetlb pages are configured, across mmap, shmget and memfd,
 *             and a memfd's fallocate takes only KEEP_SIZE and PUNCH_HOLE;
 *   thp       transparent huge pages are off, so one touch is one page, and
 *             PR_GET_THP_DISABLE reads what the guest set last;
 *   sigbus    a touch past the end of a mapped file raises SIGBUS;
 *   populate  mlock faults its range in and answers ENOMEM for a page no
 *             fault reaches (PROT_NONE, past a file's end), as __mm_populate,
 *             and msync(MS_INVALIDATE) over a locked page is EBUSY;
 *   descriptors  every mapped file holds one host memfd: past the host's
 *             descriptor limit the shim stops by name, and the guest never
 *             sees the host's EMFILE (the test lowers the host limit). */

#define MIB (1024UL * 1024UL)

static int expect_errno(long result, int expected) {
    return result == -1 && errno == expected;
}

static int limits(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) return 10;
    if (limit.rlim_cur != 8 * MIB || limit.rlim_max != 8 * MIB) return 11;
    char *region = mmap(NULL, 16 * MIB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 12;
    if (mlock(region, 4096) != 0) return 13;
    if (!expect_errno(mlock(region, 9 * MIB), ENOMEM)) return 14;
    limit.rlim_cur = limit.rlim_max = 4096;
    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) return 15;
    /* The page already locked counts; a second one is past the limit. */
    if (!expect_errno(mlock(region + 4096, 4096), ENOMEM)) return 16;
    if (mlock(region, 4096) != 0) return 17;
    limit.rlim_cur = limit.rlim_max = 8 * MIB;
    if (!expect_errno(setrlimit(RLIMIT_MEMLOCK, &limit), EPERM)) return 18;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0 || limit.rlim_max != 4096) return 19;
    if (munlockall() != 0 || munmap(region, 16 * MIB) != 0) return 20;
    /* Every other resource follows the same unprivileged rule from its own
     * virtual start: core dumps off (the daemon idiom), the descriptor soft
     * limit raised to its hard limit (Go's runtime does at start), then
     * lowered, which the descriptor table enforces. */
    if (getrlimit(RLIMIT_STACK, &limit) != 0 || limit.rlim_cur != 8 * MIB ||
        limit.rlim_max != RLIM_INFINITY) return 30;
    limit.rlim_cur = limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) return 31;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur != 1024 || limit.rlim_max != 4096)
        return 32;
    limit.rlim_cur = 4096;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 33;
    limit.rlim_cur = limit.rlim_max = 8;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 34;
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 35;
    int last = -1;
    for (;;) {
        int fd = open("/state/limit", O_CREAT | O_RDWR, 0600);
        if (fd < 0) break;
        last = fd;
    }
    if (errno != EMFILE || last != 7) return 36;
    limit.rlim_max = 4096;
    if (!expect_errno(setrlimit(RLIMIT_NOFILE, &limit), EPERM)) return 37;
    return 0;
}

static int mprotect_views(void) {
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 10;
    int fd = open("/state/mapped", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, 4096) != 0 || close(fd) != 0) return 11;
    fd = open("/state/mapped", O_RDONLY);
    if (fd < 0) return 12;
    char *shared = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (shared == MAP_FAILED) return 13;
    if (!expect_errno(mprotect(shared, 4096, PROT_READ | PROT_WRITE), EACCES)) return 14;
    char *private = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (private == MAP_FAILED) return 15;
    if (mprotect(private, 4096, PROT_READ | PROT_WRITE) != 0) return 16;
    private[0] = 'p';
    if (shared[0] != 0) return 17;
    if (munmap(shared, 4096) != 0 || munmap(private, 4096) != 0 || close(fd) != 0) return 18;
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (id < 0) return 20;
    char *segment = shmat(id, NULL, SHM_RDONLY);
    if (segment == (void *)-1) return 21;
    if (!expect_errno(mprotect(segment, 4096, PROT_READ | PROT_WRITE), EACCES)) return 22;
    if (shmdt(segment) != 0 || shmctl(id, IPC_RMID, NULL) != 0) return 23;
    return 0;
}

static int huge(void) {
    int anon = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
    void *view = mmap(NULL, 2 * MIB, PROT_READ | PROT_WRITE, anon, -1, 0);
    if (!expect_errno(view == MAP_FAILED ? -1 : 0, ENOMEM)) return 10;
    view = mmap(NULL, 2 * MIB, PROT_READ | PROT_WRITE, anon | MAP_NORESERVE, -1, 0);
    if (view == MAP_FAILED || munmap(view, 2 * MIB) != 0) return 11;
    /* MAP_FIXED_NOREPLACE keeps its address: EEXIST over a live mapping, the
     * address itself once free, EINVAL off a huge-page boundary. */
    char *region = mmap(NULL, 4 * MIB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 30;
    char *aligned = (char *)(((uintptr_t)region + 2 * MIB - 1) & ~(uintptr_t)(2 * MIB - 1));
    int claim = anon | MAP_NORESERVE | MAP_FIXED_NOREPLACE;
    view = mmap(aligned, 2 * MIB, PROT_READ | PROT_WRITE, claim, -1, 0);
    if (!expect_errno(view == MAP_FAILED ? -1 : 0, EEXIST)) return 31;
    if (munmap(aligned, 2 * MIB) != 0) return 32;
    if (mmap(aligned, 2 * MIB, PROT_READ | PROT_WRITE, claim, -1, 0) != aligned) return 33;
    view = mmap(aligned + 4096, 2 * MIB, PROT_READ | PROT_WRITE, claim, -1, 0);
    if (!expect_errno(view == MAP_FAILED ? -1 : 0, EINVAL)) return 34;
    if (munmap(region, 4 * MIB) != 0) return 35;
    if (!expect_errno(shmget(IPC_PRIVATE, 2 * MIB, IPC_CREAT | SHM_HUGETLB | 0600), EPERM)) return 12;
    int fd = memfd_create("huge", MFD_HUGETLB);
    if (fd < 0) return 13;
    if (!expect_errno(write(fd, "x", 1), EINVAL)) return 14;
    if (!expect_errno(ftruncate(fd, 4096), EINVAL)) return 15;
    if (ftruncate(fd, 2 * MIB) != 0) return 16;
    view = mmap(NULL, 2 * MIB, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!expect_errno(view == MAP_FAILED ? -1 : 0, ENOMEM)) return 17;
    if (close(fd) != 0) return 18;
    /* Any memfd's fallocate (shmem's as hugetlbfs's) takes only KEEP_SIZE
     * and PUNCH_HOLE. */
    int plain = memfd_create("plain", 0);
    if (plain < 0) return 19;
    if (!expect_errno(fallocate(plain, FALLOC_FL_ZERO_RANGE, 0, 4096), EOPNOTSUPP)) return 20;
    if (fallocate(plain, 0, 0, 4096) != 0) return 21;
    if (fallocate(plain, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096) != 0) return 22;
    if (close(plain) != 0) return 23;
    return 0;
}

static int thp(void) {
    char *region = mmap(NULL, 4 * MIB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 10;
    char *aligned = (char *)(((uintptr_t)region + 2 * MIB - 1) & ~(uintptr_t)(2 * MIB - 1));
    if (madvise(aligned, 2 * MIB, MADV_HUGEPAGE) != 0) return 11;
    aligned[0] = 1;
    unsigned char resident[2 * MIB / 4096];
    if (mincore(aligned, 2 * MIB, resident) != 0) return 12;
    size_t pages = 0;
    for (size_t i = 0; i < sizeof resident; i++) pages += resident[i] & 1;
    if (pages != 1) return 13;
    if (munmap(region, 4 * MIB) != 0) return 14;
    /* The flag reads as the guest set it last. */
    if (prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 1) return 15;
    if (prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) != 0) return 16;
    if (prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 0) return 17;
    if (!expect_errno(prctl(PR_SET_THP_DISABLE, 1, 1, 0, 0), EINVAL)) return 18;
    return 0;
}

static int sigbus(void) {
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 10;
    int fd = open("/state/short", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, 100) != 0) return 11;
    volatile char *view = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (view == MAP_FAILED) return 12;
    view[99] = 'x';
    view[4096] = 'x';
    return 13;
}

static int populate(void) {
    char *region = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 10;
    if (mprotect(region + 4096, 4096, PROT_NONE) != 0) return 11;
    if (!expect_errno(mlock(region, 3 * 4096), ENOMEM)) return 12;
    /* A lock is the virtual kernel's alone: MS_INVALIDATE over it is EBUSY. */
    if (!expect_errno(msync(region, 4096, MS_INVALIDATE), EBUSY)) return 14;
    if (munlock(region, 3 * 4096) != 0) return 13;
    if (msync(region, 4096, MS_INVALIDATE) != 0) return 15;
    if (munmap(region, 3 * 4096) != 0) return 13;
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 20;
    int fd = open("/state/short", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, 100) != 0) return 21;
    char *view = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
    if (view == MAP_FAILED) return 22;
    if (mlock(view, 4096) != 0) return 23;
    if (!expect_errno(mlock(view, 8192), ENOMEM)) return 24;
    unsigned char resident[2];
    if (mincore(view, 8192, resident) != 0 || (resident[0] & 1) != 1) return 25;
    if (munlockall() != 0 || munmap(view, 8192) != 0 || close(fd) != 0) return 26;
    return 0;
}

static int descriptors(void) {
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 10;
    for (int i = 0; i < 256; i++) {
        char path[32];
        snprintf(path, sizeof path, "/state/%d", i);
        int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, 4096) != 0) return 11;
        void *view = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (view == MAP_FAILED) return errno == EMFILE ? 12 : 13;
        if (close(fd) != 0) return 14;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (patina_init_seed(7) != 0) return 3;
    int status;
    if (strcmp(argv[1], "limits") == 0) {
        status = limits();
    } else if (strcmp(argv[1], "mprotect") == 0) {
        status = mprotect_views();
    } else if (strcmp(argv[1], "huge") == 0) {
        status = huge();
    } else if (strcmp(argv[1], "thp") == 0) {
        status = thp();
    } else if (strcmp(argv[1], "sigbus") == 0) {
        status = sigbus();
    } else if (strcmp(argv[1], "populate") == 0) {
        status = populate();
    } else if (strcmp(argv[1], "descriptors") == 0) {
        status = descriptors();
    } else {
        return 4;
    }
    if (status != 0) return status;
    printf("NATIVE_MEM_RESULT %s=ok\n", argv[1]);
    if (patina_flush_captured_stdio() != 0) return 5;
    if (patina_shutdown() != 0) return 6;
    return 0;
}
