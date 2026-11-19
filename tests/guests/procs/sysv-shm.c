/* System V shared memory as Linux has it.
 *
 * sysv-shm all: every check below; prints "ok" (exit 0) or the first failure (exit 3).
 * - shmget: IPC_PRIVATE; a key with IPC_CREAT|IPC_EXCL (again: EEXIST); a missing key without
 *   IPC_CREAT (ENOENT); a larger size than the segment's (EINVAL).
 * - IPC_STAT: size, key, mode, creator pid, nattch; IPC_SET changes the mode.
 * - nattch across fork (the child's attachment counts), exit, execve (the old image's
 *   attachment ends) and shmdt; two attachments in one process; munmap of a whole attachment.
 * - shmat at an address the program chooses: exact, SHM_RND, unaligned without SHM_RND
 *   (EINVAL), over a mapping without SHM_REMAP (EINVAL) and with it.
 * - SHM_RDONLY: a store is SIGSEGV.
 * - IPC_RMID while attached: still usable, the key is gone, SHM_DEST in the mode; the segment
 *   ends at the last detach (IPC_STAT: EINVAL).
 * - an unrelated image (exec of this program) finds a segment by its key and sees its data;
 *   a process-shared mutex in a segment between two processes.
 * sysv-shm refused: SHM_HUGETLB and SHM_LOCK, printed (their answers depend on privileges).
 * sysv-shm crash: with --crash: the first incarnation makes key 0x5053 and writes it, then
 *   writes /work/f (crash points); a later one prints whether the segment is still there. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c, ...)                                   \
    do {                                                \
        if (!(c)) {                                     \
            printf("FAIL line %d: ", __LINE__);         \
            printf(__VA_ARGS__);                        \
            printf(" (errno %d)\n", errno);             \
            fflush(stdout);                             \
            _exit(3);                                   \
        }                                               \
    } while (0)

static char *self;

static struct shmid_ds st(int id) {
    struct shmid_ds d;
    CHECK(shmctl(id, IPC_STAT, &d) == 0, "IPC_STAT %d", id);
    return d;
}

static int status_of(pid_t c) {
    int s;
    CHECK(waitpid(c, &s, 0) == c, "waitpid");
    return s;
}

static void keys(void) {
    key_t k = 0x4b45;
    int id = shmget(k, 8192, IPC_CREAT | IPC_EXCL | 0640);
    CHECK(id >= 0, "create key");
    CHECK(shmget(k, 8192, IPC_CREAT | IPC_EXCL | 0640) < 0 && errno == EEXIST, "EEXIST");
    CHECK(shmget(k, 0, 0) == id, "find key");
    CHECK(shmget(k, 4096, IPC_CREAT) == id, "smaller size");
    CHECK(shmget(k, 9000, 0) < 0 && errno == EINVAL, "larger size");
    CHECK(shmget(0x4b46, 10, 0) < 0 && errno == ENOENT, "missing key");
    struct shmid_ds d = st(id);
    CHECK(d.shm_segsz == 8192 && d.shm_perm.__key == k && (d.shm_perm.mode & 0777) == 0640 &&
              d.shm_cpid == getpid() && d.shm_nattch == 0 && d.shm_perm.uid == getuid(),
          "stat size %zu key %d mode %o cpid %d nattch %lu", d.shm_segsz, d.shm_perm.__key,
          d.shm_perm.mode, d.shm_cpid, d.shm_nattch);
    d.shm_perm.mode = 0600;
    CHECK(shmctl(id, IPC_SET, &d) == 0 && (st(id).shm_perm.mode & 0777) == 0600, "IPC_SET");
    CHECK(shmctl(id, IPC_RMID, NULL) == 0, "rmid");
    CHECK(shmctl(id, IPC_STAT, &d) < 0 && errno == EINVAL, "gone at once without attachments");
}

static void attachments(void) {
    int id = shmget(IPC_PRIVATE, 10000, 0600);
    CHECK(id >= 0, "IPC_PRIVATE");
    char *a = shmat(id, NULL, 0), *b = shmat(id, NULL, 0);
    CHECK(a != (void *)-1 && b != (void *)-1 && a != b, "two attachments");
    CHECK(st(id).shm_nattch == 2, "nattch 2");
    strcpy(a, "one");
    CHECK(!strcmp(b, "one"), "same memory");
    CHECK(a[9999] == 0, "zeroed");
    pid_t c = fork();
    if (c == 0) {
        CHECK(st(id).shm_nattch == 4, "child: nattch %lu", st(id).shm_nattch);
        strcpy(a, "child");
        CHECK(shmdt(b) == 0, "child shmdt");
        CHECK(st(id).shm_nattch == 3, "child after shmdt");
        _exit(0);
    }
    CHECK(status_of(c) == 0, "child");
    CHECK(!strcmp(b, "child") && st(id).shm_nattch == 2, "after the child's exit: %lu", st(id).shm_nattch);
    // execve ends the old image's attachments.
    c = fork();
    if (c == 0) {
        char arg[16];
        snprintf(arg, sizeof arg, "%d", id);
        execl(self, self, "after-exec", arg, (char *)NULL);
        _exit(5);
    }
    CHECK(status_of(c) == 0, "exec child");
    CHECK(shmdt(b) == 0 && st(id).shm_nattch == 1, "shmdt");
    CHECK(shmdt(b) < 0 && errno == EINVAL, "shmdt twice");
    CHECK(munmap(a, 12288) == 0 && st(id).shm_nattch == 0, "munmap of an attachment");
    CHECK(shmctl(id, IPC_RMID, NULL) == 0, "rmid");
}

static void addresses(void) {
    int id = shmget(IPC_PRIVATE, 4096, 0600);
    char *hole = mmap(NULL, 8 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(hole != MAP_FAILED, "mmap");
    CHECK(munmap(hole, 8 * 4096) == 0, "munmap");
    char *at = hole + 2 * 4096;
    CHECK(shmat(id, at, 0) == at, "chosen address");
    CHECK(shmat(id, at + 4096 + 10, 0) == (void *)-1 && errno == EINVAL, "unaligned");
    CHECK(shmat(id, at + 4096 + 10, SHM_RND) == at + 4096, "SHM_RND");
    CHECK(shmat(id, at, 0) == (void *)-1 && errno == EINVAL, "in use");
    CHECK(shmat(id, at, SHM_REMAP) == at, "SHM_REMAP");
    CHECK(shmat(id, NULL, SHM_REMAP) == (void *)-1 && errno == EINVAL, "SHM_REMAP without an address");
    at[0] = 'x';
    CHECK(at[4096] == 'x', "the same memory");
    CHECK(shmdt(at) == 0 && shmdt(at + 4096) == 0, "shmdt");
    // SHM_REMAP replaced the first attachment's mapping, which ended with it.
    struct shmid_ds d = st(id);
    CHECK(d.shm_nattch == 0, "nattch after remap %lu", d.shm_nattch);
    char *ro = shmat(id, NULL, SHM_RDONLY);
    CHECK(ro != (void *)-1 && ro[0] == 'x', "SHM_RDONLY read");
    pid_t c = fork();
    if (c == 0) {
        ro[0] = 'y';
        _exit(0);
    }
    int s = status_of(c);
    CHECK(WIFSIGNALED(s) && WTERMSIG(s) == SIGSEGV, "store to SHM_RDONLY: status %d", s);
    // IPC_RMID while attached.
    key_t k = 0x5244;
    int kid = shmget(k, 100, IPC_CREAT | 0600);
    char *p = shmat(kid, NULL, 0);
    CHECK(shmctl(kid, IPC_RMID, NULL) == 0, "rmid attached");
    d = st(kid);
    CHECK((d.shm_perm.mode & SHM_DEST) && d.shm_perm.__key == IPC_PRIVATE && d.shm_nattch == 1,
          "marked: mode %o key %d", d.shm_perm.mode, d.shm_perm.__key);
    CHECK(shmget(k, 100, 0) < 0 && errno == ENOENT, "key gone");
    strcpy(p, "still");
    CHECK(!strcmp(p, "still"), "usable");
    CHECK(shmdt(p) == 0, "last detach");
    CHECK(shmctl(kid, IPC_STAT, &d) < 0 && errno == EINVAL, "gone at the last detach");
    shmdt(ro);
    shmctl(id, IPC_RMID, NULL);
}

struct counter {
    pthread_mutex_t mu;
    long n;
    char note[64];
};

static void unrelated_and_mutex(void) {
    key_t k = 0x554e;
    int id = shmget(k, sizeof(struct counter), IPC_CREAT | 0600);
    struct counter *c = shmat(id, NULL, 0);
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&c->mu, &ma);
    strcpy(c->note, "from the parent");
    pid_t ch = fork();
    if (ch == 0) {
        execl(self, self, "unrelated", (char *)NULL);
        _exit(5);
    }
    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&c->mu);
        long v = c->n;
        sched_yield();
        c->n = v + 1;
        pthread_mutex_unlock(&c->mu);
    }
    CHECK(status_of(ch) == 0, "unrelated image");
    CHECK(c->n == 200 && !strcmp(c->note, "from the child"), "counter %ld note %s", c->n, c->note);
    shmdt(c);
    shmctl(id, IPC_RMID, NULL);
}

static int unrelated(void) {
    int id = shmget(0x554e, 0, 0);
    CHECK(id >= 0, "unrelated: find the key");
    struct counter *c = shmat(id, NULL, 0);
    CHECK(c != (void *)-1 && !strcmp(c->note, "from the parent"), "unrelated: data");
    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&c->mu);
        long v = c->n;
        sched_yield();
        c->n = v + 1;
        pthread_mutex_unlock(&c->mu);
    }
    strcpy(c->note, "from the child");
    return 0;
}

static int after_exec(int id) {
    // The parent's two attachments; the one this process had before its execve is gone.
    CHECK(st(id).shm_nattch == 2, "after exec: nattch %lu", st(id).shm_nattch);
    return 0;
}

static int crash(void) {
    const char *inc = getenv("PATINA_INCARNATION");
    if (!inc) {
        int id = shmget(0x5053, 4096, IPC_CREAT | 0600);
        char *p = shmat(id, NULL, 0);
        strcpy(p, "kept");
        for (int i = 0; i < 20; i++) {
            int fd = open("/work/f", O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (write(fd, "x", 1) != 1) return 4;
            fsync(fd);
            close(fd);
        }
        printf("not crashed\n");
        return 0;
    }
    int id = shmget(0x5053, 0, 0);
    if (id < 0) {
        printf("incarnation %s: no segment (errno %d)\n", inc, errno);
        return 0;
    }
    struct shmid_ds d = st(id);
    char *p = shmat(id, NULL, SHM_RDONLY);
    printf("incarnation %s: segment %d nattch %lu holds %s\n", inc, id, d.shm_nattch, p);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    self = argv[0];
    const char *m = argc > 1 ? argv[1] : "all";
    if (!strcmp(m, "after-exec")) return after_exec(atoi(argv[2]));
    if (!strcmp(m, "unrelated")) return unrelated();
    if (!strcmp(m, "crash")) return crash();
    if (!strcmp(m, "refused")) {
        int r = shmget(IPC_PRIVATE, 2 << 20, SHM_HUGETLB | 0600);
        printf("SHM_HUGETLB: %d errno %d\n", r, r < 0 ? errno : 0);
        int id = shmget(IPC_PRIVATE, 4096, 0600);
        r = shmctl(id, SHM_LOCK, NULL);
        printf("SHM_LOCK: %d errno %d\n", r, r < 0 ? errno : 0);
        return 0;
    }
    keys();
    attachments();
    addresses();
    unrelated_and_mutex();
    printf("ok\n");
    return 0;
}
