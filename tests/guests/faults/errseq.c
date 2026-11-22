/* errseq: how write-back errors are reported, one scenario per mode, each printing one line
 * per call ("LABEL 0" or "LABEL ERRNO-NAME"). Under Patina the first sync-class call of the
 * mode is given the injected failure (`--fault fsync-error-at=1`); tests/faults/22-errseq.sh
 * holds what Linux returns (its header cites the kernel sources).
 *
 *   errseq MODE
 *     sfr      write, close; sync_file_range(WRITE) on a new descriptor (fails), close; fsync
 *              on a new one, again on it, then on one opened after
 *     wait     sync_file_range(WRITE | WAIT_AFTER) (fails)
 *     before   two descriptors opened before the failure: fsync of one fails, the other
 *              reports it once; one opened after reports nothing
 *     dup      fsync of a descriptor fails; its duplicate reports nothing
 *     fork     the child's fsync of an inherited descriptor fails; the parent's of the same
 *              description reports nothing, of one it opened apart reports it
 *     msync    a store through a shared mapping, msync(MS_SYNC) fails; fsync of the
 *              descriptor it was mapped from reports nothing
 *     dir      fsync of a directory fails, then succeeds
 *     syncfs   syncfs fails; again on it, then on a descriptor opened before, one after; fsync
 *              of a file written before the failure reports it
 *     osync    a write through an O_DSYNC descriptor fails; the next fsync reports nothing
 *     badfd [DIR] no injection: fsync and sync_file_range of an O_PATH descriptor and of a
 *              pipe (DIR, default /work, holds the file: natively a scratch directory)
 *     pg       the durability shape: write files, sync_file_range(WRITE) each, then reopen and
 *              fsync each, then acknowledge (a synced marker); on a restart every file of an
 *              acknowledged set must hold its data, else "INVARIANT acked-file-lost" and exit
 *              1. A failed fsync stops it without acknowledging.
 *     pg-retry the planted bug: retry a failed fsync on a new descriptor, then acknowledge
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void show(const char *label, long r) {
    printf("%s %s\n", label, r < 0 ? strerrorname_np(errno) : "0");
    fflush(stdout);
}

static int make(const char *p, const char *data) {
    int fd = open(p, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0 || write(fd, data, strlen(data)) != (long)strlen(data)) {
        perror(p);
        exit(2);
    }
    return fd;
}

static int reopen(const char *p) {
    int fd = open(p, O_RDWR);
    if (fd < 0) {
        perror(p);
        exit(2);
    }
    return fd;
}

#define N 4
#define LEN 4096

static void fill(int i, char *b) {
    memset(b, 'a' + i, LEN);
}

static int pg(int retry) {
    char p[64], b[LEN], got[LEN];
    if (access("/work/ack", F_OK) == 0) {
        for (int i = 0; i < N; i++) {
            snprintf(p, sizeof p, "/work/f%d", i);
            fill(i, b);
            int fd = open(p, O_RDONLY);
            long n = fd < 0 ? -1 : read(fd, got, LEN);
            if (n != LEN || memcmp(got, b, LEN) != 0) {
                printf("INVARIANT acked-file-lost f%d (%ld bytes)\n", i, n);
                return 1;
            }
            close(fd);
        }
        printf("acknowledged files kept\n");
        return 0;
    }
    const char *boot = getenv("PATINA_BOOT");
    if (boot && atoi(boot) > 1) {
        printf("restarted before the acknowledgement\n");
        return 0;
    }
    for (int i = 0; i < N; i++) {
        snprintf(p, sizeof p, "/work/f%d", i);
        fill(i, b);
        int fd = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (fd < 0 || write(fd, b, LEN) != LEN) return 2;
        close(fd);
    }
    /* The pre-sync pass: start write-back of each file, ignoring errors. */
    for (int i = 0; i < N; i++) {
        snprintf(p, sizeof p, "/work/f%d", i);
        int fd = open(p, O_RDONLY);
        sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE);
        close(fd);
    }
    for (int i = 0; i < N; i++) {
        snprintf(p, sizeof p, "/work/f%d", i);
        int fd = open(p, O_RDONLY);
        while (fsync(fd) != 0) {
            printf("fsync f%d: %s\n", i, strerrorname_np(errno));
            if (!retry) return 0;
            close(fd);
            fd = open(p, O_RDONLY);
        }
        close(fd);
    }
    int d = open("/work", O_RDONLY | O_DIRECTORY);
    if (fsync(d) != 0) return 0;
    int a = make("/work/ack", "ack\n");
    if (fsync(a) != 0 || fsync(d) != 0) return 0;
    printf("acknowledged\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "sfr")) {
        close(make("/work/f", "data"));
        int a = reopen("/work/f");
        show("sfr-write", sync_file_range(a, 0, 0, SYNC_FILE_RANGE_WRITE));
        close(a);
        int b = reopen("/work/f");
        show("fsync-new", fsync(b));
        show("fsync-again", fsync(b));
        int c = reopen("/work/f");
        show("fsync-later", fsync(c));
    } else if (!strcmp(m, "wait")) {
        int a = make("/work/f", "data");
        show("sfr-write-wait",
             sync_file_range(a, 0, 0, SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER));
        show("fsync", fsync(a));
    } else if (!strcmp(m, "before")) {
        int a = make("/work/f", "data");
        int b = reopen("/work/f");
        show("fsync-a", fsync(a));
        show("fsync-b", fsync(b));
        show("fsync-b-again", fsync(b));
        int c = reopen("/work/f");
        show("fsync-after", fsync(c));
    } else if (!strcmp(m, "dup")) {
        int a = make("/work/f", "data");
        int b = dup(a);
        show("fsync", fsync(a));
        show("fsync-dup", fsync(b));
    } else if (!strcmp(m, "fork")) {
        int a = make("/work/f", "data");
        int b = reopen("/work/f");
        pid_t c = fork();
        if (c == 0) {
            show("child-fsync", fsync(a));
            _exit(0);
        }
        waitpid(c, NULL, 0);
        show("parent-fsync-shared", fsync(a));
        show("parent-fsync-own", fsync(b));
    } else if (!strcmp(m, "msync")) {
        int a = make("/work/f", "data");
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, a, 0);
        if (p == MAP_FAILED) return 2;
        p[0] = 'D';
        show("msync", msync(p, 4096, MS_SYNC));
        show("fsync", fsync(a));
    } else if (!strcmp(m, "dir")) {
        close(make("/work/f", "data"));
        int d = open("/work", O_RDONLY | O_DIRECTORY);
        show("fsync-dir", fsync(d));
        show("fsync-dir-again", fsync(d));
    } else if (!strcmp(m, "syncfs")) {
        int f = make("/work/f", "data");
        int d = open("/work", O_RDONLY | O_DIRECTORY);
        show("syncfs", syncfs(d));
        show("syncfs-again", syncfs(d));
        show("syncfs-before", syncfs(f));
        int g = open("/work", O_RDONLY | O_DIRECTORY);
        show("syncfs-after", syncfs(g));
        show("fsync-file", fsync(f));
    } else if (!strcmp(m, "osync")) {
        int a = open("/work/f", O_CREAT | O_WRONLY | O_DSYNC, 0644);
        show("write-dsync", write(a, "data", 4));
        show("fsync", fsync(a));
    } else if (!strcmp(m, "badfd")) {
        char p[4096];
        snprintf(p, sizeof p, "%s/f", argc > 2 ? argv[2] : "/work");
        close(make(p, "data"));
        int o = open(p, O_PATH);
        show("fsync-opath", fsync(o));
        show("sfr-opath", sync_file_range(o, 0, 0, SYNC_FILE_RANGE_WRITE));
        int pp[2];
        if (pipe(pp) != 0) return 2;
        show("fsync-pipe", fsync(pp[1]));
        show("sfr-pipe", sync_file_range(pp[1], 0, 0, SYNC_FILE_RANGE_WRITE));
    } else if (!strcmp(m, "pg")) {
        return pg(0);
    } else if (!strcmp(m, "pg-retry")) {
        return pg(1);
    } else {
        fprintf(stderr, "usage: errseq MODE\n");
        return 2;
    }
    return 0;
}
