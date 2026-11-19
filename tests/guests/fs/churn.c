/* churn N: create and remove N files and N symlinks under /tmp, one of each at a time, while
 * holding a descriptor of a file unlinked before the churn. More inodes are created than the
 * runtime's table of changed inodes holds, so its entries for the removed ones must be
 * reclaimed; the held file's times must survive that. Exit 0, or 1 naming what differed.
 * churn pipes N: create, fstat and close N pipes (each gets a virtual inode number, which
 * the runtime does not reclaim: past its table, a named limit).
 * churn socks N: create N unix socket pairs, pass a byte, close them (never asking for their
 * inode numbers, so none is given). */
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 2 && argv[1][0] == 's') {
        long n = atol(argv[2]);
        for (long i = 0; i < n; i++) {
            int sv[2];
            char c = 'x';
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
            if (write(sv[0], &c, 1) != 1 || read(sv[1], &c, 1) != 1) return 2;
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (argc > 2 && argv[1][0] == 'p') {
        long n = atol(argv[2]);
        for (long i = 0; i < n; i++) {
            int p[2];
            struct stat st;
            if (pipe(p) != 0 || fstat(p[0], &st) != 0) return 2;
            close(p[0]);
            close(p[1]);
        }
        return 0;
    }
    long n = argc > 1 ? atol(argv[1]) : 100000;
    int held = open("/tmp/held", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (held < 0 || write(held, "x", 1) != 1 || unlink("/tmp/held") != 0) return 2;
    struct stat before, after;
    if (fstat(held, &before) != 0) return 2;
    for (long i = 0; i < n; i++) {
        int fd = open("/tmp/f", O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0 || close(fd) != 0 || symlink("f", "/tmp/l") != 0 || unlink("/tmp/l") != 0 ||
            unlink("/tmp/f") != 0) {
            fprintf(stderr, "churn: step %ld failed\n", i);
            return 2;
        }
    }
    if (fstat(held, &after) != 0) return 2;
    if (before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        fprintf(stderr, "churn: the held file's times changed: mtime %ld.%09ld -> %ld.%09ld\n",
                (long)before.st_mtim.tv_sec, before.st_mtim.tv_nsec, (long)after.st_mtim.tv_sec,
                after.st_mtim.tv_nsec);
        return 1;
    }
    printf("churn: %ld files and %ld symlinks\n", n, n);
    return 0;
}
