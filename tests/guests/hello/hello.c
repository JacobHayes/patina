// the skeleton guest: arguments, pid, clocks, entropy, addresses, a file under /work, a listing of /work.
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    for (int i = 0; i < argc; i++) printf("arg %d %s\n", i, argv[i]);
    printf("pid %d\n", (int)getpid());
    for (int i = 0; i < 100; i++) {
        struct timespec m, r;
        clock_gettime(CLOCK_MONOTONIC, &m);
        clock_gettime(CLOCK_REALTIME, &r);
        printf("clock %d %lld.%09ld %lld.%09ld\n", i, (long long)m.tv_sec, m.tv_nsec, (long long)r.tv_sec, r.tv_nsec);
    }
    unsigned char rnd[16];
    if (getrandom(rnd, sizeof rnd, 0) != sizeof rnd) { perror("getrandom"); return 1; }
    printf("random ");
    for (int i = 0; i < 16; i++) printf("%02x", rnd[i]);
    printf("\n");
    void *big = malloc(1 << 20);
    int local = 0;
    printf("malloc %p\nstack %p\n", big, (void *)&local);
    int fd = open("/work/hello.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    if (write(fd, "hello\n", 6) != 6) { perror("write"); return 1; }
    close(fd);
    struct stat st;
    if (stat("/work/hello.txt", &st) != 0) { perror("stat"); return 1; }
    printf("stat dev %llx ino %llu mode %o nlink %llu size %lld blocks %lld atime %lld mtime %lld ctime %lld\n",
           (unsigned long long)st.st_dev, (unsigned long long)st.st_ino, st.st_mode, (unsigned long long)st.st_nlink,
           (long long)st.st_size, (long long)st.st_blocks, (long long)st.st_atime, (long long)st.st_mtime,
           (long long)st.st_ctime);
    DIR *d = opendir("/work");
    if (!d) { perror("opendir"); return 1; }
    struct dirent *e;
    while ((e = readdir(d))) printf("dirent %s %llu\n", e->d_name, (unsigned long long)e->d_ino);
    closedir(d);
    free(big);
    return 0;
}
