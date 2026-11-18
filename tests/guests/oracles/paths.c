/* paths MODE: path strings for `patina run --log-paths` (built static: no library opens).
 *   tour           creates data/a.txt and the symlink link -> data, reads link/a.txt, stats
 *                  /etc/passwd, looks up a 300-byte path, runs /bin/true x y
 *   edges          opens a path at a bad pointer (EFAULT), one ending at the end of a mapping,
 *                  one running past it (EFAULT), creates "odd\n\xff"; runs /bin/true with 300
 *                  arguments
 *   opens N        opens and closes data/a.txt N times
 *   escape [link] [fixed]
 *                  serves public/report.txt (and public/notes.txt, with "link" a symlink
 *                  planted to /etc/passwd) five times each. The bug: it checks a name with
 *                  stat and then opens the name, following any symlink: the planted one, or
 *                  one a path swap makes between the two calls. `fixed` opens beneath
 *                  the working directory with no symlink (openat2 RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS). */
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int put(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 1;
    ssize_t n = write(fd, text, strlen(text));
    return close(fd) || n != (ssize_t)strlen(text);
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "tour")) {
        char buf[64], longp[301];
        struct stat st;
        if (mkdir("data", 0755) || put("data/a.txt", "a\n") || symlink("data", "link")) return 2;
        int fd = open("link/a.txt", O_RDONLY);
        if (fd < 0 || read(fd, buf, sizeof buf) != 2 || close(fd)) return 2;
        if (stat("/etc/passwd", &st)) return 2;
        memset(longp, 'p', 300);
        longp[150] = '/';
        longp[300] = 0;
        if (stat(longp, &st) == 0) return 2;
        pid_t c = fork();
        if (c == 0) {
            execl("/bin/true", "/bin/true", "x", "y", (char *)0);
            _exit(127);
        }
        int ws;
        return waitpid(c, &ws, 0) == c && WIFEXITED(ws) ? WEXITSTATUS(ws) : 3;
    }
    if (!strcmp(m, "edges")) {
        long pg = sysconf(_SC_PAGESIZE);
        char *map = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || munmap(map + pg, pg)) return 2;
        printf("bad %d\n", (int)syscall(SYS_openat, AT_FDCWD, (char *)8, O_RDONLY) == -1);
        memcpy(map + pg - 6, "at-end", 6);
        printf("across %d\n", (int)syscall(SYS_openat, AT_FDCWD, map + pg - 6, O_RDONLY) == -1);
        memcpy(map + pg - 7, "at-end", 7);
        if (put(map + pg - 7, "e\n") || put("odd\n\xff", "o\n")) return 2;
        static char *args[302];
        static char words[300][8];
        args[0] = "/bin/true";
        for (int i = 0; i < 300; i++) {
            snprintf(words[i], sizeof words[i], "a%d", i);
            args[i + 1] = words[i];
        }
        pid_t c = fork();
        if (c == 0) {
            execv("/bin/true", args);
            _exit(127);
        }
        int ws;
        return waitpid(c, &ws, 0) == c && WIFEXITED(ws) ? WEXITSTATUS(ws) : 3;
    }
    if (!strcmp(m, "opens")) {
        long n = argc > 2 ? atol(argv[2]) : 100000;
        mkdir("data", 0755);
        if (put("data/a.txt", "a\n")) return 2;
        for (long i = 0; i < n; i++) {
            int fd = open("data/a.txt", O_RDONLY);
            if (fd < 0 || close(fd)) return 2;
        }
        return 0;
    }
    if (!strcmp(m, "escape")) {
        int link = 0, fixed = 0;
        for (int i = 2; i < argc; i++) {
            link |= !strcmp(argv[i], "link");
            fixed |= !strcmp(argv[i], "fixed");
        }
        if (mkdir("public", 0755) || put("public/report.txt", "quarterly numbers\n")) return 2;
        if (link && symlink("/etc/passwd", "public/notes.txt")) return 2;
        const char *names[] = {"report.txt", "notes.txt"};
        int served = 0, refused = 0;
        for (int i = 0; i < 5; i++) {
            for (int k = 0; k < 1 + link; k++) {
                char path[64], buf[256];
                struct stat st;
                snprintf(path, sizeof path, "public/%s", names[k]);
                if (stat(path, &st) || !S_ISREG(st.st_mode)) {
                    refused++;
                    continue;
                }
                int fd;
                if (fixed) {
                    struct open_how how = {.flags = O_RDONLY,
                                           .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS};
                    fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof how);
                } else {
                    fd = open(path, O_RDONLY);
                }
                if (fd < 0) {
                    refused++;
                    continue;
                }
                served += read(fd, buf, sizeof buf) > 0;
                close(fd);
            }
        }
        printf("%d served, %d refused\n", served, refused);
        return 0;
    }
    fprintf(stderr, "usage: paths tour|opens N|escape [link] [fixed]\n");
    return 2;
}
