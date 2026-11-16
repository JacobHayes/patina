/* sandbox hardening guest: the metadata of what the guest reads from the host: its own image under /guest,
 * the guest directory, /etc/ld.so.cache and an /etc/alternatives link. Hex dumps of stat; and
 * the hidden copy sources must not be reachable. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void st(const char *p, int follow) {
    struct stat s;
    int r = follow ? stat(p, &s) : lstat(p, &s);
    printf("%s r=%d", p, r);
    if (!r) {
        const unsigned char *b = (const void *)&s;
        printf(" ");
        for (unsigned i = 0; i < sizeof s; i++) printf("%02x", b[i]);
    }
    printf("\n");
}

int main(void) {
    st("/guest", 1);
    st("/guest/hostcopy", 1);
    st("/etc/ld.so.cache", 1);
    st("/etc/alternatives", 1);
    st("/etc/alternatives/awk", 0);
    int fd = open("/.patina/guest/hostcopy", O_RDONLY);
    printf("open /.patina/guest/hostcopy %d errno %d\n", fd, fd < 0 ? errno : 0);
    return 0;
}
