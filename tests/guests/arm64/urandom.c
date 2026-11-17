/* 16 bytes read from /dev/urandom, printed: the runtime answers them from the seed. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    unsigned char b[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, b, sizeof b) != sizeof b) { perror("urandom"); return 1; }
    close(fd);
    for (int i = 0; i < 16; i++) printf("%02x", b[i]);
    printf("\n");
    return 0;
}
