/* Writes a text in upper case to out.txt, 4 KiB at a time, with no Patina SDK in it. Every
 * error ends it cleanly: a message and exit status 1. The planted bug: the count write()
 * returns is checked for -1 only, so a short write loses the rest of that block and the
 * program still exits 0, with the wrong file. `upcase fixed` writes the rest. */
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int fixed = argc > 1 && !strcmp(argv[1], "fixed");
    int out = open("out.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { perror("upcase: open"); return 1; }
    static char text[96 << 10];
    long len = 0;
    for (int i = 0; len < (long)sizeof text - 64; i++)
        len += snprintf(text + len, sizeof text - len, "line %d: the quick brown fox\n", i);
    for (long i = 0; i < len; i++) text[i] = toupper((unsigned char)text[i]);
    for (long at = 0; at < len;) {
        long n = len - at < 4096 ? len - at : 4096;
        ssize_t w = write(out, text + at, n);
        if (w < 0) { perror("upcase: write"); return 1; }
        at += fixed ? w : n;
    }
    if (fsync(out) < 0 || close(out) < 0) { perror("upcase: sync"); return 1; }
    printf("wrote %ld bytes\n", len);
    return 0;
}
