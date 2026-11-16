/* storage reproductions regression guest: an injected close error applies to regular files only.
 * Closes a /work directory descriptor (close #1), then a /work file (close #2), and prints
 * each result. Run with --fault fs-error-at=close:1 or close:2. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(void) {
    mkdir("/work/d", 0755);
    int d = open("/work/d", O_RDONLY | O_DIRECTORY);
    int r = close(d);
    printf("dir close %d %s\n", r, r ? strerror(errno) : "ok");
    int f = open("/work/f", O_CREAT | O_WRONLY, 0644);
    r = close(f);
    printf("file close %d %s\n", r, r ? strerror(errno) : "ok");
    return 0;
}
