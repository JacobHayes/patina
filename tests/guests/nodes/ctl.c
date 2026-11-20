/* ctl.c: the C SDK's control call. `ctl driver` cuts and heals (0), asks for an unknown
 * node and bad words, pauses and resumes node c (each twice: the second EALREADY), asks to
 * pause itself, steps c's clock and asks to step its own (EINVAL); `ctl node` asks from a node
 * (EPERM). Each answer is
 * printed as `WORDS: errno NAME`, or `ok`. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "patina.h"

static void ask(const char *w) {
    long r = patina_control(w);
    if (r == 0)
        printf("%s: ok\n", w);
    else
        printf("%s: %s\n", w, r == -EPERM ? "EPERM" : r == -ENOENT ? "ENOENT"
               : r == -EINVAL ? "EINVAL" : r == -EOPNOTSUPP ? "EOPNOTSUPP"
               : r == -EALREADY ? "EALREADY" : strerror((int)-r));
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "node") == 0) {
        ask("net heal");
        ask("mark from-a-node");
        /* Up while the driver pauses and resumes it, however long the asks above took on this
         * host (the run ends with the driver). */
        sleep(5);
        return 0;
    }
    ask("net cut driver c");
    ask("net heal --from driver --to c");
    ask("net cut driver nobody");
    ask("net sever driver c");
    ask("node pause c");
    ask("node pause c");
    ask("node resume c");
    ask("node resume c");
    ask("node pause driver");
    ask("clock step c +1s");
    ask("clock step driver +1s");
    sleep(1); /* virtual: the node runs meanwhile */
    return 0;
}
