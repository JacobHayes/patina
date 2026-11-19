/* ctl.c: the C SDK's control call. `ctl driver` cuts and heals (0), and asks for an unknown
 * node, bad words and a later feature; `ctl node` asks from a node (EPERM). Each answer is
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
               : r == -EINVAL ? "EINVAL" : r == -EOPNOTSUPP ? "EOPNOTSUPP" : strerror((int)-r));
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "node") == 0) {
        ask("net heal");
        ask("mark from-a-node");
        return 0;
    }
    ask("net cut driver c");
    ask("net heal --from driver --to c");
    ask("net cut driver nobody");
    ask("net sever driver c");
    ask("node kill c");
    sleep(1); /* virtual: the node runs meanwhile */
    return 0;
}
