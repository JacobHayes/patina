/* ctl.c: the C SDK's control call. `ctl` (main) cuts and heals (0), asks for an unknown
 * machine and bad words, pauses and resumes machine c (each twice: the second EALREADY), asks to
 * pause itself, steps c's clock and asks to step its own (EINVAL); `ctl machine` asks from another machine
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
    if (argc > 1 && strcmp(argv[1], "machine") == 0) {
        ask("heal");
        /* Up while main pauses and resumes it, however long the asks above took on this
         * host (the run ends with main). */
        sleep(5);
        return 0;
    }
    ask("partition main c");
    ask("heal --from main --to c");
    ask("partition main nobody");
    ask("net cut main c");
    ask("pause c");
    ask("pause c");
    ask("resume c");
    ask("resume c");
    ask("pause main");
    ask("clock c +1s");
    ask("clock main +1s");
    sleep(1); /* virtual: the other machine runs meanwhile */
    return 0;
}
