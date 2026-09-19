/* `main`'s third parameter keeps pointing at the ORIGINAL host environ array
 * after startup repoints the environ global at the deterministic one, so the
 * ambient host environment must be scrubbed in that original array IN PLACE.
 * The caller supplies the PATINA_* protocol through the host environment,
 * because that is the ordering that matters: a supervised startup installs the
 * runtime -- publishing the deterministic array -- BEFORE the scrub runs, so a
 * scrub that resolves the array through the environ global would wipe the guest
 * environment and leave the host's fully readable here. */
#include <stdio.h>

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv;
    int count = 0;
    if (envp != NULL) {
        for (char **entry = envp; *entry != NULL; ++entry) count += 1;
    }
    printf("NATIVE_ENVP_RESULT count=%d first=%s\n", count,
           (envp != NULL && envp[0] != NULL) ? envp[0] : "<none>");
    return 0;
}
