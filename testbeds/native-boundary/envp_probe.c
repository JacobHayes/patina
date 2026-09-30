/* Direct PATINA_* protocol startup has no supervisor stack reservation.
 * Its empty map must still hide every host/control entry through both the
 * original argv-adjacent array and main's envp, sharing environ at entry. */
#include <assert.h>
#include <stdio.h>

extern char **environ;

int main(int argc, char **argv, char **envp) {
    assert(envp == environ);
    assert((argv + argc + 1)[0] == NULL);
    int count = 0;
    if (envp != NULL) {
        for (char **entry = envp; *entry != NULL; ++entry) count += 1;
    }
    printf("NATIVE_ENVP_RESULT count=%d first=%s\n", count,
           (envp != NULL && envp[0] != NULL) ? envp[0] : "<none>");
    return 0;
}
