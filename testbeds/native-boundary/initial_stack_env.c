/* Class detector: runtimes may find envp and the platform startup trailer by
 * walking argv, without consulting environ. Expected entries are argv[1..]. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#endif
#ifdef __APPLE__
#include <crt_externs.h>
#endif

extern char **environ;

static int initial_stack_sentinel(int argc, char **argv) {
    /* The caller supplies exec's original env entry count. Even after startup
     * scrubs envp, the original trailer remains at that offset. Measure it in
     * this very binary, not from an assumed kernel or a different executable.
     * Return codes distinguish reaching main from every startup refusal. */
    if (argv[2][0] == '\0') return 43;
    size_t capacity = 0;
    for (const char *digit = argv[2]; *digit != '\0'; ++digit) {
        if (*digit < '0' || *digit > '9') return 43;
        capacity = capacity * 10 + (size_t)(*digit - '0');
    }
    char **trailer = argv + argc + 1 + capacity + 1;
    size_t slots;
#ifdef __linux__
    ElfW(auxv_t) *end = (ElfW(auxv_t) *)trailer;
    while (end->a_type != AT_NULL) end++;
    slots = (size_t)((char *)(end + 1) - (char *)trailer) / sizeof(char *);
#elif defined(__APPLE__)
    char **end = trailer;
    while (*end != NULL) end++;
    slots = (size_t)(end + 1 - trailer);
#endif
    printf("INITIAL_STACK_TRAILER slots=%zu\n", slots);
    return 42;
}

int main(int argc, char **argv, char **envp) {
    if (argc == 3 && strcmp(argv[1], "sentinel") == 0)
        return initial_stack_sentinel(argc, argv);
    char **initial_env = argv + argc + 1;
    assert(argv[argc] == NULL);
    assert(envp == initial_env);
    for (int i = 1; i < argc; ++i) {
        assert(initial_env[i - 1] != NULL);
        assert(strcmp(initial_env[i - 1], argv[i]) == 0);
        assert(strncmp(initial_env[i - 1], "PATINA_", 7) != 0);
    }
    assert(initial_env[argc - 1] == NULL);
    assert(envp == environ);
#ifdef __linux__
    ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(initial_env + argc);
    unsigned long pagesize = 0;
    int found_random = 0;
    size_t entries = 0;
    for (; aux->a_type != AT_NULL; ++aux) {
        assert(++entries < 256);
        if (aux->a_type == AT_PAGESZ) {
            assert(pagesize == 0);
            pagesize = aux->a_un.a_val;
        }
        if (aux->a_type == AT_RANDOM) {
            assert(aux->a_un.a_val != 0);
            found_random = 1;
        }
        /* libc still walks the original trailer. Compare every uncached entry,
         * including AT_RANDOM and any vDSO entry, not only the page size. */
        if (aux->a_type != AT_IGNORE && aux->a_type != AT_HWCAP)
            assert(aux->a_un.a_val == getauxval(aux->a_type));
    }
    assert(found_random);
    assert(pagesize != 0);
    assert(pagesize == getauxval(AT_PAGESZ));
#elif defined(__APPLE__)
    assert(*_NSGetEnviron() == envp);
    /* Darwin has a NULL-terminated apple-string vector, not an ELF auxv. */
    char **apple = initial_env + argc;
    assert(apple[0] != NULL);
    assert(strncmp(apple[0], "executable_path=", 16) == 0);
    size_t entries = 0;
    while (*apple != NULL) {
        assert(++entries < 256);
        assert(strncmp(*apple, "PATINA_", 7) != 0);
        ++apple;
    }
#endif
    printf("INITIAL_STACK_ENV entries=%d\n", argc - 1);
    return 0;
}
