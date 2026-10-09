/* A C translation unit that registers its own `.preinit_array` entry: linked
 * into a guest ahead of the shim, it would run before the shim armed its
 * containment, so the pre-run audit refuses the binary (`early-init`). */
static void guest_preinit(int argc, char **argv, char **envp) {
    (void)argc;
    (void)argv;
    (void)envp;
}

__attribute__((section(".preinit_array"), used)) static void (*const guest_preinit_entry)(
    int, char **, char **) = guest_preinit;
