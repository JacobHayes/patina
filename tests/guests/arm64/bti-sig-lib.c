/* The handlers of bti-sig, in a shared object linked -z force-bti, so its loader maps the text
 * PROT_BTI where the CPU has BTI. Signal entry is an indirect branch (BTYPE=C): `h_pad` starts
 * with `bti c` and runs; `h_bare` has no landing pad, and its entry is a branch-target fault
 * (SIGILL) on a BTI host. Each sets the flag `bti_result` returns. */
__attribute__((visibility("hidden"))) int bti_flag;
int bti_result(void) { return bti_flag; }
__asm__(".text\n"
        ".balign 4\n"
        ".global h_pad\n"
        ".type h_pad, %function\n"
        "h_pad:\n"
        "\tbti c\n"
        "\tadrp x1, bti_flag\n"
        "\tmov w2, #1\n"
        "\tstr w2, [x1, :lo12:bti_flag]\n"
        "\tret\n"
        ".size h_pad, .-h_pad\n"
        ".global h_bare\n"
        ".type h_bare, %function\n"
        "h_bare:\n"
        "\tadrp x1, bti_flag\n"
        "\tmov w2, #2\n"
        "\tstr w2, [x1, :lo12:bti_flag]\n"
        "\tret\n"
        ".size h_bare, .-h_bare\n");
