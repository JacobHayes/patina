int main(void) {
    void *p;
    /* movabs $0xffffffffff600000, %reg — a single 64-bit immediate in .text. */
    __asm__ volatile("movabs $0xffffffffff600000, %0" : "=r"(p));
    return p != 0;
}
