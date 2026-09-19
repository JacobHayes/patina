int main(void) {
#if defined(__x86_64__)
    __asm__ volatile("mov $39, %%rax\n\tsyscall" ::: "rax", "rcx", "r11");
#elif defined(__aarch64__)
    __asm__ volatile("mov x8, #172\n\tsvc #0" ::: "x8", "x0");
#endif
    return 0;
}
