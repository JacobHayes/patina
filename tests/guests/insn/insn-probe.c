/* instruction channels channel probe: execute every user-mode instruction that can observe something varying
 * (or might) and print "name value" or "name SIGNAME". Run natively on several cores and under
 * patina, and the differences between the two. */
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static sigjmp_buf jb;
static void on_sig(int s) { siglongjmp(jb, s); }

#define TRY(name, body)                                                     \
    do {                                                                    \
        int s_ = sigsetjmp(jb, 1);                                          \
        if (s_ == 0) {                                                      \
            body;                                                           \
        } else {                                                            \
            printf("%-14s %s\n", name, s_ == SIGSEGV ? "SIGSEGV" : s_ == SIGILL ? "SIGILL" : "SIG?"); \
        }                                                                   \
    } while (0)

static void cpuid(uint32_t l, uint32_t s, uint32_t r[4]) {
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(l), "c"(s));
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    int tsc_mode = -1;
    prctl(PR_GET_TSC, &tsc_mode);
    printf("%-14s %d\n", "pr_get_tsc", tsc_mode);
    uint32_t lo, hi, c;
    TRY("rdtsc", ({ __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); printf("%-14s %llu\n", "rdtsc", ((unsigned long long)hi << 32) | lo); }));
    TRY("rdtscp.aux", ({ __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(c)); printf("%-14s %u\n", "rdtscp.aux", c); }));
    TRY("rdpid", ({ uint64_t v; __asm__ volatile("rdpid %0" : "=r"(v)); printf("%-14s %llu\n", "rdpid", (unsigned long long)v); }));
    TRY("rdpru.mperf", ({ __asm__ volatile(".byte 0x0f,0x01,0xfd" : "=a"(lo), "=d"(hi) : "c"(0)); printf("%-14s %llu\n", "rdpru.mperf", ((unsigned long long)hi << 32) | lo); }));
    TRY("rdpmc.0", ({ __asm__ volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(0)); printf("%-14s %llu\n", "rdpmc.0", ((unsigned long long)hi << 32) | lo); }));
    TRY("rdrand", ({ uint64_t v; __asm__ volatile("rdrand %0" : "=r"(v)::"cc"); printf("%-14s %llx\n", "rdrand", (unsigned long long)v); }));
    TRY("rdseed", ({ uint64_t v; __asm__ volatile("rdseed %0" : "=r"(v)::"cc"); printf("%-14s %llx\n", "rdseed", (unsigned long long)v); }));
    uint32_t r[4];
    cpuid(1, 0, r);
    printf("%-14s %u\n", "cpuid1.apic", r[1] >> 24);
    cpuid(0xb, 0, r);
    printf("%-14s %u\n", "cpuidB.x2apic", r[3]);
    cpuid(0x8000001e, 0, r);
    printf("%-14s %u %u\n", "cpuid8000001e", r[0], r[1]);
    TRY("lsl.cpunode", ({ uint32_t v = 0; __asm__ volatile("lsl %1, %0" : "=r"(v) : "r"(0x7bu)); printf("%-14s cpu=%u node=%u\n", "lsl.cpunode", v & 0xfff, v >> 12); }));
    TRY("sgdt", ({ unsigned char b[10]; __asm__ volatile("sgdt %0" : "=m"(b)); printf("%-14s %llx\n", "sgdt", *(unsigned long long *)(b + 2)); }));
    TRY("sidt", ({ unsigned char b[10]; __asm__ volatile("sidt %0" : "=m"(b)); printf("%-14s %llx\n", "sidt", *(unsigned long long *)(b + 2)); }));
    TRY("sldt", ({ uint16_t v = 1; __asm__ volatile("sldt %0" : "=m"(v)); printf("%-14s %u\n", "sldt", v); }));
    TRY("str", ({ uint16_t v = 1; __asm__ volatile("str %0" : "=m"(v)); printf("%-14s %u\n", "str", v); }));
    TRY("smsw", ({ uint64_t v = 1; __asm__ volatile("smsw %0" : "=r"(v)); printf("%-14s %llx\n", "smsw", (unsigned long long)v); }));
    TRY("xgetbv0", ({ __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0)); printf("%-14s %x\n", "xgetbv0", lo); }));
    TRY("xgetbv1", ({ __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(1)); printf("%-14s %x\n", "xgetbv1", lo); }));
    TRY("rdfsbase", ({ uint64_t v; __asm__ volatile("rdfsbase %0" : "=r"(v)); printf("%-14s %llx\n", "rdfsbase", (unsigned long long)v); }));
    TRY("rdgsbase", ({ uint64_t v; __asm__ volatile("rdgsbase %0" : "=r"(v)); printf("%-14s %llx\n", "rdgsbase", (unsigned long long)v); }));
    TRY("rdsspq", ({ uint64_t v = 0; __asm__ volatile("rdsspq %0" : "+r"(v)); printf("%-14s %llx\n", "rdsspq", (unsigned long long)v); }));
    TRY("rdpkru", ({ __asm__ volatile("rdpkru" : "=a"(lo), "=d"(hi) : "c"(0)); printf("%-14s %x\n", "rdpkru", lo); }));
    TRY("xbegin", ({ __asm__ volatile(".byte 0xc7,0xf8,0,0,0,0" ::: "memory", "eax"); printf("%-14s ran\n", "xbegin"); }));
    TRY("monitorx", ({ static char m[64]; __asm__ volatile(".byte 0x0f,0x01,0xfa" :: "a"(m), "c"(0), "d"(0)); printf("%-14s ran\n", "monitorx"); }));
    TRY("umonitor", ({ static char m[64]; __asm__ volatile(".byte 0xf3,0x0f,0xae,0xf0" :: "a"(m)); printf("%-14s ran\n", "umonitor"); }));
    printf("%-14s %ld\n", "arch_get_cpuid", syscall(SYS_arch_prctl, 0x1011, 0));
    printf("%-14s %ld\n", "arch_set_cpuid", syscall(SYS_arch_prctl, 0x1012, 0));
    unsigned char *ar = (unsigned char *)getauxval(AT_RANDOM);
    printf("%-14s %02x%02x%02x%02x\n", "at_random", ar[0], ar[1], ar[2], ar[3]);
    printf("%-14s %lx %lx\n", "at_hwcap", getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    printf("%-14s %lx\n", "at_sysinfo", getauxval(AT_SYSINFO_EHDR));
    int local;
    void *m = malloc(100), *mm = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%-14s stack=%p heap=%p mmap=%p\n", "addresses", (void *)&local, m, mm);
    return 0;
}
