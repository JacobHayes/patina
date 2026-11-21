// What a program sees of its own code under load-time points (tests/rewrite/03-fidelity). Two
// small routines in assembly are planned the same in every build: fid_atomic, an atomic add
// (x86_64: `lock xadd` with a 32-bit displacement, 8 bytes, flags dead after it; arm64:
// `ldaddal`) whose count goes before it, the instruction running as a copy in a trampoline, and
// fid_spin, a loop that waits for a flag with a backward branch (x86_64: `jz rel32`; arm64:
// `cbz`) patched in place to its trampoline. Each mode prints what it found;
// natively and under Patina the lines are the same, except `checksum`.
//   fault     fid_atomic on a bad address: the SIGSEGV handler's ucontext names the address of
//             its `lock xadd` (fid_xadd), and backtrace() from the handler reaches main
//   timer     a timer signal interrupts fid_spin (no system call in it): the handler's
//             ucontext names an address inside fid_spin
//   checksum  the sum of fid_spin's bytes (a program that reads its own code reads the patch)
//   maps      /proc/self/maps lines of this program's file and of the C library
//   mprotect  makes fid_spin's page writable and back, then runs fid_spin once
//   jit       copies a routine into anonymous executable memory and calls it
//   fork      a child runs `fault` by execve of this program; the parent `timer`
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

long fid_atomic(long *p, long v);
void fid_spin(volatile int *flag);
extern char fid_xadd[], fid_spin_end[];
#if defined(__x86_64__)
#define PC(uc) ((ucontext_t *)(uc))->uc_mcontext.gregs[REG_RIP]
#define ATOMIC "lock xadd"
__asm__(".text\n"
	".globl fid_atomic\n.type fid_atomic,@function\n"
	"fid_atomic:\n"
	"  .cfi_startproc\n"
	"  mov %rsi, %rax\n"
	".globl fid_xadd\nfid_xadd:\n"
	"  lock xadd %rax, 0x1000(%rdi)\n"
	"  xor %edx, %edx\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size fid_atomic, .-fid_atomic\n"
	".globl fid_spin\n.type fid_spin,@function\n"
	".p2align 4\n"
	"fid_spin:\n"
	"  .cfi_startproc\n"
	"1: mov (%rdi), %eax\n"
	"  test %eax, %eax\n"
	"  .byte 0x0f, 0x84\n  .long 1b - (. + 4)\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".globl fid_spin_end\nfid_spin_end:\n"
	".size fid_spin, .-fid_spin\n");
// mov $42, %eax; ret
static const unsigned char jit_code[] = {0xb8, 42, 0, 0, 0, 0xc3};
#elif defined(__aarch64__)
#define PC(uc) ((ucontext_t *)(uc))->uc_mcontext.pc
#define ATOMIC "ldaddal"
__asm__(".text\n"
	".arch armv8.1-a\n"
	".globl fid_atomic\n.type fid_atomic,%function\n"
	"fid_atomic:\n"
	"  .cfi_startproc\n"
	"  add x2, x0, #0x1000\n"
	".globl fid_xadd\nfid_xadd:\n"
	"  ldaddal x1, x0, [x2]\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size fid_atomic, .-fid_atomic\n"
	".globl fid_spin\n.type fid_spin,%function\n"
	".p2align 4\n"
	"fid_spin:\n"
	"  .cfi_startproc\n"
	"1: ldr w1, [x0]\n"
	"  cbz w1, 1b\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".globl fid_spin_end\nfid_spin_end:\n"
	".size fid_spin, .-fid_spin\n");
// mov w0, #42; ret
static const unsigned char jit_code[] = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
#endif

static sigjmp_buf back;
static volatile uintptr_t seen_pc;
static volatile int seen_main, flag;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
	(void)sig, (void)si;
	seen_pc = PC(uc);
	void *f[32];
	int n = backtrace(f, 32);
	for (int i = 0; i < n; i++) {
		Dl_info d;
		if (dladdr(f[i], &d) && d.dli_sname && !strcmp(d.dli_sname, "main"))
			seen_main = 1;
	}
	siglongjmp(back, 1);
}

static void on_alarm(int sig, siginfo_t *si, void *uc)
{
	(void)sig, (void)si;
	seen_pc = PC(uc);
	flag = 1;
}

static void handle(int sig, void (*h)(int, siginfo_t *, void *))
{
	struct sigaction sa = {0};
	sa.sa_sigaction = h;
	sa.sa_flags = SA_SIGINFO;
	sigaction(sig, &sa, 0);
}

static int fault(void)
{
	handle(SIGSEGV, on_segv);
	if (!sigsetjmp(back, 1))
		fid_atomic((long *)8, 1);
	printf("fault: at the " ATOMIC " %s; backtrace reaches main %s\n",
	       seen_pc == (uintptr_t)fid_xadd ? "yes" : "no", seen_main ? "yes" : "no");
	return 0;
}

static int timer(void)
{
	handle(SIGALRM, on_alarm);
	struct itimerval t = {.it_value = {.tv_usec = 2000}};
	setitimer(ITIMER_REAL, &t, 0);
	fid_spin(&flag);
	uintptr_t lo = (uintptr_t)fid_spin, hi = (uintptr_t)fid_spin_end;
	printf("timer: interrupted inside fid_spin %s\n", seen_pc >= lo && seen_pc < hi ? "yes" : "no");
	return 0;
}

static int checksum(void)
{
	unsigned sum = 0;
	for (const unsigned char *p = (const void *)fid_spin; p < (const unsigned char *)fid_spin_end; p++)
		sum = sum * 31 + *p;
	printf("checksum: %08x\n", sum);
	return 0;
}

static int maps(void)
{
	char self[4096], line[8192];
	ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
	if (n < 0)
		return 1;
	self[n] = 0;
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f)
		return 1;
	while (fgets(line, sizeof line, f))
		if (strstr(line, self) || strstr(line, "libc.so"))
			fputs(line, stdout);
	fclose(f);
	return 0;
}

static int reprotect(void)
{
	uintptr_t page = (uintptr_t)fid_spin & ~(uintptr_t)4095;
	if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) ||
	    mprotect((void *)page, 4096, PROT_READ | PROT_EXEC))
		return 1;
	flag = 1;
	fid_spin(&flag);
	checksum();
	return 0;
}

static int jit(void)
{
	void *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED)
		return 1;
	memcpy(m, jit_code, sizeof jit_code);
	__builtin___clear_cache((char *)m, (char *)m + sizeof jit_code);
	if (mprotect(m, 4096, PROT_READ | PROT_EXEC))
		return 1;
	printf("jit: %d\n", ((int (*)(void))m)());
	return 0;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";
	setvbuf(stdout, 0, _IONBF, 0);
	if (!strcmp(m, "fault"))
		return fault();
	if (!strcmp(m, "timer"))
		return timer();
	if (!strcmp(m, "checksum"))
		return checksum();
	if (!strcmp(m, "maps"))
		return maps();
	if (!strcmp(m, "mprotect"))
		return reprotect();
	if (!strcmp(m, "jit"))
		return jit();
	if (!strcmp(m, "fork")) {
		pid_t c = fork();
		if (c == 0) {
			execl("/proc/self/exe", argv[0], "fault", (char *)0);
			_exit(127);
		}
		int st;
		timer();
		return waitpid(c, &st, 0) != c || st != 0;
	}
	fprintf(stderr, "usage: fidelity fault|timer|checksum|maps|mprotect|jit|fork\n");
	return 2;
}
