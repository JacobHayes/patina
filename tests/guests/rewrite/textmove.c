// A program that changes one page of its own text, then computes in two threads
// (tests/rewrite/06-textmove). `cold` and `hot` are loops, each alone on a page of its own;
// natively and under Patina the lines are the same.
//   mremap    moves cold's page with mremap(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP),
//             as V8 moves its builtins, and calls the copy and the original place
//   mprotect  makes cold's page read-only and executable again, and calls it
//   munmap    unmaps cold's page, the middle of the text
//   remap     unmaps cold's page and maps it again from the file, then the threads run cold
// Then two threads each run hot (cold for remap) and the results are printed.
#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#define PG 4096
#define OWN_PAGE __attribute__((noinline, aligned(PG), section(".text.textmove")))

OWN_PAGE unsigned long hot(unsigned long n)
{
	unsigned long x = 1;
	for (unsigned long i = 0; i < n; i++)
		x = x * 6364136223846793005ul + i;
	return x;
}

OWN_PAGE unsigned long cold(unsigned long n)
{
	unsigned long x = 7;
	for (unsigned long i = 0; i < n; i++)
		x = x * 2862933555777941757ul + (i ^ 3037000493ul);
	return x;
}

// Ends cold's page: nothing else shares it.
OWN_PAGE void textmove_end(void)
{
}

typedef unsigned long (*loop_fn)(unsigned long);
static loop_fn run_fn = hot;
static unsigned long out[2];

static void *worker(void *arg)
{
	long k = (long)arg;
	out[k] = run_fn(300000 + k);
	return NULL;
}

// The file offset of the executable's page at `page` (a static, non-PIE program: its program
// headers give the link addresses it runs at).
static long file_offset(uintptr_t page)
{
	const Elf64_Phdr *ph = (const void *)getauxval(AT_PHDR);
	unsigned long n = getauxval(AT_PHNUM);
	for (unsigned long i = 0; i < n; i++)
		if (ph[i].p_type == PT_LOAD && page >= ph[i].p_vaddr &&
		    page < ph[i].p_vaddr + ph[i].p_memsz)
			return (long)(ph[i].p_offset + (page - ph[i].p_vaddr));
	return -1;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";
	uintptr_t page = (uintptr_t)cold & ~(uintptr_t)(PG - 1);
	if (!strcmp(m, "mremap")) {
		void *to = mmap(NULL, PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		void *r = mremap((void *)page, PG, PG, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
				 to);
		if (r == MAP_FAILED) {
			perror("mremap");
			return 1;
		}
		loop_fn moved = (loop_fn)((uintptr_t)r + ((uintptr_t)cold - page));
		printf("mremap: the copy %lx, the original place %lx\n", moved(1000), cold(1000));
	} else if (!strcmp(m, "mprotect")) {
		if (mprotect((void *)page, PG, PROT_READ) || mprotect((void *)page, PG, PROT_READ | PROT_EXEC)) {
			perror("mprotect");
			return 1;
		}
		printf("mprotect: %lx\n", cold(1000));
	} else if (!strcmp(m, "munmap") || !strcmp(m, "remap")) {
		if (munmap((void *)page, PG)) {
			perror("munmap");
			return 1;
		}
		printf("munmap: done\n");
		if (!strcmp(m, "remap")) {
			int fd = open("/proc/self/exe", O_RDONLY);
			long off = file_offset(page);
			if (fd < 0 || off < 0 ||
			    mmap((void *)page, PG, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, off) !=
				    (void *)page) {
				perror("remap");
				return 1;
			}
			close(fd);
			run_fn = cold;
			printf("remap: done\n");
		}
	} else {
		fprintf(stderr, "usage: textmove mremap|mprotect|munmap|remap\n");
		return 2;
	}
	pthread_t t[2];
	for (long k = 0; k < 2; k++)
		pthread_create(&t[k], NULL, worker, (void *)k);
	for (int k = 0; k < 2; k++)
		pthread_join(t[k], NULL);
	printf("threads: %lx %lx\n", out[0], out[1]);
	return 0;
}
