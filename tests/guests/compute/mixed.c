/* Several processes, some rebuilt with compute points, under one seed.
 *   mixed            four threads add up a table under a mutex; then, each checked:
 *                    posix_spawn of stock /usr/bin/sha256sum on this program (prints its hash);
 *                    a fork child that computes in the copied cell and exits with its sum;
 *                    vfork, a computed argument in the child, exec of `mixed leaf`;
 *                    fork, then exec of `mixed leaf` (this image's third start).
 *                    Prints one line per step and `ok`; exits 1 at the first wrong answer.
 *   mixed leaf N     a loop of N iterations; prints `leaf N sum=S`.
 *   mixed many DIR N copies this program to DIR/m0 .. DIR/m(N-1) and runs each as a leaf
 *                    (N distinct instrumented paths); prints `many N ok`. */
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static long table[512];
static long total;
static volatile long sink;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static long sum(long n, long salt)
{
	long s = 0;
	for (long i = 0; i < n; i++) s += table[(i * 7 + salt) & 511] ^ i;
	return s;
}

static void *worker(void *arg)
{
	long k = (long)arg;
	for (int r = 0; r < 20; r++) {
		long s = sum(200, k + r);
		pthread_mutex_lock(&mu);
		total += s;
		pthread_mutex_unlock(&mu);
	}
	return 0;
}

static int fail(const char *what)
{
	printf("FAIL %s\n", what);
	return 1;
}

static int waited(pid_t p, int want)
{
	int st;
	if (waitpid(p, &st, 0) != p) return 0;
	return WIFEXITED(st) && WEXITSTATUS(st) == want;
}

static int run_leaf(const char *prog, int use_vfork, long n)
{
	char arg[32];
	pid_t p = use_vfork ? vfork() : fork();
	if (p < 0) return 0;
	if (p == 0) {
		/* Computed in the child, in this image's code: under vfork the cell is the parent's. */
		sink = sum(64, n);
		snprintf(arg, sizeof arg, "%ld", n);
		char *argv[] = {(char *)prog, "leaf", arg, 0};
		execve(prog, argv, environ);
		_exit(127);
	}
	return waited(p, 0);
}

static int tree(const char *self)
{
	pthread_t t[4];
	for (long i = 0; i < 4; i++)
		if (pthread_create(&t[i], 0, worker, (void *)i)) return fail("pthread_create");
	for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
	long want = 0;
	for (long k = 0; k < 4; k++)
		for (int r = 0; r < 20; r++) want += sum(200, k + r);
	if (total != want) return fail("threads");
	printf("threads total=%ld\n", total);
	fflush(stdout);

	/* A stock child: its hash of this program comes back through a pipe. */
	int fd[2];
	if (pipe(fd)) return fail("pipe");
	posix_spawn_file_actions_t fa;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, fd[1], 1);
	posix_spawn_file_actions_addclose(&fa, fd[0]);
	posix_spawn_file_actions_addclose(&fa, fd[1]);
	char *argv[] = {"/usr/bin/sha256sum", (char *)self, 0};
	pid_t p;
	if (posix_spawn(&p, argv[0], &fa, 0, argv, environ)) return fail("posix_spawn");
	posix_spawn_file_actions_destroy(&fa);
	close(fd[1]);
	char buf[256];
	ssize_t n = 0, r;
	while (n < (ssize_t)sizeof buf - 1 && (r = read(fd[0], buf + n, sizeof buf - 1 - n)) > 0) n += r;
	close(fd[0]);
	buf[n] = 0;
	if (!waited(p, 0) || n < 64) return fail("sha256sum");
	printf("sha256 %.64s\n", buf);
	fflush(stdout);

	/* A fork child computing in its copy of the cell. */
	long fs = sum(5000, 3);
	p = fork();
	if (p == 0) _exit((int)(sum(5000, 3) & 0x7f));
	if (p < 0 || !waited(p, (int)(fs & 0x7f))) return fail("fork child");
	printf("fork child sum&127=%ld\n", fs & 0x7f);
	fflush(stdout);

	if (!run_leaf(self, 1, 3000)) return fail("vfork exec");
	if (!run_leaf(self, 0, 4000)) return fail("fork exec");
	printf("ok\n");
	return 0;
}

static int copy(const char *from, const char *to)
{
	int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (in < 0 || out < 0) return 0;
	char b[65536];
	ssize_t n;
	while ((n = read(in, b, sizeof b)) > 0)
		if (write(out, b, n) != n) return 0;
	close(in);
	return close(out) == 0 && n == 0;
}

int main(int argc, char **argv)
{
	for (int i = 0; i < 512; i++) table[i] = i * 31 + argc;
	if (argc == 3 && !strcmp(argv[1], "leaf")) {
		long n = atol(argv[2]);
		printf("leaf %ld sum=%ld\n", n, sum(n, 1));
		return 0;
	}
	if (argc == 4 && !strcmp(argv[1], "many")) {
		int n = atoi(argv[3]);
		for (int i = 0; i < n; i++) {
			char path[4096];
			snprintf(path, sizeof path, "%s/m%d", argv[2], i);
			if (!copy(argv[0], path)) return fail("copy");
			fflush(stdout);
			if (!run_leaf(path, 0, 100)) return fail("many leaf");
		}
		printf("many %d ok\n", n);
		return 0;
	}
	if (argc == 1) return tree(argv[0]);
	fprintf(stderr, "usage: mixed [leaf N | many DIR N]\n");
	return 2;
}
