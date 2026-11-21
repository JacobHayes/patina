/* A realistic small program: a worker pool. Jobs come from a mutex-protected queue,
 * each worker hashes its job's data and writes a result line, then bumps the shared
 * statistics, outside the lock (the bug: `stats.done++` and `stats.bytes += n` are
 * unsynchronised read-modify-writes with no system call between the read and the write).
 * At the end the program checks its own statistics. Exit 1 and "LOST-UPDATE" if a count
 * went missing. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NJOBS 24
#define NWORKERS 3

struct job { int id; int len; };
static struct job queue[NJOBS];
static int head;
static pthread_mutex_t qmu = PTHREAD_MUTEX_INITIALIZER;
static struct { long done; long bytes; } stats;

static int next_job(struct job *j)
{
	pthread_mutex_lock(&qmu);
	int ok = head < NJOBS;
	if (ok) *j = queue[head++];
	pthread_mutex_unlock(&qmu);
	return ok;
}

static void *worker(void *arg)
{
	long w = (long)arg;
	struct job j;
	while (next_job(&j)) {
		unsigned h = 2166136261u;
		for (int i = 0; i < j.len; i++) h = (h ^ (unsigned)(j.id * 131 + i)) * 16777619u;
		char line[64];
		int n = snprintf(line, sizeof line, "worker %ld job %d hash %08x\n", w, j.id, h);
		if (write(1, line, n) != n) exit(2);
		stats.done++;          /* unsynchronised */
		stats.bytes += j.len;  /* unsynchronised */
	}
	return 0;
}

int main(void)
{
	long want_bytes = 0;
	for (int i = 0; i < NJOBS; i++) {
		queue[i].id = i;
		queue[i].len = 16 + (i * 37) % 64;
		want_bytes += queue[i].len;
	}
	pthread_t t[NWORKERS];
	for (long i = 0; i < NWORKERS; i++) pthread_create(&t[i], 0, worker, (void *)i);
	for (int i = 0; i < NWORKERS; i++) pthread_join(t[i], 0);
	int bad = stats.done != NJOBS || stats.bytes != want_bytes;
	printf("done=%ld/%d bytes=%ld/%ld %s\n", stats.done, NJOBS, stats.bytes, want_bytes, bad ? "LOST-UPDATE" : "ok");
	return bad;
}
