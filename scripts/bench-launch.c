/* bench-launch: run one command and report its wall time and resource usage.
 *
 * usage: bench-launch REPORT_PATH COMMAND [ARGS...]
 *
 * scripts/bench.py measures every run through this launcher rather than
 * spawning the command itself. The kernel folds the pre-exec address space's
 * high-water mark into a process's peak RSS, so a command spawned straight from
 * the Python interpreter reports at least the interpreter's own footprint. This
 * process is small, and the command is forked from it.
 *
 * The report is one line: wall_ns, user and system CPU (microseconds) and the
 * raw ru_maxrss (KiB on Linux, bytes on macOS). wait4's usage includes the
 * command's own waited-for children, such as the Patina guest the CLI spawns.
 * Exit status: the command's, 128+N for a death by signal N, or
 * 125 when the launcher itself fails. */
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long nanos(const struct timespec *t) {
  return (long long)t->tv_sec * 1000000000LL + t->tv_nsec;
}

static long long micros(const struct timeval *t) {
  return (long long)t->tv_sec * 1000000LL + t->tv_usec;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: bench-launch REPORT_PATH COMMAND [ARGS...]\n");
    return 125;
  }
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  pid_t pid = fork();
  if (pid < 0) {
    perror("bench-launch: fork");
    return 125;
  }
  if (pid == 0) {
    execvp(argv[2], argv + 2);
    perror("bench-launch: exec");
    _exit(127);
  }
  int status;
  struct rusage usage;
  if (wait4(pid, &status, 0, &usage) < 0) {
    perror("bench-launch: wait4");
    return 125;
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  FILE *report = fopen(argv[1], "w");
  if (report == NULL) {
    perror("bench-launch: open report");
    return 125;
  }
  fprintf(report, "wall_ns=%lld utime_us=%lld stime_us=%lld maxrss=%ld\n",
          nanos(&end) - nanos(&start), micros(&usage.ru_utime), micros(&usage.ru_stime),
          (long)usage.ru_maxrss);
  if (fclose(report) != 0) {
    perror("bench-launch: write report");
    return 125;
  }
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return WEXITSTATUS(status);
}
