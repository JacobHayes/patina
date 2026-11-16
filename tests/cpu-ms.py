"""Run a command and print the CPU time (user + system, ms) it and every process it reaped used.

For scripts that bound how long Patina computes: unlike wall time, CPU time does not grow
when other work on the host delays the run. The command's own exit status is not checked.
Usage: python3 -I tests/cpu-ms.py CMD [ARGS...]
"""

import resource
import subprocess
import sys

subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
r = resource.getrusage(resource.RUSAGE_CHILDREN)
print(round((r.ru_utime + r.ru_stime) * 1000))
