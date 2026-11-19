"""Run a command and print the largest resident set (MiB) of it and every process it reaped.

For scripts that bound memory: the kernel's high-water mark of each process, carried to the
parent as it is reaped, so it does not depend on when anyone looks. The command's own exit
status is not checked.
Usage: python3 -I tests/maxrss-mb.py CMD [ARGS...]
"""

import resource
import subprocess
import sys

subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024)
