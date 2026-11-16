# 6. A python3 -c program: walks /usr/lib/python3*, imports 40 modules, file I/O, os.stat,
#    tempfile, shutil, pathlib, mmap. ok and identical over 3 runs.
#@ tier=area budget=60
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/06-python
verify_ok "$o" 1 "" 3 -- /usr/bin/python3 -c 'exec(open("/guest/pyscript.py").read())'
grep '^walked\|^imported\|^digest' "$o/run-0/inc-0/stdout"
