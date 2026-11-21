# Append fsynced 4 KiB records to /work/log until the disk is full; at a later boot, first
# count the whole records the disk kept. Prints `kept N` (later boots) and `full after N`.
import errno, os, sys, time
REC = 4096
path = "/work/log"
if os.path.exists(path):
    n = os.path.getsize(path) // REC
    print("kept", n, flush=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
n = 0
while True:
    try:
        b = bytes([n % 251]) * REC
        w = os.write(fd, b)
        os.fsync(fd)
        if w < REC:
            raise OSError(errno.ENOSPC, "short")
        n += 1
    except OSError as e:
        if e.errno != errno.ENOSPC:
            raise
        break
print("full after", n, flush=True)
if len(sys.argv) > 1:
    time.sleep(float(sys.argv[1]))
