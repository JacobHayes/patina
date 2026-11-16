# Native-side twin of the supervisor's copy of /in into /work: sorted order, so that
# tmpfs inode numbers follow the same creation order as under patina.
import os, shutil, sys

def copy(src, dst):
    for n in sorted(os.listdir(src), key=os.fsencode):
        s, d = os.path.join(src, n), os.path.join(dst, n)
        st = os.lstat(s)
        if os.path.islink(s):
            os.symlink(os.readlink(s), d)
        elif os.path.isdir(s):
            os.mkdir(d)
            copy(s, d)
            os.chmod(d, st.st_mode & 0o7777)
        elif os.path.isfile(s):
            shutil.copyfile(s, d)
            os.chmod(d, st.st_mode & 0o7777)

# Under patina the copied tree's times read as the virtual file epoch; do the same here.
EPOCH = 1_767_225_600

def stamp(d):
    for n in os.listdir(d):
        p = os.path.join(d, n)
        if os.path.isdir(p) and not os.path.islink(p):
            stamp(p)
        os.utime(p, (EPOCH, EPOCH), follow_symlinks=False)

copy(sys.argv[1], sys.argv[2])
stamp(sys.argv[2])
os.utime(sys.argv[2], (EPOCH, EPOCH))
