"""Whether a directory's filesystem counts what is written to it as written: tmpfs and ramfs keep it in memory, so
/proc/<pid>/io's write_bytes stays 0 there however much a process writes."""
import os


def counts_writes(path):
    path = os.path.realpath(path)
    best, kind = "", ""
    with open("/proc/self/mounts") as f:
        for line in f:
            dev, mnt, fs = line.split()[:3]
            mnt = mnt.replace("\\040", " ")
            if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                best, kind = mnt, fs
    return kind not in ("tmpfs", "ramfs")
