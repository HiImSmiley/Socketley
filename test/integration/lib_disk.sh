# A directory where what is written counts as written, for a test that counts a process's writes: the test's own where
# it is on a disk, and one under /var/tmp where it is on tmpfs, which disk_dir_done removes.
disk_dir() {   # dir -> a directory on a filesystem that counts writes
    if python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from lib_disk import counts_writes; sys.exit(not counts_writes(sys.argv[2]))' \
           "$(dirname "${BASH_SOURCE[0]}")" "$1"; then
        echo "$1"
    else
        mktemp -d /var/tmp/socketley-disk.XXXXXX 2>/dev/null || echo "$1"
    fi
}

disk_dir_done() {   # dir
    case "$1" in /var/tmp/socketley-disk.*) rm -rf "$1" ;; esac
}
