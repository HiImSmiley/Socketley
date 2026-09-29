#pragma once
// Disk operations on a runtime's own ring, each with a completion callback, so
// a runtime that serves files never blocks its loop on the disk.
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>

#include <sys/types.h>

#include "event_loop.h"

namespace socketley
{

class file_io
{
public:
    // The completion's result as the kernel reported it: a byte count, a
    // descriptor or zero on success, and a negative errno otherwise.
    using done = std::function<void(int64_t res)>;

    // `owner` is the io_handler whose on_cqe() forwards every completion of the
    // types owns() recognises back here, so one registration serves a runtime's
    // sockets and its files.
    file_io(event_loop& loop, io_handler* owner);

    // The caller frees this only once the loop owes its owner nothing, because
    // an operation in flight names memory this object holds.
    ~file_io();

    file_io(const file_io&)            = delete;
    file_io& operator=(const file_io&) = delete;

    // False from every call below means nothing was queued and `cb` will never
    // run, which a caller answers as its own failure.
    bool openat(int dirfd, std::string path, int flags, mode_t mode, done cb);
    bool mkdirat(int dirfd, std::string path, mode_t mode, done cb);
    bool unlinkat(int dirfd, std::string path, int flags, done cb);
    bool renameat(int olddirfd, std::string oldpath, int newdirfd, std::string newpath, done cb);
    bool fsync(int fd, bool datasync, done cb);

    // One read, short at the end of the file, and the whole of the range or an
    // error for the write, which is continued across a short count.
    bool pread(int fd, char* buf, uint32_t len, uint64_t off, done cb);
    bool pwrite(int fd, const char* buf, uint32_t len, uint64_t off, done cb);

    // Whether a completion of this kind is one of this object's.
    static bool owns_type(uint8_t type)
    {
        return type == op_file_read || type == op_file_write || type == op_fsync ||
               type == op_rename || type == op_unlink || type == op_openat ||
               type == op_mkdir;
    }

    // Runs the callback of the operation `cqe` completes.
    void on_cqe(struct io_uring_cqe* cqe);

    size_t inflight() const { return m_live.size(); }

private:
    struct op;
    bool submit(op* o);
    void finish(op* o, int64_t res);

    event_loop*         m_loop;
    io_handler*         m_owner;
    std::unordered_set<op*> m_live;
};

}   // namespace socketley
