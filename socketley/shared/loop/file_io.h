#pragma once
// Disk operations on a runtime's own ring, each with a completion callback, so
// a runtime that serves files never blocks its loop on the disk.
#include <cstdint>
#include <chrono>
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
    bool linkat(int olddirfd, std::string oldpath, int newdirfd, std::string newpath, done cb);
    bool fsync(int fd, bool datasync, done cb);
    // The same for a sync that only makes an answered write survive a crash of the machine, which a runtime that
    // traded that away makes a no-op with set_relaxed(); a crash of the process loses nothing either way.
    bool sync(int fd, bool datasync, done cb);
    void set_relaxed(bool relaxed) { m_relaxed = relaxed; }
    bool relaxed() const { return m_relaxed; }
    // The syncs that ran and succeeded, and those set_relaxed() skipped.
    uint64_t syncs() const { return m_syncs; }
    uint64_t skipped_syncs() const { return m_skipped; }

    // One read, short at the end of the file, and the whole of the range or an
    // error for the write, which is continued across a short count.
    bool pread(int fd, char* buf, uint32_t len, uint64_t off, done cb);
    bool pwrite(int fd, const char* buf, uint32_t len, uint64_t off, done cb);

    // The offset of a descriptor with no position of its own, a socket's, which a continued write keeps.
    static constexpr uint64_t at_stream = UINT64_MAX;

    // A socket's connect, the address copied so the caller need not keep it.
    bool connect(int fd, const struct sockaddr* addr, socklen_t len, done cb);

    // Moves up to `len` bytes from a file at `off` into a pipe, or from a pipe into a socket when `off` is at_stream,
    // without their passing through this process.
    bool splice(int fd_in, uint64_t off, int fd_out, uint32_t len, done cb);

    // `cb` with the events once `fd` is ready for those in `mask` (POLLOUT, POLLIN), or with a negative errno.
    bool poll(int fd, unsigned mask, done cb);

    // `cb` once `wait` has passed, with 0.
    bool after(std::chrono::nanoseconds wait, done cb);

    // Whether a completion of this kind is one of this object's.
    static bool owns_type(uint8_t type)
    {
        return type == op_file_read || type == op_file_write || type == op_fsync ||
               type == op_rename || type == op_unlink || type == op_openat ||
               type == op_mkdir || type == op_link || type == op_connect || type == op_io_splice ||
               type == op_file_timer || type == op_file_poll;
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
    bool                m_relaxed{false};
    uint64_t            m_syncs{0};
    uint64_t            m_skipped{0};
};

}   // namespace socketley
