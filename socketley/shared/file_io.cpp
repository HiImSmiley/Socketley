#include "file_io.h"

#include <cerrno>
#include <utility>

namespace socketley
{

struct file_io::op
{
    // Its `buffer` field carries this op, which is how a completion finds it
    // again -- the loop never reads that field.
    io_request req{};
    op_type    kind{op_nop};
    done       cb;

    int         fd{-1};
    int         fd2{-1};
    std::string path;
    std::string path2;
    int         flags{0};
    mode_t      mode{0};
    bool        datasync{false};

    char*       rbuf{nullptr};
    const char* wbuf{nullptr};
    uint32_t    len{0};
    uint64_t    off{0};
    // What a write has put on disk so far, because a short write continues.
    uint32_t    written{0};
};

file_io::file_io(event_loop& loop, io_handler* owner) : m_loop(&loop), m_owner(owner)
{
    m_loop->register_owner(owner);
}

file_io::~file_io()
{
    for (op* o : m_live)
        delete o;
}

bool file_io::submit(op* o)
{
    o->req        = io_request{};
    o->req.owner  = m_owner;
    o->req.type   = o->kind;
    o->req.buffer = reinterpret_cast<char*>(o);

    bool queued = false;
    switch (o->kind)
    {
        case op_openat:
            queued = m_loop->submit_openat(o->fd, o->path.c_str(), o->flags, o->mode, &o->req);
            break;
        case op_mkdir:
            queued = m_loop->submit_mkdirat(o->fd, o->path.c_str(), o->mode, &o->req);
            break;
        case op_unlink:
            queued = m_loop->submit_unlinkat(o->fd, o->path.c_str(), &o->req, o->flags);
            break;
        case op_rename:
            queued = m_loop->submit_renameat(o->fd, o->path.c_str(), o->fd2, o->path2.c_str(),
                                             &o->req, false);
            break;
        case op_fsync:
            queued = m_loop->submit_fsync(o->fd, o->datasync, &o->req, false);
            break;
        case op_file_read:
            queued = m_loop->submit_file_read(o->fd, o->rbuf, o->len, o->off, &o->req);
            break;
        case op_file_write:
            queued = m_loop->submit_file_write(o->fd, o->wbuf + o->written, o->len - o->written,
                                               o->off + o->written, &o->req, false);
            break;
        default:
            break;
    }
    return queued;
}

bool file_io::openat(int dirfd, std::string path, int flags, mode_t mode, done cb)
{
    auto* o = new op;
    o->kind = op_openat;
    o->fd = dirfd;
    o->path = std::move(path);
    o->flags = flags;
    o->mode = mode;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::mkdirat(int dirfd, std::string path, mode_t mode, done cb)
{
    auto* o = new op;
    o->kind = op_mkdir;
    o->fd = dirfd;
    o->path = std::move(path);
    o->mode = mode;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::unlinkat(int dirfd, std::string path, int flags, done cb)
{
    auto* o = new op;
    o->kind = op_unlink;
    o->fd = dirfd;
    o->path = std::move(path);
    o->flags = flags;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::renameat(int olddirfd, std::string oldpath, int newdirfd, std::string newpath, done cb)
{
    auto* o = new op;
    o->kind = op_rename;
    o->fd = olddirfd;
    o->fd2 = newdirfd;
    o->path = std::move(oldpath);
    o->path2 = std::move(newpath);
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::fsync(int fd, bool datasync, done cb)
{
    auto* o = new op;
    o->kind = op_fsync;
    o->fd = fd;
    o->datasync = datasync;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::pread(int fd, char* buf, uint32_t len, uint64_t off, done cb)
{
    auto* o = new op;
    o->kind = op_file_read;
    o->fd = fd;
    o->rbuf = buf;
    o->len = len;
    o->off = off;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

bool file_io::pwrite(int fd, const char* buf, uint32_t len, uint64_t off, done cb)
{
    auto* o = new op;
    o->kind = op_file_write;
    o->fd = fd;
    o->wbuf = buf;
    o->len = len;
    o->off = off;
    o->cb = std::move(cb);
    if (!submit(o))
    {
        delete o;
        return false;
    }
    m_live.insert(o);
    return true;
}

void file_io::finish(op* o, int64_t res)
{
    // Out of the set and freed before the callback, because the callback is
    // free to queue the next step of its chain.
    done cb = std::move(o->cb);
    m_live.erase(o);
    delete o;
    if (cb)
        cb(res);
}

void file_io::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    auto* o = reinterpret_cast<op*>(req->buffer);
    if (!m_live.contains(o))
        return;

    const int64_t res = cqe->res;
    if (o->kind == op_file_write && res >= 0)
    {
        // A write that took less than it was given continues where it stopped,
        // and one that took nothing is a device that will not, not a reason to
        // spin.
        o->written += static_cast<uint32_t>(res);
        if (o->written < o->len)
        {
            if (res == 0 || !submit(o))
            {
                finish(o, res == 0 ? -EIO : -ENOBUFS);
                return;
            }
            return;
        }
        finish(o, static_cast<int64_t>(o->len));
        return;
    }
    finish(o, res);
}

}   // namespace socketley
