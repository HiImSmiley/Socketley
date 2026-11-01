#pragma once
// Sending a file to a plain TCP socket from the event loop, as nginx does: sendfile(2) on the loop thread, where an
// io_uring splice is a hand-off to an io-wq worker per operation (event_loop.h, at submit_splice).  The decisions and
// the syscalls only; each runtime keeps its own write queue and its own wait for room on the socket.
//
// The socket stays blocking for the ring's own writes, which would answer -EAGAIN on an O_NONBLOCK one, and is
// non-blocking for the sendfile call alone -- safe because nothing of the ring runs on it meanwhile: the ring is
// SINGLE_ISSUER with DEFER_TASKRUN, so its work happens on this thread, between calls like this one.
#include <cstdint>
#include <string_view>

#include <sys/types.h>

namespace socketley::file_send
{

// At most this much one call sends before the loop turns, and the send buffer a connection sending a file this
// large asks for (the kernel doubles it, to tcp_wmem's 4 MiB here, as far as nginx's autotuned sockets grow).
inline constexpr uint64_t burst_max = 4u << 20;
inline constexpr int send_buffer = 2 << 20;
// From this size a file is worth a raised send buffer; below it one burst is a single short sendfile anyway.
inline constexpr uint64_t large = 256u << 10;

// Whether the burst [off, off + min(left, burst_max)) ends out of the page cache, where sendfile would hold the loop on
// the disk; the caller then reads that window through the ring, which also has the kernel read ahead.  tmpfs, which
// cannot be asked (EOPNOTSUPP), is always in memory and counts as warm.
bool cold(int file_fd, uint64_t off, uint64_t left);

enum class burst
{
    done,    // `left` reached 0
    more,    // the socket is full or the burst ran out: wait for POLLOUT, then call again
    failed,  // the client is gone, or the file shrank under a length already promised: end the connection
};

// One burst of sendfile from `file_fd` at `off` to `sock`, advancing `off` and `left` and adding to `sent`.
// `sock_flags` is the socket's F_GETFL, read here on first use (-1) and kept by the caller for the connection.
burst send(int sock, int& sock_flags, int file_fd, uint64_t& off, uint64_t& left, uint64_t& sent);

// The head of a file answer sent at once, held for the file's first bytes (MSG_MORE) so they travel together: the
// bytes the socket took, which may be fewer, or -1 when the client is gone.  Only when nothing else is queued.
ssize_t send_head(int sock, std::string_view head);

// The send buffer raised for a connection about to send a large file, which the caller does once per connection.
void raise_send_buffer(int sock);

}   // namespace socketley::file_send
