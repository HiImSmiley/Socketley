#pragma once
// The worker's end of a shell's send link (send_link.h).
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

#include "../loop/event_loop.h"
#include "../loop/event_loop_definitions.h"
#include "send_link.h"

namespace socketley::send_link
{

// The worker's end of one link: a standing recv, the line handed to `deliver`, its answer written back at once.
class server : public io_handler
{
public:
    using deliver_fn = std::function<uint8_t(std::string_view)>;

    server(int fd, deliver_fn fn) : m_fd(fd), m_fn(std::move(fn)), m_buf(new char[max_message + 1]) {}

    ~server() override
    {
        if (m_fd >= 0 && !m_loop)
            ::close(m_fd);
    }

    server(const server&)            = delete;
    server& operator=(const server&) = delete;

    bool attach(event_loop& loop)
    {
        m_loop = &loop;
        loop.register_owner(this);
        if (!arm())
        {
            end();
            return false;
        }
        return true;
    }

    // Ended: deregistered and its descriptor given to the loop, so it may be freed once the loop has drained it.
    bool ended() const { return m_fd < 0; }

    // At the worker's end: a later line fails at the shell's send (EPIPE) and a queued one is answered not_taken, so
    // the shell asks the daemon rather than read the close as a line lost after it was taken.
    void refuse_rest()
    {
        if (m_fd < 0)
            return;
        if (::shutdown(m_fd, SHUT_RD) < 0) {}
        for (;;)
        {
            const ssize_t n = ::recv(m_fd, m_buf.get(), max_message + 1, MSG_DONTWAIT);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            const uint8_t st = not_taken;
            if (::send(m_fd, &st, 1, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {}
        }
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        if (static_cast<io_request*>(io_uring_cqe_get_data(cqe)) != &m_req || m_fd < 0)
            return;
        const int res = cqe->res;
        if (res == -EINTR || res == -EAGAIN)
        {
            if (!arm())
                end();
            return;
        }
        // The shell closed its end or the socket failed; nothing is owed an answer.
        if (res <= 0)
        {
            end();
            return;
        }

        // A message that filled the buffer was cut by the kernel, so none of it is delivered.
        const uint8_t st = static_cast<size_t>(res) > max_message
                               ? not_taken
                               : m_fn(std::string_view(m_buf.get(), static_cast<size_t>(res)));
        ssize_t n;
        do
            n = ::send(m_fd, &st, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        while (n < 0 && errno == EINTR);
        // A shell that does not read its answers has no claim on another line.
        if (n != 1 || !arm())
            end();
    }

private:
    bool arm()
    {
        m_req = {this, m_buf.get(), m_fd, static_cast<uint32_t>(max_message + 1), op_read};
        return m_loop->submit_read(m_fd, m_buf.get(), static_cast<uint32_t>(max_message + 1), &m_req);
    }

    void end()
    {
        m_loop->deregister_owner(this);
        m_loop->close_fd(m_fd);
        m_fd = -1;
    }

    int                     m_fd{-1};
    deliver_fn              m_fn;
    std::unique_ptr<char[]> m_buf;
    event_loop*             m_loop{nullptr};
    io_request              m_req{};
};

}   // namespace socketley::send_link
