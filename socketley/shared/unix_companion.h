#pragma once
// A second way in to a runtime that already has a port: the same runtime, on a
// node beside it, for callers that are already on this box.
//
// Its own object rather than a second entry in the accept chain that owns the
// port, because it hands over a descriptor and nothing else -- it has no
// completion of that chain's to resubmit, and folding it in would put two
// lifetimes into a function whose comments are already about one.
//
// What it is NOT: a replacement for the port.  Nothing outside this machine
// can reach a node, so a runtime that drops its port to gain one has stopped
// being reachable, which is why this is only ever additional.
#include <sys/socket.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <utility>

#include "event_loop.h"
#include "event_loop_definitions.h"
#include "logging.h"
#include "unix_listener.h"

namespace socketley
{

class unix_companion : public io_handler
{
public:
    // True means the descriptor became a connection; false means the callee
    // dealt with it and it is gone.  The same contract the port's own accept
    // path answers, because it is the same function on the other side.
    using adopt_fn = std::function<bool(int fd)>;

    unix_companion(std::string path, adopt_fn adopt)
        : m_path(std::move(path)), m_adopt(std::move(adopt)) {}

    ~unix_companion() override { close_node(); }

    unix_companion(const unix_companion&)            = delete;
    unix_companion& operator=(const unix_companion&) = delete;

    const std::string& path() const { return m_path; }
    bool listening() const { return m_fd >= 0; }

    // False is not a failure to start the runtime: the port is up either way,
    // and a runtime reachable one way instead of two is still reachable.
    bool start(event_loop& loop)
    {
        if (m_fd >= 0)
            return true;

        // The directory is the daemon's to make and to vouch for: it decided
        // this path was worth publishing, and a worker that made the directory
        // itself would be binding into one nobody had checked.  Asked again
        // here only because being handed a path is not evidence about it.
        if (!unix_sock::secure_node_dir(unix_sock::node_dir_of(m_path)))
        {
            LOG_WARN(("companion node: " + unix_sock::node_dir_of(m_path)
                      + " is not a directory this process owns with nothing but "
                        "owner access; this runtime is reached on its port only")
                     .c_str());
            return false;
        }

        auto r = unix_sock::bind_listener(m_path, "companion node");
        if (r.fd < 0)
        {
            LOG_WARN((r.error + "; this runtime is reached on its port only").c_str());
            return false;
        }

        m_fd   = r.fd;
        m_loop = &loop;
        loop.register_owner(this);
        arm();
        return true;
    }

    // Disarmed by closing the descriptor, which is how a recv and an accept
    // are withdrawn, and unlinked because the node is this object's file.
    void stop()
    {
        close_node();
    }

    // A submission the ring refused is not a dead listener, so the loop's turn
    // tries again rather than leaving the node deaf.
    void pump()
    {
        if (!m_armed)
            arm();
    }

    bool needs_wake() const { return m_fd >= 0 && !m_armed; }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req != &m_req)
            return;

        // Multishot stays armed unless the kernel says otherwise; a one-shot
        // never does.
        m_armed = m_multishot && (cqe->flags & IORING_CQE_F_MORE) != 0;

        const int fd = cqe->res;

        // The listener is going away and this is its last completion.
        if (fd == -ECANCELED || fd == -EBADF || fd == -EINVAL || fd == -ENOTSOCK)
        {
            m_armed = false;
            return;
        }

        if (fd >= 0)
        {
            if (m_adopt && !m_adopt(fd))
            {
                // Dealt with by the callee, which closed it; nothing here owns
                // it any more.
            }
        }
        else if (fd == -EMFILE || fd == -ENFILE)
        {
            // Deliberately not re-armed on this turn: the descriptor table is
            // full, and arming again inside the completion is a spin.  pump()
            // retries on the next turn, which is one attempt per turn rather
            // than one per completion.
            return;
        }

        arm();
    }

private:
    void arm()
    {
        if (m_fd < 0 || m_armed || !m_loop || !m_loop->ring_open())
            return;

        m_multishot = event_loop::supports_multishot_accept();
        if (m_multishot)
        {
            m_req   = { this, nullptr, m_fd, 0, op_multishot_accept };
            m_armed = m_loop->submit_multishot_accept(m_fd, &m_req);
        }
        else
        {
            m_addrlen = sizeof(m_addr);
            m_req     = { this, nullptr, m_fd, 0, op_accept };
            m_armed   = m_loop->submit_accept(m_fd, &m_addr, &m_addrlen, &m_req);
        }
    }

    void close_node()
    {
        // Only a node this object bound is its file to remove: a stopped one's
        // destructor runs when its process exits, which can be after the next
        // worker of the same runtime has bound the same path.
        if (m_fd < 0)
            return;
        ::shutdown(m_fd, SHUT_RDWR);
        if (m_loop)
            m_loop->close_fd(m_fd);
        else
            ::close(m_fd);
        m_fd    = -1;
        m_armed = false;

        // Closing a descriptor does not remove the file, and a node left
        // behind is what the next start has to decide whether to take over.
        if (!m_path.empty())
            if (::unlink(m_path.c_str()) < 0) {}
    }

    std::string m_path;
    adopt_fn    m_adopt;

    int         m_fd{-1};
    event_loop* m_loop{nullptr};
    io_request  m_req{};
    bool        m_armed{false};
    bool        m_multishot{false};

    struct sockaddr_in m_addr{};
    socklen_t          m_addrlen{sizeof(struct sockaddr_in)};
};

}   // namespace socketley
