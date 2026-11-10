#include "web_fcgi.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <charconv>
#include <cstring>

#include "../../shared/http/fastcgi.h"
#include "../../shared/net/unix_listener.h"
#include "../../shared/util/logging.h"

namespace socketley::web
{

namespace fcgi = socketley::fastcgi;

bool parse_fcgi_target(std::string_view url, fcgi_target& out, std::string& why)
{
    out = {};
    why = "a FastCGI server is fastcgi://unix:/path or fastcgi://a.b.c.d:port";
    if (!url.starts_with("fastcgi://"))
        return false;
    std::string_view where = url.substr(10);
    if (where.starts_with("unix:"))
    {
        where.remove_prefix(5);
        if (where.empty() || where.front() != '/' || where.size() >= sizeof(out.un.sun_path))
            return false;
        out.unix_socket = true;
        out.len = socketley::unix_sock::fill_addr(where, out.un);
        return true;
    }
    const size_t colon = where.rfind(':');
    if (colon == std::string_view::npos)
        return false;
    const std::string host(where.substr(0, colon));
    const std::string_view port_text = where.substr(colon + 1);
    unsigned port = 0;
    const auto r = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (r.ec != std::errc() || r.ptr != port_text.data() + port_text.size() || port == 0 || port > 65535 ||
        inet_pton(AF_INET, host.c_str(), &out.in.sin_addr) != 1)
        return false;
    out.in.sin_family = AF_INET;
    out.in.sin_port = htons(static_cast<uint16_t>(port));
    out.len = sizeof out.in;
    return true;
}

namespace
{

constexpr uint32_t read_chunk = 64 * 1024;

// One exchange, owned by the completions that are owed to it, the last of which closes its socket.
struct call : std::enable_shared_from_this<call>
{
    file_io& io;
    int fd{-1};
    std::string out;
    std::string raw;
    std::string answer;
    std::string err;
    std::unique_ptr<char[]> buf{new char[read_chunk]};
    std::weak_ptr<bool> alive;
    fcgi_done done;
    bool ended{false};
    bool timed_out{false};
    bool finished{false};

    explicit call(file_io& i) : io(i) {}
    ~call()
    {
        if (fd >= 0)
            ::close(fd);
    }

    // `done` told once: the answer, or a 502 or 504 and the reason in the log.
    void finish(int status_if_failed, const char* why)
    {
        if (finished)
            return;
        finished = true;
        fcgi_answer a;
        if (!why)
        {
            fcgi::cgi_head h;
            size_t len = 0;
            if (fcgi::parse_cgi_head(answer, len, h) != fcgi::head_result::done)
                why = "answered with a CGI head that is not one";
            else if (!h.accel_redirect.empty())
                why = "named a file by X-Accel-Redirect, which is nginx's";
            else
            {
                a.status = h.status;
                a.fields = std::move(h.fields);
                a.body = answer.substr(len);
            }
        }
        if (why)
        {
            a = fcgi_answer{};
            a.status = status_if_failed;
            a.body = status_if_failed == 504 ? "Gateway Timeout\n" : "Bad Gateway\n";
            LOG_WARN((std::string("web: the FastCGI server ") + why + "; the request is answered " +
                      std::to_string(status_if_failed)).c_str());
        }
        if (!alive.expired() && done)
            done(std::move(a));
        done = nullptr;
    }

    void fail(const char* why)
    {
        finish(timed_out ? 504 : 502, timed_out ? "did not answer in time" : why);
    }

    // The records read so far, taken off the front of `raw`; false when they are not FastCGI.
    bool take_records()
    {
        size_t at = 0;
        for (;;)
        {
            fcgi::record r;
            size_t used = 0;
            const fcgi::take t = fcgi::next_record(std::string_view(raw).substr(at), r, used);
            if (t == fcgi::take::need_more)
                break;
            if (t == fcgi::take::bad)
                return false;
            at += used;
            switch (r.type)
            {
                case fcgi::record_type::stdout_data:
                    answer.append(r.content);
                    break;
                case fcgi::record_type::stderr_data:
                    err.append(r.content);
                    break;
                case fcgi::record_type::end_request:
                    ended = true;
                    break;
                default:
                    break;
            }
            if (ended)
                break;
        }
        raw.erase(0, at);
        return true;
    }

    void log_stderr()
    {
        if (err.empty())
            return;
        while (!err.empty() && (err.back() == '\n' || err.back() == '\r'))
            err.pop_back();
        LOG_WARN(("web: the FastCGI server said: " + err.substr(0, 4096)).c_str());
        err.clear();
    }

    void read()
    {
        auto self = shared_from_this();
        if (!io.pread(fd, buf.get(), read_chunk, file_io::at_stream, [self](int64_t res) { self->got(res); }))
            fail("could not be read from");
    }

    void got(int64_t res)
    {
        if (res < 0)
            return fail("broke the connection");
        if (res == 0)
        {
            log_stderr();
            return ended ? finish(502, nullptr) : fail("closed the connection before its answer was whole");
        }
        raw.append(buf.get(), static_cast<size_t>(res));
        if (!take_records())
            return fail("answered with records that are not FastCGI");
        if (answer.size() > fcgi_answer_max)
            return fail("answered with more than the 64 MiB an answer is held to");
        if (ended)
        {
            log_stderr();
            return finish(502, nullptr);
        }
        read();
    }
};

}   // namespace

bool fcgi_exchange(file_io& io, const fcgi_target& target, std::string request, uint32_t timeout_ms,
                   std::weak_ptr<bool> alive, fcgi_done done)
{
    const int fd = ::socket(target.unix_socket ? AF_UNIX : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    auto c = std::make_shared<call>(io);
    c->fd = fd;
    c->out = std::move(request);
    c->alive = std::move(alive);
    c->done = std::move(done);
    const auto* addr = target.unix_socket ? reinterpret_cast<const struct sockaddr*>(&target.un)
                                          : reinterpret_cast<const struct sockaddr*>(&target.in);
    const bool started = io.connect(fd, addr, target.len, [c](int64_t res) {
        if (res < 0)
            return c->fail("could not be reached");
        if (!c->io.pwrite(c->fd, c->out.data(), static_cast<uint32_t>(c->out.size()), file_io::at_stream,
                          [c](int64_t w) {
                              if (w < 0)
                                  return c->fail("refused the request");
                              c->out.clear();
                              c->out.shrink_to_fit();
                              c->read();
                          }))
            c->fail("could not be written to");
    });
    if (!started)
    {
        c->done = nullptr;
        return false;
    }
    // A server that never answers is ended here: the shutdown makes the read under way come back, and that answers.
    std::weak_ptr<call> weak = c;
    io.after(std::chrono::milliseconds(timeout_ms), [weak](int64_t) {
        if (const auto cc = weak.lock(); cc && !cc->finished)
        {
            cc->timed_out = true;
            ::shutdown(cc->fd, SHUT_RDWR);
        }
    });
    return true;
}

}   // namespace socketley::web
