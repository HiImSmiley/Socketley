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

// One exchange, owned by the completions that are owed to it and by the runtime's handle, the last of which closes its
// socket.
struct call final : fcgi_stream, std::enable_shared_from_this<call>
{
    file_io& io;
    int fd{-1};
    std::string out;
    std::string raw;
    std::string answer;
    std::string err;
    std::unique_ptr<char[]> buf{new char[read_chunk]};
    std::weak_ptr<bool> alive;
    fcgi_sink sink;
    bool ended{false};
    bool timed_out{false};
    bool finished{false};
    // The head went to the runtime and the body goes in pieces; a read waits for resume() while `paused`.
    bool streaming{false};
    bool paused{false};
    bool reading{false};

    explicit call(file_io& i) : io(i) {}
    ~call() override
    {
        if (fd >= 0)
            ::close(fd);
    }

    bool listening() const { return !finished && !alive.expired(); }

    void resume() override
    {
        if (!paused || finished)
            return;
        paused = false;
        if (!reading)
            read();
    }

    void cancel() override
    {
        if (finished)
            return;
        finished = true;
        sink = {};
        // The read under way comes back, and its completion lets the socket go.
        ::shutdown(fd, SHUT_RDWR);
    }

    void failed(int status, const char* why)
    {
        if (finished)
            return;
        LOG_WARN((std::string("web: the FastCGI server ") + why +
                  (streaming ? "; the answer under way is cut short" : "; the request is answered " +
                                                                           std::to_string(status))).c_str());
        finished = true;
        if (alive.expired())
            return;
        if (streaming)
        {
            if (sink.end)
                sink.end(false);
            return;
        }
        fcgi_answer a;
        a.status = status;
        a.body = status == 504 ? "Gateway Timeout\n" : "Bad Gateway\n";
        if (sink.head)
            sink.head(std::move(a), true);
    }

    void fail(const char* why)
    {
        failed(timed_out ? 504 : 502, timed_out ? "did not answer in time" : why);
    }

    // The head and what came of the body handed over, whole when the answer ended; false for a head that is not one.
    bool give_head(bool whole)
    {
        fcgi::cgi_head h;
        size_t len = 0;
        const fcgi::head_result hr = fcgi::parse_cgi_head(answer, len, h);
        if (hr == fcgi::head_result::need_more && !whole)
            return true;
        if (hr != fcgi::head_result::done)
        {
            fail("answered with a CGI head that is not one");
            return false;
        }
        if (!h.accel_redirect.empty())
        {
            fail("named a file by X-Accel-Redirect, which is nginx's");
            return false;
        }
        // An answer that is not whole goes when its body outgrows what is held of one.
        if (!whole && answer.size() - len <= fcgi_whole_max)
            return true;
        fcgi_answer a;
        a.status = h.status;
        a.fields = std::move(h.fields);
        a.body = answer.substr(len);
        answer.clear();
        answer.shrink_to_fit();
        streaming = !whole;
        if (whole)
            finished = true;
        if (listening() || whole)
            if (!alive.expired() && sink.head)
                sink.head(std::move(a), whole);
        return true;
    }

    // The records read so far, taken off the front of `raw`; false when they are not FastCGI or the exchange ended.
    bool take_records()
    {
        size_t at = 0;
        bool ok = true;
        while (!ended && listening())
        {
            fcgi::record r;
            size_t used = 0;
            const fcgi::take t = fcgi::next_record(std::string_view(raw).substr(at), r, used);
            if (t == fcgi::take::need_more)
                break;
            if (t == fcgi::take::bad)
            {
                ok = false;
                break;
            }
            at += used;
            switch (r.type)
            {
                case fcgi::record_type::stdout_data:
                    if (streaming)
                    {
                        if (!r.content.empty() && sink.more && !sink.more(r.content))
                            paused = true;
                    }
                    else
                    {
                        answer.append(r.content);
                        if (!give_head(false))
                            return false;
                    }
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
        }
        raw.erase(0, at);
        if (!ok)
            fail("answered with records that are not FastCGI");
        return ok && listening();
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

    void complete()
    {
        log_stderr();
        if (streaming)
        {
            finished = true;
            if (!alive.expired() && sink.end)
                sink.end(true);
            return;
        }
        give_head(true);
    }

    void read()
    {
        auto self = shared_from_this();
        reading = true;
        if (!io.pread(fd, buf.get(), read_chunk, file_io::at_stream, [self](int64_t res) { self->got(res); }))
        {
            reading = false;
            fail("could not be read from");
        }
    }

    void got(int64_t res)
    {
        reading = false;
        if (finished)
            return;
        if (res < 0)
            return fail("broke the connection");
        if (res == 0)
            return ended ? complete() : fail("closed the connection before its answer was whole");
        raw.append(buf.get(), static_cast<size_t>(res));
        if (!take_records())
            return;
        if (ended)
            return complete();
        if (!paused)
            read();
    }
};

}   // namespace

std::shared_ptr<fcgi_stream> fcgi_exchange(file_io& io, const fcgi_target& target, std::string request,
                                           uint32_t timeout_ms, std::weak_ptr<bool> alive, fcgi_sink sink)
{
    const int fd = ::socket(target.unix_socket ? AF_UNIX : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return nullptr;
    auto c = std::make_shared<call>(io);
    c->fd = fd;
    c->out = std::move(request);
    c->alive = std::move(alive);
    c->sink = std::move(sink);
    const auto* addr = target.unix_socket ? reinterpret_cast<const struct sockaddr*>(&target.un)
                                          : reinterpret_cast<const struct sockaddr*>(&target.in);
    const bool started = io.connect(fd, addr, target.len, [c](int64_t res) {
        if (c->finished)
            return;
        if (res < 0)
            return c->fail("could not be reached");
        if (!c->io.pwrite(c->fd, c->out.data(), static_cast<uint32_t>(c->out.size()), file_io::at_stream,
                          [c](int64_t w) {
                              if (c->finished)
                                  return;
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
        c->sink = {};
        return nullptr;
    }
    // A server that has not answered with a head by then is ended here: the shutdown makes the read under way come
    // back, and that answers 504; a body already under way is the client's to take at its own pace.
    std::weak_ptr<call> weak = c;
    io.after(std::chrono::milliseconds(timeout_ms), [weak](int64_t) {
        if (const auto cc = weak.lock(); cc && !cc->finished && !cc->streaming)
        {
            cc->timed_out = true;
            ::shutdown(cc->fd, SHUT_RDWR);
        }
    });
    return c;
}

}   // namespace socketley::web
