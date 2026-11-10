#pragma once
// A web runtime's PHP: one request handed to an application server such as php-fpm over FastCGI, on a connection of
// its own that the server closes once it has answered, so a php-fpm worker is free the moment its script is done.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <sys/un.h>

#include "../../shared/loop/file_io.h"

namespace socketley::web
{

// Where the application server listens: fastcgi://unix:/path or fastcgi://a.b.c.d:port.
struct fcgi_target
{
    bool unix_socket{false};
    struct sockaddr_un un{};
    struct sockaddr_in in{};
    socklen_t len{0};
};

// False with `why` for a value that names neither.
bool parse_fcgi_target(std::string_view url, fcgi_target& out, std::string& why);

// What the application server answered, or a 502 or 504 for an answer that did not come whole.
struct fcgi_answer
{
    int status{502};
    std::vector<std::pair<std::string, std::string>> fields;
    std::string body;
};

// An answer whose body ends within this much is handed over whole, to be sent with its length; a longer one in pieces.
inline constexpr size_t fcgi_whole_max = 64u << 10;

// What an exchange tells its runtime as the answer comes, always from the loop and never inside fcgi_exchange().
struct fcgi_sink
{
    // The status, the fields and the body or the first of it; `whole` when that is all of it, always so for a 502 or
    // a 504.
    std::function<void(fcgi_answer, bool whole)> head;
    // More of a body that did not come whole; false asks for no more until fcgi_stream::resume().
    std::function<bool(std::string_view)> more;
    // The end of such a body; false when the server failed after its head was handed over.
    std::function<void(bool ok)> end;
};

// An exchange under way, which its runtime asks for more of once its client has taken what it was given, or gives up
// when the client is gone; nothing of the sink is called after cancel().
class fcgi_stream
{
public:
    virtual ~fcgi_stream() = default;
    virtual void resume() = 0;
    virtual void cancel() = 0;
};

// Sends `request`, already FastCGI records, and tells `sink` the answer, until `alive` expires; null when nothing could
// be started, and then the sink is never called. `timeout_ms` bounds the wait for the answer's head.
std::shared_ptr<fcgi_stream> fcgi_exchange(file_io& io, const fcgi_target& target, std::string request,
                                           uint32_t timeout_ms, std::weak_ptr<bool> alive, fcgi_sink sink);

}   // namespace socketley::web
