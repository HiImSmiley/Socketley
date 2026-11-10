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

// The scripts' answers bigger than this are a 502, since an answer is held whole to be sent with its length.
inline constexpr size_t fcgi_answer_max = 64u << 20;

using fcgi_done = std::function<void(fcgi_answer)>;

// Sends `request`, already FastCGI records, and calls `done` exactly once, never from inside this call, unless
// `alive` has expired first; false when nothing could be started, and then `done` is never called.
bool fcgi_exchange(file_io& io, const fcgi_target& target, std::string request, uint32_t timeout_ms,
                   std::weak_ptr<bool> alive, fcgi_done done);

}   // namespace socketley::web
