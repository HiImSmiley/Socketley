#include "mail_content.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>

#include "mail_mime.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail
{

namespace
{

bool listed(std::string_view list, std::string_view ext)
{
    if (list == "default")
        list = default_refused_attachments;
    for (std::string_view rest = list; !rest.empty();)
    {
        const size_t comma = rest.find(',');
        std::string_view one = rest.substr(0, comma);
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
        while (!one.empty() && (one.front() == ' ' || one.front() == '.'))
            one.remove_prefix(1);
        if (!one.empty() && socketley::ascii::iequals(one, ext))
            return true;
    }
    return false;
}

std::string first_refused(std::string_view msg, const mime::part& p, std::string_view list, int depth)
{
    if (depth > 32)
        return {};
    for (const auto& c : p.children)
        if (std::string n = first_refused(msg, c, list, depth + 1); !n.empty())
            return n;
    std::string name = mime::param(p.disposition_params, "filename");
    if (name.empty())
        name = mime::param(p.params, "name");
    name = mime::decode_words(name);
    const size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 == name.size())
        return {};
    return listed(list, std::string_view(name).substr(dot + 1)) ? name : std::string();
}

// A connection to clamd, its timeout on every read and write; -1 with why where it cannot be made.
int clamd_connect(const std::string& where, int timeout_s, std::string& why)
{
    int fd = -1;
    if (where.starts_with("/"))
    {
        sockaddr_un un{};
        un.sun_family = AF_UNIX;
        if (where.size() >= sizeof un.sun_path)
        {
            why = "the socket's path is too long";
            return -1;
        }
        std::memcpy(un.sun_path, where.c_str(), where.size() + 1);
        fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && ::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof un) != 0)
        {
            why = std::string("it cannot be reached: ") + std::strerror(errno);
            ::close(fd);
            return -1;
        }
    }
    else
    {
        const size_t colon = where.rfind(':');
        addrinfo hints{}, *res = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (::getaddrinfo(where.substr(0, colon).c_str(), where.substr(colon + 1).c_str(), &hints, &res) != 0 || !res)
        {
            why = "its address does not resolve";
            return -1;
        }
        fd = ::socket(res->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && ::connect(fd, res->ai_addr, res->ai_addrlen) != 0)
        {
            why = std::string("it cannot be reached: ") + std::strerror(errno);
            ::close(fd);
            fd = -1;
        }
        ::freeaddrinfo(res);
        if (fd < 0)
            return -1;
    }
    timeval tv{timeout_s, 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) {}
    return fd;
}

bool send_all(int fd, const void* p, size_t n)
{
    const auto* b = static_cast<const char*>(p);
    while (n)
    {
        const ssize_t w = ::send(fd, b, n, MSG_NOSIGNAL);
        if (w <= 0)
            return false;
        b += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

}   // namespace

std::string refused_attachment(std::string_view msg, std::string_view list)
{
    if (list.empty() || list == "none")
        return {};
    return first_refused(msg, mime::parse(msg), list, 0);
}

virus_verdict clamav_scan(const std::string& where, std::string_view msg, int timeout_s)
{
    virus_verdict v;
    const int fd = clamd_connect(where, timeout_s, v.why);
    if (fd < 0)
        return v;
    // zINSTREAM, then chunks each after its length in four bytes in network order, then a length of 0.
    bool sent = send_all(fd, "zINSTREAM", 10);
    for (size_t at = 0; sent && at < msg.size(); at += 65536)
    {
        const std::string_view chunk = msg.substr(at, 65536);
        const uint32_t len = htonl(static_cast<uint32_t>(chunk.size()));
        sent = send_all(fd, &len, 4) && send_all(fd, chunk.data(), chunk.size());
    }
    const uint32_t end = 0;
    sent = sent && send_all(fd, &end, 4);
    std::string reply;
    char buf[512];
    while (sent && reply.size() < 4096)
    {
        const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n <= 0)
            break;
        reply.append(buf, static_cast<size_t>(n));
        if (reply.find('\0') != std::string::npos)
            break;
    }
    ::close(fd);
    if (const size_t z = reply.find('\0'); z != std::string::npos)
        reply.resize(z);
    // "stream: OK", "stream: <name> FOUND", or "<what> ERROR".
    if (!sent || reply.empty())
    {
        v.why = "it did not answer";
        return v;
    }
    if (reply.ends_with(" FOUND"))
    {
        v.scanned = true;
        const size_t colon = reply.find(": ");
        v.found = reply.substr(colon == std::string::npos ? 0 : colon + 2, reply.size() - 6 - (colon == std::string::npos ? 0 : colon + 2));
        return v;
    }
    if (reply.ends_with(" OK"))
    {
        v.scanned = true;
        return v;
    }
    v.why = "it said " + reply;
    return v;
}

}   // namespace socketley::mail
