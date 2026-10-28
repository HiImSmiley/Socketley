#include "mail_srs.h"

#include "../../shared/crypto/mac.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::srs
{

namespace
{

constexpr std::string_view base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr int64_t max_age_days = 21;

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

// Eight base32 characters, 40 bits, of the HMAC over what an address carries lower-cased, kept whole by a relay that
// folds case.
std::string hash_of(std::string_view key, std::string_view what)
{
    const std::string mac = socketley::crypto::hmac_sha1(key, lower(what));
    uint64_t bits = 0;
    for (size_t i = 0; i < 5 && i < mac.size(); ++i)
        bits = bits << 8 | static_cast<uint8_t>(mac[i]);
    std::string out;
    for (int i = 7; i >= 0; --i)
        out += base32[(bits >> (5 * i)) & 31];
    return out;
}

std::string stamp(int64_t day)
{
    const auto t = static_cast<uint32_t>(((day % 1024) + 1024) % 1024);
    return {base32[t >> 5], base32[t & 31]};
}

// Whether the stamp `s` is of a day within the last 21 (the stamp counts days modulo 1024).
bool fresh(std::string_view s, int64_t day)
{
    if (s.size() != 2)
        return false;
    const size_t hi = base32.find(socketley::ascii::upper(s[0])), lo = base32.find(socketley::ascii::upper(s[1]));
    if (hi == std::string_view::npos || lo == std::string_view::npos)
        return false;
    const int64_t then = static_cast<int64_t>(hi << 5 | lo);
    const int64_t age = (((day % 1024) - then) % 1024 + 1024) % 1024;
    return age <= max_age_days;
}

// Whether `h` is the hash of `what` under `key`, in a time that tells nothing of where it differs.
bool hash_ok(std::string_view h, std::string_view key, std::string_view what)
{
    return h.size() == 8 && socketley::crypto::secure_equal(lower(h), lower(hash_of(key, what)));
}

}   // namespace

std::string forward(std::string_view sender, std::string_view domain, std::string_view key, int64_t day)
{
    const size_t at = sender.rfind('@');
    if (sender.empty() || at == std::string_view::npos || at == 0 || key.empty())
        return std::string(sender);
    const std::string_view local = sender.substr(0, at), host = sender.substr(at + 1);
    if (socketley::ascii::iequals(host, domain))
        return std::string(sender);
    const std::string head = lower(local.substr(0, 5));
    // A sender another forwarder rewrote: its first forwarder and what it said are kept, the hash made new (SRS1).
    if (head == "srs0=" || head == "srs1=")
    {
        std::string orighost, rest;
        if (head == "srs0=")
        {
            orighost = std::string(host);
            rest = std::string(local.substr(4));
        }
        else
        {
            const std::string_view tail = local.substr(5);
            const size_t h = tail.find('=');
            const size_t dd = h == std::string_view::npos ? h : tail.find("==", h + 1);
            if (dd == std::string_view::npos)
                return std::string(sender);
            orighost = std::string(tail.substr(h + 1, dd - h - 1));
            rest = std::string(tail.substr(dd + 1));
        }
        // The hash's text ends the host at its first '=', so a host holding one is not vouched for.
        if (orighost.find('=') != std::string::npos)
            return std::string(sender);
        return "SRS1=" + hash_of(key, orighost + rest) + "=" + orighost + "=" + rest + "@" + std::string(domain);
    }
    if (host.find('=') != std::string_view::npos)
        return std::string(sender);
    const std::string t = stamp(day);
    // The parts are hashed with the '=' between them, so the host cannot end elsewhere under the same hash.
    return "SRS0=" + hash_of(key, t + "=" + std::string(host) + "=" + std::string(local)) + "=" + t + "=" +
           std::string(host) + "=" + std::string(local) + "@" + std::string(domain);
}

std::string reverse(std::string_view address, std::string_view domain, std::string_view key, int64_t day)
{
    const size_t at = address.rfind('@');
    if (at == std::string_view::npos || !socketley::ascii::iequals(address.substr(at + 1), domain) || key.empty())
        return {};
    const std::string_view local = address.substr(0, at);
    const std::string head = lower(local.substr(0, 5));
    if (head == "srs0=")
    {
        // SRS0=HHHH=TT=domain=local, the local part after the third '=' whatever it holds.
        const std::string_view tail = local.substr(5);
        const size_t a = tail.find('='), b = a == std::string_view::npos ? a : tail.find('=', a + 1);
        const size_t c = b == std::string_view::npos ? b : tail.find('=', b + 1);
        if (c == std::string_view::npos)
            return {};
        const std::string_view h = tail.substr(0, a), t = tail.substr(a + 1, b - a - 1),
                               host = tail.substr(b + 1, c - b - 1), who = tail.substr(c + 1);
        if (host.empty() || who.empty() || !fresh(t, day) ||
            !hash_ok(h, key, std::string(t) + "=" + std::string(host) + "=" + std::string(who)))
            return {};
        return std::string(who) + "@" + std::string(host);
    }
    if (head == "srs1=")
    {
        // SRS1=HHHH=orighost==rest: back to the forwarder before this one, as SRS0 of its own.
        const std::string_view tail = local.substr(5);
        const size_t a = tail.find('='), dd = a == std::string_view::npos ? a : tail.find("==", a + 1);
        if (dd == std::string_view::npos)
            return {};
        const std::string_view h = tail.substr(0, a), orighost = tail.substr(a + 1, dd - a - 1), rest = tail.substr(dd + 1);
        // The first forwarder's day stamp in =HHHH=TT=... is read too, so an SRS1 address lives no longer than its SRS0.
        const size_t ta = rest.find('=', 1), tb = ta == std::string_view::npos ? ta : rest.find('=', ta + 1);
        if (orighost.empty() || orighost.find('=') != std::string_view::npos || tb == std::string_view::npos ||
            !fresh(rest.substr(ta + 1, tb - ta - 1), day) || !hash_ok(h, key, std::string(orighost) + std::string(rest)))
            return {};
        return "SRS0" + std::string(rest) + "@" + std::string(orighost);
    }
    return {};
}

}   // namespace socketley::mail::srs
