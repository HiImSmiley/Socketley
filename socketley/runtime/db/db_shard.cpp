#include "db_shard.h"

#include "../../shared/byte_codec.h"

namespace socketley::db
{

std::string encode_crossing(const crossing& c)
{
    socketley::bytes::writer w;
    w.reserve(cross_marker.size() + 32 + c.who.sub.size() + c.method.size() + c.path.size() + c.body.size() +
              c.if_match.size() + c.if_none_match.size());
    std::string out(cross_marker);
    w.u8(static_cast<uint8_t>(c.who.kind));
    w.bytes(c.who.sub);
    w.bytes(c.method);
    w.bytes(c.path);
    w.bytes(c.body);
    w.bytes(c.if_match);
    w.bytes(c.if_none_match);
    out += w.take();
    return out;
}

bool decode_crossing(std::string_view in, crossing& out)
{
    if (!in.starts_with(cross_marker))
        return false;
    socketley::bytes::reader r(in.substr(cross_marker.size()));
    uint8_t kind = 0;
    std::string_view sub;
    if (!r.u8(kind) || kind > principal::key || !r.view(sub, 4096) || !r.view(out.method, 16) ||
        !r.view(out.path, 4096) || !r.view(out.body, 64u << 20) || !r.view(out.if_match, 256) ||
        !r.view(out.if_none_match, 256) || r.left() != 0)
        return false;
    out.who = principal{static_cast<principal::kind_t>(kind), std::string(sub)};
    return true;
}

std::string encode_crossing_reply(int status, uint64_t version, std::string_view body)
{
    socketley::bytes::writer w;
    w.reserve(16 + body.size());
    w.u32(static_cast<uint32_t>(status));
    w.u64(version);
    w.bytes(body);
    return w.take();
}

bool decode_crossing_reply(std::string_view in, int& status, uint64_t& version, std::string_view& body)
{
    socketley::bytes::reader r(in);
    uint32_t s = 0;
    if (!r.u32(s) || !r.u64(version) || !r.view(body, 64u << 20) || r.left() != 0)
        return false;
    status = static_cast<int>(s);
    return true;
}

}   // namespace socketley::db
