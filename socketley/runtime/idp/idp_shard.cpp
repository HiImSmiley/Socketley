#include "idp_shard.h"

#include <charconv>

#include "../../shared/util/byte_codec.h"

namespace socketley::idp
{

std::string encode_call(const shard_call& c)
{
    socketley::bytes::writer w(cross_marker);
    w.u8(c.op);
    w.bytes(c.key);
    w.u64(static_cast<uint64_t>(c.at));
    w.u32(static_cast<uint32_t>(c.fields.size()));
    for (const auto& [k, v] : c.fields)
    {
        w.bytes(k);
        w.bytes(v);
    }
    return w.take();
}

bool decode_call(std::string_view in, shard_call& out)
{
    socketley::bytes::reader r(in);
    uint8_t op = 0;
    uint64_t at = 0;
    uint32_t n = 0;
    if (!r.marker(cross_marker) || !r.u8(op) || op < shard_call::redeem || op > shard_call::device_ask || !r.bytes(out.key, 256) || !r.u64(at) ||
        !r.u32(n) || n > account_store::max_fields)
        return false;
    out.op = static_cast<shard_call::op_t>(op);
    out.at = static_cast<int64_t>(at);
    out.fields.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string k, v;
        if (!r.bytes(k, 64) || !r.bytes(v, account_store::max_value))
            return false;
        out.fields.emplace_back(std::move(k), std::move(v));
    }
    return r.left() == 0;
}

std::string encode_code(const code_entry* e)
{
    socketley::bytes::writer w;
    w.flag(e);
    if (e)
    {
        w.bytes(e->client_id);
        w.bytes(e->redirect);
        w.bytes(e->sub);
        w.bytes(e->nonce);
        w.bytes(e->scope);
        w.bytes(e->challenge);
        w.u64(static_cast<uint64_t>(e->auth_time));
        w.u64(static_cast<uint64_t>(e->expires));
    }
    return w.take();
}

bool decode_code(std::string_view in, bool& found, code_entry& out)
{
    socketley::bytes::reader r(in);
    if (!r.flag(found))
        return false;
    if (found)
    {
        uint64_t auth = 0, exp = 0;
        if (!r.bytes(out.client_id, 4096) || !r.bytes(out.redirect, 4096) || !r.bytes(out.sub, 4096) ||
            !r.bytes(out.nonce, 4096) || !r.bytes(out.scope, 4096) || !r.bytes(out.challenge, 4096) || !r.u64(auth) ||
            !r.u64(exp))
            return false;
        out.auth_time = static_cast<int64_t>(auth);
        out.expires = static_cast<int64_t>(exp);
    }
    return r.left() == 0;
}

std::string encode_device(device_poll what, const device_entry* e)
{
    socketley::bytes::writer w;
    w.u8(static_cast<uint8_t>(what));
    w.bytes(e ? std::string_view(e->sub) : std::string_view());
    w.bytes(e ? std::string_view(e->scope) : std::string_view());
    w.u64(e ? static_cast<uint64_t>(e->auth_time) : 0);
    return w.take();
}

bool decode_device(std::string_view in, device_poll& what, device_entry& out)
{
    socketley::bytes::reader r(in);
    uint8_t w = 0;
    uint64_t auth = 0;
    if (!r.u8(w) || w > static_cast<uint8_t>(device_poll::gone) || !r.bytes(out.sub, 4096) ||
        !r.bytes(out.scope, 4096) || !r.u64(auth))
        return false;
    what = static_cast<device_poll>(w);
    out.auth_time = static_cast<int64_t>(auth);
    return r.left() == 0;
}

std::string encode_result(bool ok, std::string_view why)
{
    socketley::bytes::writer w;
    w.flag(ok);
    w.bytes(why);
    return w.take();
}

bool decode_result(std::string_view in, bool& ok, std::string& why)
{
    socketley::bytes::reader r(in);
    return r.flag(ok) && r.bytes(why, 4096) && r.left() == 0;
}

bool code_shard(std::string_view code, uint32_t shards, uint32_t& shard)
{
    const size_t dot = code.find('.');
    if (shards <= 1 || dot == std::string_view::npos || dot == 0 || dot > 2)
        return false;
    uint32_t n = 0;
    const auto [end, ec] = std::from_chars(code.data(), code.data() + dot, n);
    if (ec != std::errc{} || end != code.data() + dot || n >= shards)
        return false;
    shard = n;
    return true;
}

}   // namespace socketley::idp
