#pragma once
// What a script asks of a storage runtime and what it is told, as the request
// channel carries it: a payload on the way in and a reply on the way out, both
// self-describing so the runtime that asks and the runtime that answers need
// share nothing but this file.
//
// An object moved this way is held whole in memory at both ends and crosses a
// process boundary in a frame that waits in a writer capped at 4 MiB, so
// `max_value` leaves room for a few of them in flight; anything larger is what
// the S3 port is for.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "byte_codec.h"

namespace socketley::storage_rpc
{

inline constexpr size_t max_value = 1u << 20;
inline constexpr size_t max_field = 1u << 16;
inline constexpr uint32_t max_list = 1000;
inline constexpr uint8_t version = 1;

// users answers for the storage's users rather than its objects, a page of them after start_after, each an
// object_info whose key is the user and whose metadata holds name, email, admin, reset and the password's hash.
enum class op : uint8_t { put = 1, get = 2, head = 3, del = 4, list = 5, users = 6 };

inline const char* op_name(op o)
{
    switch (o)
    {
        case op::put:  return "put";
        case op::get:  return "get";
        case op::head: return "head";
        case op::del:  return "delete";
        case op::list: return "list";
        case op::users: return "users";
    }
    return "?";
}

struct request
{
    op          kind{op::get};
    std::string bucket;
    std::string key;
    // put
    std::string data;
    std::string content_type;
    // The user metadata, as name and value without the x-amz-meta- prefix.
    std::vector<std::pair<std::string, std::string>> metadata;
    // list
    std::string prefix;
    std::string delimiter;
    std::string start_after;
    uint32_t    max_keys{max_list};
};

inline std::string encode(const request& r)
{
    socketley::bytes::writer w;
    w.u8(version);
    w.u8(static_cast<uint8_t>(r.kind));
    w.bytes(r.bucket);
    w.bytes(r.key);
    w.bytes(r.data);
    w.bytes(r.content_type);
    w.u32(static_cast<uint32_t>(r.metadata.size()));
    for (const auto& [k, v] : r.metadata)
    {
        w.bytes(k);
        w.bytes(v);
    }
    w.bytes(r.prefix);
    w.bytes(r.delimiter);
    w.bytes(r.start_after);
    w.u32(r.max_keys);
    return w.take();
}

inline bool decode(std::string_view in, request& r)
{
    socketley::bytes::reader rd(in);
    uint8_t v = 0, k = 0;
    if (!rd.u8(v) || v != version || !rd.u8(k) || k < 1 || k > 6)
        return false;
    r.kind = static_cast<op>(k);
    uint32_t n = 0;
    if (!rd.bytes(r.bucket, max_field) || !rd.bytes(r.key, max_field) ||
        !rd.bytes(r.data, max_value) || !rd.bytes(r.content_type, max_field) || !rd.u32(n) || n > 256)
        return false;
    r.metadata.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string name, value;
        if (!rd.bytes(name, max_field) || !rd.bytes(value, max_field))
            return false;
        r.metadata.emplace_back(std::move(name), std::move(value));
    }
    return rd.bytes(r.prefix, max_field) && rd.bytes(r.delimiter, max_field) &&
           rd.bytes(r.start_after, max_field) && rd.u32(r.max_keys);
}

struct object_info
{
    std::string key;
    uint64_t    size{0};
    std::string etag;
    std::string content_type;
    int64_t     mtime_ms{0};
    std::vector<std::pair<std::string, std::string>> metadata;
};

struct reply
{
    bool        ok{true};
    // An S3 error code and its message when not ok.
    std::string code;
    std::string message;
    // get
    std::string data;
    // put, get, head
    object_info info;
    // list
    std::vector<object_info> objects;
    std::vector<std::string> prefixes;
    bool        truncated{false};
    std::string next;
};

inline void encode_info(socketley::bytes::writer& w, const object_info& i, bool with_meta)
{
    w.bytes(i.key);
    w.u64(i.size);
    w.bytes(i.etag);
    w.bytes(i.content_type);
    w.u64(static_cast<uint64_t>(i.mtime_ms));
    if (!with_meta)
    {
        w.u32(0);
        return;
    }
    w.u32(static_cast<uint32_t>(i.metadata.size()));
    for (const auto& [k, v] : i.metadata)
    {
        w.bytes(k);
        w.bytes(v);
    }
}

inline bool decode_info(socketley::bytes::reader& rd, object_info& i)
{
    uint64_t mt = 0;
    uint32_t n = 0;
    if (!rd.bytes(i.key, max_field) || !rd.u64(i.size) || !rd.bytes(i.etag, max_field) ||
        !rd.bytes(i.content_type, max_field) || !rd.u64(mt) || !rd.u32(n) || n > 256)
        return false;
    i.mtime_ms = static_cast<int64_t>(mt);
    i.metadata.clear();
    for (uint32_t j = 0; j < n; ++j)
    {
        std::string name, value;
        if (!rd.bytes(name, max_field) || !rd.bytes(value, max_field))
            return false;
        i.metadata.emplace_back(std::move(name), std::move(value));
    }
    return true;
}

inline std::string encode(const reply& r, op kind)
{
    socketley::bytes::writer w;
    w.u8(version);
    w.u8(r.ok ? 1 : 0);
    if (!r.ok)
    {
        w.bytes(r.code);
        w.bytes(r.message);
        return w.take();
    }
    switch (kind)
    {
        case op::put:
        case op::head:
            encode_info(w, r.info, true);
            break;
        case op::get:
            encode_info(w, r.info, true);
            w.bytes(r.data);
            break;
        case op::del:
            break;
        case op::users:
            w.u32(static_cast<uint32_t>(r.objects.size()));
            for (const auto& o : r.objects)
                encode_info(w, o, true);
            w.u8(r.truncated ? 1 : 0);
            break;
        case op::list:
            w.u32(static_cast<uint32_t>(r.objects.size()));
            for (const auto& o : r.objects)
                encode_info(w, o, false);
            w.u32(static_cast<uint32_t>(r.prefixes.size()));
            for (const auto& p : r.prefixes)
                w.bytes(p);
            w.u8(r.truncated ? 1 : 0);
            w.bytes(r.next);
            break;
    }
    return w.take();
}

inline bool decode(std::string_view in, op kind, reply& r)
{
    socketley::bytes::reader rd(in);
    uint8_t v = 0, ok = 0;
    if (!rd.u8(v) || v != version || !rd.u8(ok) || ok > 1)
        return false;
    r.ok = ok == 1;
    if (!r.ok)
        return rd.bytes(r.code, max_field) && rd.bytes(r.message, max_field);
    switch (kind)
    {
        case op::put:
        case op::head:
            return decode_info(rd, r.info);
        case op::get:
            return decode_info(rd, r.info) && rd.bytes(r.data, max_value);
        case op::del:
            return true;
        case op::users:
        {
            uint32_t n = 0;
            if (!rd.u32(n) || n > max_list)
                return false;
            r.objects.resize(n);
            for (auto& o : r.objects)
                if (!decode_info(rd, o))
                    return false;
            uint8_t t = 0;
            if (!rd.u8(t) || t > 1)
                return false;
            r.truncated = t == 1;
            return true;
        }
        case op::list:
        {
            uint32_t n = 0;
            if (!rd.u32(n) || n > max_list)
                return false;
            r.objects.resize(n);
            for (auto& o : r.objects)
                if (!decode_info(rd, o))
                    return false;
            if (!rd.u32(n) || n > max_list)
                return false;
            r.prefixes.resize(n);
            for (auto& p : r.prefixes)
                if (!rd.bytes(p, max_field))
                    return false;
            uint8_t t = 0;
            if (!rd.u8(t) || t > 1)
                return false;
            r.truncated = t == 1;
            return rd.bytes(r.next, max_field);
        }
    }
    return false;
}

}   // namespace socketley::storage_rpc
