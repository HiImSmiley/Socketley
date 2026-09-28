#include "raft_codec.h"

#include "byte_codec.h"

namespace socketley::raft::wire
{

namespace {

class writer : public bytes::writer
{
public:
    explicit writer(kind k)
    {
        u8(version);
        u8(static_cast<uint8_t>(k));
    }
};

using reader = bytes::reader;

constexpr size_t entry_header = 8 + 8 + 1 + 4;

bool fail(std::string* why, const char* reason)
{
    if (why)
        *why = reason;
    return false;
}

}   // namespace

std::string encode(const raft::message& m)
{
    writer w(kind::message);
    w.u8(static_cast<uint8_t>(m.type));
    w.u64(m.from);
    w.u64(m.to);
    w.u64(m.term);
    w.u64(m.index);
    w.u64(m.log_term);
    w.u64(m.commit);
    w.u8(m.reject ? 1 : 0);
    w.u64(m.hint_index);
    w.u64(m.hint_term);
    w.u64(m.context);
    w.u32(static_cast<uint32_t>(m.entries.size()));
    for (const entry& e : m.entries)
    {
        w.u64(e.term);
        w.u64(e.index);
        w.u8(static_cast<uint8_t>(e.type));
        w.bytes(e.data);
    }
    w.u8(m.snap ? 1 : 0);
    if (m.snap)
    {
        w.u64(m.snap->index);
        w.u64(m.snap->term);
        w.ids(m.snap->voters);
        w.ids(m.snap->learners);
        w.bytes(m.snap->data);
    }
    return w.take();
}

std::string encode(const hello& h)
{
    writer w(kind::hello);
    w.u64(h.id);
    w.bytes(h.name);
    w.bytes(h.addr);
    return w.take();
}

std::string encode(const join& j)
{
    writer w(kind::join);
    w.u64(j.id);
    w.bytes(j.name);
    w.bytes(j.addr);
    w.u8(j.voter ? 1 : 0);
    return w.take();
}

std::string encode(const command& c)
{
    writer w(kind::command);
    w.bytes(c.data);
    return w.take();
}

std::string encode(kind k, const lease& l)
{
    writer w(k);
    w.u64(l.nonce);
    w.u64(l.index);
    return w.take();
}

bool decode(std::string_view payload, frame& out, std::string* why)
{
    reader r(payload);
    uint8_t v = 0, k = 0;
    if (!r.u8(v) || !r.u8(k))
        return fail(why, "short header");
    if (v != version)
        return fail(why, "unknown version");

    out = frame{};
    switch (k)
    {
    case static_cast<uint8_t>(kind::hello):
        out.kind = kind::hello;
        if (!r.u64(out.hi.id) || !r.bytes(out.hi.name, max_label) || !r.bytes(out.hi.addr, max_label))
            return fail(why, "malformed hello");
        if (out.hi.id == no_node)
            return fail(why, "hello from node 0");
        break;

    case static_cast<uint8_t>(kind::join):
        out.kind = kind::join;
        if (!r.u64(out.req.id) || !r.bytes(out.req.name, max_label) || !r.bytes(out.req.addr, max_label)
            || !r.flag(out.req.voter))
            return fail(why, "malformed join");
        if (out.req.id == no_node)
            return fail(why, "join from node 0");
        break;

    case static_cast<uint8_t>(kind::command):
        out.kind = kind::command;
        if (!r.bytes(out.cmd.data, max_command))
            return fail(why, "malformed command");
        if (out.cmd.data.empty())
            return fail(why, "empty command");
        break;

    case static_cast<uint8_t>(kind::lease_req):
    case static_cast<uint8_t>(kind::lease_grant):
        out.kind = static_cast<kind>(k);
        if (!r.u64(out.lease.nonce) || !r.u64(out.lease.index))
            return fail(why, "malformed lease");
        break;

    case static_cast<uint8_t>(kind::message):
    {
        out.kind = kind::message;
        raft::message& m = out.msg;
        uint8_t t = 0;
        if (!r.u8(t) || t > static_cast<uint8_t>(msg_type::timeout_now))
            return fail(why, "unknown message type");
        m.type = static_cast<msg_type>(t);
        uint32_t n = 0;
        if (!r.u64(m.from) || !r.u64(m.to) || !r.u64(m.term) || !r.u64(m.index) || !r.u64(m.log_term)
            || !r.u64(m.commit) || !r.flag(m.reject) || !r.u64(m.hint_index) || !r.u64(m.hint_term)
            || !r.u64(m.context) || !r.u32(n))
            return fail(why, "short message");
        if (static_cast<uint64_t>(n) * entry_header > r.left())
            return fail(why, "more entries than bytes");
        m.entries.resize(n);
        for (entry& e : m.entries)
        {
            uint8_t et = 0;
            if (!r.u64(e.term) || !r.u64(e.index) || !r.u8(et) || et > static_cast<uint8_t>(entry_type::config)
                || !r.bytes(e.data, r.left()))
                return fail(why, "malformed entry");
            e.type = static_cast<entry_type>(et);
        }
        bool has_snap = false;
        if (!r.flag(has_snap))
            return fail(why, "short message");
        if (has_snap)
        {
            auto s = std::make_shared<snapshot>();
            if (!r.u64(s->index) || !r.u64(s->term) || !r.ids(s->voters) || !r.ids(s->learners)
                || !r.bytes(s->data, r.left()))
                return fail(why, "malformed snapshot");
            m.snap = std::move(s);
        }
        // Only a snapshot message carries one, so the core never has to ask.
        if ((m.type == msg_type::snapshot) != static_cast<bool>(m.snap))
            return fail(why, "snapshot on the wrong message");
        // The core appends entries where they say they go, so an append whose entries do not continue its index is refused here.
        if (m.type != msg_type::append && !m.entries.empty())
            return fail(why, "entries on the wrong message");
        for (size_t i = 0; i < m.entries.size(); ++i)
            if (m.entries[i].index != m.index + 1 + i || m.entries[i].index == 0)
                return fail(why, "entries out of sequence");
        break;
    }

    default:
        return fail(why, "unknown frame kind");
    }

    if (r.left() != 0)
        return fail(why, "trailing bytes");
    return true;
}

bool same(const raft::message& a, const raft::message& b)
{
    if (a.type != b.type || a.from != b.from || a.to != b.to || a.term != b.term || a.index != b.index
        || a.log_term != b.log_term || a.commit != b.commit || a.reject != b.reject
        || a.hint_index != b.hint_index || a.hint_term != b.hint_term || a.context != b.context
        || a.entries != b.entries || static_cast<bool>(a.snap) != static_cast<bool>(b.snap))
        return false;
    if (!a.snap)
        return true;
    return a.snap->index == b.snap->index && a.snap->term == b.snap->term && a.snap->voters == b.snap->voters
        && a.snap->learners == b.snap->learners && a.snap->data == b.snap->data;
}

}   // namespace socketley::raft::wire
