#include "mail_mailbox.h"

#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_run.h"
#include "../idp/idp_run.h"
#include "../../shared/storage/storage_rpc.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/size_suffix.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

namespace rpc = socketley::storage_rpc;

constexpr int64_t known_ms = 60000;
constexpr int64_t unknown_ms = 10000;

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

// What a storage's refusal is for the sender, its reply's start: a message too large for good, a store that is full
// for now, as its operator may make room, and anything else worth trying again.
std::string refusal_of(const rpc::reply& r)
{
    if (r.code == "EntityTooLarge")
        return "552 5.3.4";
    if (r.code == "QuotaExceeded")
        return "452 4.2.2";
    return "451 4.3.0";
}

}   // namespace

namespace
{

// `s` cut to at most `n` bytes between whole UTF-8 characters, so metadata and an event hold no broken one.
std::string utf8_cut(std::string s, size_t n)
{
    if (s.size() <= n)
        return s;
    size_t k = n;
    while (k > 0 && (static_cast<unsigned char>(s[k]) & 0xC0) == 0x80)
        --k;
    s.resize(k);
    return s;
}

}   // namespace

struct mailboxes::writing
{
    entry_ptr e;
    std::string key;
    std::string head;
    std::string pending;
    uint64_t read_off{0};
    uint64_t total{0};
    std::string stream;
    std::string from, subject;
    // The header block a filter's editheader left, written in place of the message's own.
    std::string header;
    std::function<void(int, std::string)> done;
    bool retried{false};
};

mailboxes::mailboxes(mail_run& run) : m_run(run) {}

bool mailboxes::configure(std::string& why)
{
    const std::string_view spec = m_run.owner().get_storage();
    m_idp = std::string(m_run.owner().get_idp());
    if (spec.empty())
        return true;
    const size_t slash = spec.find('/');
    m_storage = std::string(spec.substr(0, slash));
    if (slash != std::string_view::npos && slash + 1 < spec.size())
        m_bucket = std::string(spec.substr(slash + 1));
    if (m_storage.empty())
    {
        why = "--storage names no storage runtime";
        return false;
    }
    return true;
}

void mailboxes::ask(const std::string& target, std::string payload,
                    std::function<void(request_status, std::string_view)> cb)
{
    m_run.ask(target, std::move(payload), std::move(cb));
}

void mailboxes::find(const std::string& name, std::function<void(account, std::string, std::string)> done)
{
    const std::string key = lower(name);
    if (m_idp.empty())
    {
        // Without an idp runtime a mailbox is a name an alias gave it.
        done(name.find('@') == std::string::npos ? account::yes : account::no, key, {});
        return;
    }
    const int64_t now = wall::now_ms_coarse();
    if (const auto it = m_known.find(key); it != m_known.end() && it->second.until_ms > now)
    {
        done(it->second.found ? account::yes : account::no, it->second.user, it->second.email);
        return;
    }
    std::string payload(socketley::idp::command_marker);
    payload += "lookup\n" + key;
    ask(m_idp, std::move(payload), [this, key, done, alive = m_alive](request_status st, std::string_view reply) {
        if (!*alive)
            return;
        known k;
        const int64_t now = wall::now_ms_coarse();
        if (st == request_status::ok && reply.starts_with("ok "))
        {
            take_answer(reply.substr(3), k);
            k.found = true;
            k.until_ms = now + known_ms;
            m_quota[lower(k.user)] = k.quota;
        }
        else if (st == request_status::ok)
            k.until_ms = now + unknown_ms;
        // An idp runtime that does not answer leaves nothing known, so the next ask asks again, and the mail waits.
        if (st != request_status::ok)
        {
            done(account::unreachable, {}, {});
            return;
        }
        // Names a stranger tries are kept a while, never without bound: what has expired goes first, then all.
        if (m_known.size() >= 65536)
        {
            std::erase_if(m_known, [now](const auto& kv) { return kv.second.until_ms <= now; });
            if (m_known.size() >= 65536)
                m_known.clear();
        }
        m_known[key] = k;
        done(k.found ? account::yes : account::no, k.user, k.email);
    });
}

void mailboxes::verify(const std::string& user, const std::string& password,
                       std::function<void(account, std::string, std::string)> done)
{
    if (m_idp.empty() || user.find('\n') != std::string::npos || password.find('\n') != std::string::npos)
    {
        done(account::no, {}, {});
        return;
    }
    std::string payload(socketley::idp::command_marker);
    payload += "verify\n" + user + "\n" + password;
    ask(m_idp, std::move(payload), [this, done, alive = m_alive](request_status st, std::string_view reply) {
        if (!*alive)
            return;
        if (st != request_status::ok || !reply.starts_with("ok "))
        {
            done(st == request_status::ok ? account::no : account::unreachable, {}, {});
            return;
        }
        known k;
        take_answer(reply.substr(3), k);
        m_quota[lower(k.user)] = k.quota;
        done(account::yes, k.user, k.email);
    });
}

void mailboxes::take_answer(std::string_view rest, known& k)
{
    // <user> TAB <email> TAB <mail quota>, the quota a size such as 500M, none where it is empty.
    const size_t a = rest.find('\t');
    k.user = std::string(rest.substr(0, a));
    const std::string_view after = a == std::string_view::npos ? std::string_view{} : rest.substr(a + 1);
    const size_t b = after.find('\t');
    k.email = std::string(after.substr(0, b));
    size_t q = 0;
    k.quota = b != std::string_view::npos && parse_size_suffix(after.substr(b + 1), q) ? q : 0;
}

uint64_t mailboxes::quota_of(const std::string& user) const
{
    // A user with no quota of their own has the runtime's --default-quota.
    const auto it = m_quota.find(lower(user));
    return it == m_quota.end() || it->second == 0 ? m_run.owner().get_default_quota() : it->second;
}

void mailboxes::make_bucket(std::function<void(bool)> then)
{
    if (m_bucket_made)
    {
        then(true);
        return;
    }
    m_bucket_waiting.push_back(std::move(then));
    if (m_bucket_waiting.size() > 1)
        return;
    rpc::request rq;
    rq.kind = rpc::op::make_bucket;
    rq.bucket = m_bucket;
    ask(m_storage, rpc::encode(rq), [this, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        const bool ok = st == request_status::ok && rpc::decode(bytes, rpc::op::make_bucket, r) && r.ok;
        m_bucket_made = ok;
        auto waiting = std::move(m_bucket_waiting);
        m_bucket_waiting.clear();
        for (auto& w : waiting)
            w(ok);
    });
}

std::string key_flags(uint8_t flags)
{
    std::string out;
    for (const auto& [bit, letter] : {std::pair{16, 'D'}, {4, 'F'}, {2, 'R'}, {1, 'S'}, {8, 'T'}})
        if (flags & bit)
            out += letter;
    return out.empty() ? out : "," + out;
}

uint8_t flags_of_key(std::string_view key)
{
    if (!key.ends_with(".eml"))
        return 0;
    key.remove_suffix(4);
    const size_t comma = key.rfind(',');
    if (comma == std::string_view::npos || key.find('/', comma) != std::string_view::npos)
        return 0;
    uint8_t out = 0;
    for (const char c : key.substr(comma + 1))
        out |= c == 'D' ? 16 : c == 'F' ? 4 : c == 'R' ? 2 : c == 'S' ? 1 : c == 'T' ? 8 : 0;
    return out;
}

void mailboxes::deliver(const entry_ptr& e, const std::string& user, const std::string& folder, std::string head,
                        std::function<void(int, std::string)> done, uint8_t flags, std::string header)
{
    auto w = std::make_shared<writing>();
    w->e = e;
    w->header = std::move(header);
    w->key = user + "/" + folder + "/" + e->id + key_flags(flags) + ".eml";
    w->head = std::move(head);
    w->done = std::move(done);
    make_bucket([this, w](bool ok) {
        if (!ok)
        {
            finish(w, 451, "451 4.3.0 the mailbox store " + m_storage + " has no bucket " + m_bucket + " and makes none");
            return;
        }
        // The message's head first: its own Authentication-Results under this host's name are not taken as said.
        const uint32_t first = static_cast<uint32_t>(std::min<uint64_t>(w->e->body_len, rpc::max_value));
        m_run.queue().read(w->e, 0, first, [this, w, first, alive = m_alive](bool ok, std::string_view chunk) {
            if (!*alive)
                return;
            if (!ok)
            {
                finish(w, 451, "451 4.3.0 the message could not be read from the spool");
                return;
            }
            const std::string_view block = header_block(chunk);
            const bool whole_head = block.size() < chunk.size() || chunk.size() == w->e->body_len;
            std::string kept;
            // The headers kept are the edited ones where a filter changed them, the body following the original's.
            const std::string_view source = whole_head && !w->header.empty() ? std::string_view(w->header) : block;
            if (whole_head)
            {
                for (const auto& [name, value] : split_headers(source))
                {
                    // The authserv-id comes after any comments and folding, and may be quoted (RFC 8601 2.2).
                    std::string_view v = value;
                    for (int depth = 0; !v.empty();)
                    {
                        const char ch = v.front();
                        if (ch == '(')
                            ++depth;
                        else if (ch == ')' && depth > 0)
                            --depth;
                        else if (depth == 0 && ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
                            break;
                        v.remove_prefix(1);
                    }
                    std::string_view id = v.substr(0, v.find_first_of("; \t\r\n("));
                    if (id.size() >= 2 && id.front() == '"')
                        id = v.substr(1, v.find('"', 1) == std::string_view::npos ? 0 : v.find('"', 1) - 1);
                    std::string_view n = name;
                    while (!n.empty() && (n.back() == ' ' || n.back() == '\t'))
                        n.remove_suffix(1);
                    if (socketley::ascii::iequals(n, "Authentication-Results") &&
                        socketley::ascii::iequals(id, m_run.hostname()))
                        continue;
                    // The Return-Path is the one this delivery writes (RFC 5321 4.4); a sender's is not kept beside it.
                    if (socketley::ascii::iequals(n, "Return-Path"))
                        continue;
                    kept.append(name.data(), name.size()).append(":").append(value.data(), value.size()).append("\r\n");
                    if (socketley::ascii::iequals(name, "From"))
                        w->from = utf8_cut(header_value(source, "From"), 256);
                    else if (socketley::ascii::iequals(name, "Subject"))
                        w->subject = utf8_cut(header_value(source, "Subject"), 512);
                }
                if (source.ends_with("\r\n\r\n") || source == "\r\n")
                    kept += "\r\n";
            }
            else
                kept.assign(block);
            w->pending = w->head + kept;
            w->pending.append(chunk.substr(block.size()));
            w->read_off = first;
            w->total = w->head.size() + kept.size() + (w->e->body_len - block.size());
            if (w->total <= rpc::max_value && w->read_off >= w->e->body_len)
                put_small(w);
            else
                put_stream(w);
        });
    });
}

void mailboxes::put_small(const std::shared_ptr<writing>& w)
{
    rpc::request rq;
    rq.kind = rpc::op::put;
    rq.bucket = m_bucket;
    rq.key = w->key;
    rq.content_type = "message/rfc822";
    rq.data = std::move(w->pending);
    if (!w->from.empty())
        rq.metadata.emplace_back("from", w->from);
    if (!w->subject.empty())
        rq.metadata.emplace_back("subject", w->subject);
    ask(m_storage, rpc::encode(rq), [this, w, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::put, r))
        {
            finish(w, 451, "451 4.3.0 the mailbox store " + m_storage + " does not answer");
            return;
        }
        if (!r.ok)
        {
            const std::string why = refusal_of(r);
            finish(w, std::atoi(why.c_str()), why + " the mailbox store refused it: " + r.code + " " + r.message);
            return;
        }
        finish(w, 250, "250 2.0.0 delivered to " + w->key);
    });
}

void mailboxes::put_stream(const std::shared_ptr<writing>& w)
{
    rpc::request rq;
    rq.kind = rpc::op::put_begin;
    rq.bucket = m_bucket;
    rq.key = w->key;
    rq.content_type = "message/rfc822";
    rq.size = w->total;
    if (!w->from.empty())
        rq.metadata.emplace_back("from", w->from);
    if (!w->subject.empty())
        rq.metadata.emplace_back("subject", w->subject);
    ask(m_storage, rpc::encode(rq), [this, w, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::put_begin, r) || !r.ok || r.next.empty())
        {
            const std::string why = r.ok ? std::string("451 4.3.0") : refusal_of(r);
            finish(w, std::atoi(why.c_str()), why + " the mailbox store would not take it: " + r.code);
            return;
        }
        w->stream = r.next;
        read_on(w);
    });
}

void mailboxes::read_on(const std::shared_ptr<writing>& w)
{
    // A piece of a mebibyte at a time, read from the spool as the store takes the last.
    if (w->pending.size() >= rpc::max_value || w->read_off >= w->e->body_len)
    {
        put_piece(w);
        return;
    }
    const uint32_t want = static_cast<uint32_t>(
        std::min<uint64_t>(rpc::max_value - w->pending.size(), w->e->body_len - w->read_off));
    m_run.queue().read(w->e, w->read_off, want, [this, w, alive = m_alive](bool ok, std::string_view b) {
        if (!*alive)
            return;
        if (!ok || b.empty())
        {
            finish(w, 451, "451 4.3.0 the message could not be read from the spool");
            return;
        }
        w->pending.append(b);
        w->read_off += b.size();
        read_on(w);
    });
}

void mailboxes::put_piece(const std::shared_ptr<writing>& w)
{
    rpc::request rq;
    rq.kind = rpc::op::put_more;
    rq.stream = w->stream;
    const size_t n = std::min<size_t>(w->pending.size(), rpc::max_value);
    // The last piece is moved into the request rather than copied out of the buffer.
    if (n == w->pending.size())
    {
        rq.data = std::move(w->pending);
        w->pending.clear();
    }
    else
    {
        rq.data.assign(w->pending, 0, n);
        w->pending.erase(0, n);
    }
    rq.last = w->pending.empty() && w->read_off >= w->e->body_len;
    const bool last = rq.last;
    ask(m_storage, rpc::encode(rq), [this, w, last, alive = m_alive](request_status st, std::string_view bytes) {
        if (!*alive)
            return;
        rpc::reply r;
        if (st != request_status::ok || !rpc::decode(bytes, rpc::op::put_more, r))
        {
            finish(w, 451, "451 4.3.0 the mailbox store does not answer");
            return;
        }
        if (!r.ok)
        {
            const std::string why = refusal_of(r);
            finish(w, std::atoi(why.c_str()), why + " the mailbox store refused it: " + r.code + " " + r.message);
            return;
        }
        if (last)
            finish(w, 250, "250 2.0.0 delivered to " + w->key);
        else
            read_on(w);
    });
}

void mailboxes::finish(const std::shared_ptr<writing>& w, int code, std::string text)
{
    if (!w->done)
        return;
    // A stream begun and given up is ended at the store now, not when it next sweeps for stale ones.
    if (code / 100 != 2 && !w->stream.empty())
    {
        rpc::request rq;
        rq.kind = rpc::op::abort;
        rq.stream = std::move(w->stream);
        w->stream.clear();
        ask(m_storage, rpc::encode(rq), [](request_status, std::string_view) {});
    }
    if (code / 100 == 2)
    {
        ++m_stored;
        // The IMAP index is told at once, rather than when a listing of the bucket finds it.
        if (imap_store* imap = m_run.imap())
        {
            const size_t first = w->key.find('/'), last = w->key.rfind('/');
            if (first != std::string::npos && last > first)
            {
                imap->delivered(w->key.substr(0, first), w->key.substr(first + 1, last - first - 1), w->key, w->total,
                                w->e->at_ms);
                m_run.stored(w->key.substr(0, first), w->total);
            }
        }
        if (on_stored)
        {
            const size_t slash = w->key.find('/');
            const size_t slash2 = w->key.find('/', slash + 1);
            on_stored({w->e->id, w->key.substr(0, slash), w->key.substr(slash + 1, slash2 - slash - 1), w->key,
                       w->from, w->subject, w->total});
        }
    }
    else
        ++m_store_failures;
    auto done = std::move(w->done);
    w->done = nullptr;
    done(code, std::move(text));
}

}   // namespace socketley::mail
