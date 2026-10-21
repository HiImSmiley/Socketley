#include "mail_mailbox.h"

#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_run.h"
#include "../idp/idp_run.h"
#include "../../shared/storage/storage_rpc.h"
#include "../../shared/util/ascii.h"
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

// What a storage's refusal is for the sender: worth trying again, or not.
int code_for(const rpc::reply& r)
{
    if (r.code == "QuotaExceeded" || r.code == "EntityTooLarge")
        return 552;
    return 451;
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

void mailboxes::find(const std::string& name, std::function<void(bool, std::string, std::string)> done)
{
    const std::string key = lower(name);
    if (m_idp.empty())
    {
        // Without an idp runtime a mailbox is a name an alias gave it.
        done(name.find('@') == std::string::npos, key, {});
        return;
    }
    const int64_t now = wall::now_ms_coarse();
    if (const auto it = m_known.find(key); it != m_known.end() && it->second.until_ms > now)
    {
        done(it->second.found, it->second.user, it->second.email);
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
            const std::string_view rest = reply.substr(3);
            const size_t tab = rest.find('\t');
            k.found = true;
            k.user = std::string(rest.substr(0, tab));
            k.email = tab == std::string_view::npos ? std::string() : std::string(rest.substr(tab + 1));
            k.until_ms = now + known_ms;
        }
        else if (st == request_status::ok)
            k.until_ms = now + unknown_ms;
        // An idp runtime that does not answer leaves nothing known, so the next ask asks again.
        if (st == request_status::ok)
            m_known[key] = k;
        done(k.found, k.user, k.email);
    });
}

void mailboxes::verify(const std::string& user, const std::string& password,
                       std::function<void(bool, std::string, std::string)> done)
{
    if (m_idp.empty() || user.find('\n') != std::string::npos || password.find('\n') != std::string::npos)
    {
        done(false, {}, {});
        return;
    }
    std::string payload(socketley::idp::command_marker);
    payload += "verify\n" + user + "\n" + password;
    ask(m_idp, std::move(payload), [done, alive = m_alive](request_status st, std::string_view reply) {
        if (!*alive)
            return;
        if (st != request_status::ok || !reply.starts_with("ok "))
        {
            done(false, {}, {});
            return;
        }
        const std::string_view rest = reply.substr(3);
        const size_t tab = rest.find('\t');
        done(true, std::string(rest.substr(0, tab)),
             tab == std::string_view::npos ? std::string() : std::string(rest.substr(tab + 1)));
    });
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

void mailboxes::deliver(const entry_ptr& e, const std::string& user, const std::string& folder, std::string head,
                        std::function<void(int, std::string)> done)
{
    auto w = std::make_shared<writing>();
    w->e = e;
    w->key = user + "/" + folder + "/" + e->id + ".eml";
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
            if (whole_head)
            {
                for (const auto& [name, value] : split_headers(block))
                {
                    std::string_view v = value;
                    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                        v.remove_prefix(1);
                    const std::string_view id = v.substr(0, v.find_first_of("; \t\r"));
                    if (socketley::ascii::iequals(name, "Authentication-Results") &&
                        socketley::ascii::iequals(id, m_run.hostname()))
                        continue;
                    kept.append(name.data(), name.size()).append(":").append(value.data(), value.size()).append("\r\n");
                    if (socketley::ascii::iequals(name, "From"))
                        w->from = header_value(block, "From").substr(0, 256);
                    else if (socketley::ascii::iequals(name, "Subject"))
                        w->subject = header_value(block, "Subject").substr(0, 512);
                }
                if (block.ends_with("\r\n\r\n") || block == "\r\n")
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
            finish(w, code_for(r), std::to_string(code_for(r)) + " " + (code_for(r) == 552 ? "5.2.2" : "4.3.0") +
                                       " the mailbox store refused it: " + r.code + " " + r.message);
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
            finish(w, r.ok ? 451 : code_for(r), "451 4.3.0 the mailbox store would not take it: " + r.code);
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
    rq.data = w->pending.substr(0, n);
    w->pending.erase(0, n);
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
            finish(w, code_for(r), std::to_string(code_for(r)) + " " + (code_for(r) == 552 ? "5.2.2" : "4.3.0") +
                                       " the mailbox store refused it: " + r.code + " " + r.message);
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
    if (code / 100 == 2)
        ++m_stored;
    else
        ++m_store_failures;
    auto done = std::move(w->done);
    w->done = nullptr;
    done(code, std::move(text));
}

}   // namespace socketley::mail
