// The stream commands, Redis 7.0's to the error text, in one place for both
// protocols, the replication log and the readers a write wakes.
#include "cache_instance.h"
#include "resp_parser.h"
#include "../../cli/command_hashing.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

#include <chrono>
#include <cstring>
#include <strings.h>

namespace
{
using sv = std::string_view;

constexpr sv wrongtype = "WRONGTYPE Operation against a key holding the wrong kind of value";
constexpr sv bad_id    = "Invalid stream ID specified as stream command argument";
constexpr sv syntax    = "syntax error";
constexpr sv not_int   = "value is not an integer or out of range";
constexpr sv oom       = "OOM command not allowed when used memory > 'maxmemory'";

// strcasecmp, which is how Redis matches every option word.
bool ieq(sv a, sv b)
{
    return a.size() == b.size() && strncasecmp(a.data(), b.data(), a.size()) == 0;
}

void err(std::string& rb, sv m) { resp::encode_error_into(rb, m); }
void err_code(std::string& rb, sv m) { resp::encode_error_code_into(rb, m); }

void err_arity(std::string& rb, sv name)
{
    rb.append("-ERR wrong number of arguments for '");
    resp::append_one_line(rb, name);
    rb.append("' command\r\n");
}

void err_subcommand(std::string& rb, sv sub, sv container)
{
    rb.append("-ERR unknown subcommand '");
    resp::append_one_line(rb, sub.substr(0, 128));
    rb.append("'. Try ");
    rb.append(container);
    rb.append(" HELP.\r\n");
}

void err_subcommand_syntax(std::string& rb, sv sub, sv container)
{
    rb.append("-ERR unknown subcommand or wrong number of arguments for '");
    resp::append_one_line(rb, sub.substr(0, 128));
    rb.append("'. Try ");
    rb.append(container);
    rb.append(" HELP.\r\n");
}

void put_id(std::string& rb, stream_id id)
{
    char b[stream_id::text_max];
    resp::encode_bulk_into(rb, sv(b, id.format(b)));
}

void put_entry(std::string& rb, const stream_log::entry& e)
{
    rb.append("*2\r\n", 4);
    put_id(rb, e.id);
    resp::encode_array_header_into(rb, static_cast<int>(2 * e.pairs()));
    e.each([&](sv f, sv v) { resp::encode_bulk_into(rb, f); resp::encode_bulk_into(rb, v); });
}

void put_null(std::string& rb)       { rb.append("$-1\r\n", 5); }
void put_null_array(std::string& rb) { rb.append("*-1\r\n", 5); }

// A range bound, open when it starts with '(' as XRANGE's grammar has it.
bool parse_interval(sv arg, stream_id& id, bool& excl, uint64_t missing_seq)
{
    excl = arg.size() > 1 && arg[0] == '(';
    if (excl) return stream_parse_id(arg.substr(1), id, missing_seq, true, nullptr);
    return stream_parse_id(arg, id, missing_seq, false, nullptr);
}

std::string id_text(stream_id id) { return id.str(); }

// What XADD and XTRIM were asked to trim, and XADD's id.
struct trim_args
{
    stream_log::trim_spec spec;
    bool      nomkstream{false};
    bool      id_given{false};
    bool      seq_given{true};
    stream_id id;
};

// Redis's streamParseAddOrTrimArgsOrReply, answering the id's position or -1
// with the error already written.
int parse_trim(sv* a, int argc, bool xadd, trim_args& t, std::string& rb)
{
    using by = stream_log::trim_by;
    bool limit_given = false;
    int i = 2;
    for (; i < argc; ++i)
    {
        const int more = argc - 1 - i;
        const sv  o = a[i];
        if (xadd && o == "*")
            break;
        const bool maxlen = ieq(o, "maxlen");
        if ((maxlen || ieq(o, "minid")) && more)
        {
            if (t.spec.by != by::none)
            {
                err(rb, "syntax error, MAXLEN and MINID options at the same time are not compatible");
                return -1;
            }
            t.spec.approx = false;
            if (more >= 2 && a[i + 1] == "~") { t.spec.approx = true; ++i; }
            else if (more >= 2 && a[i + 1] == "=") ++i;
            if (maxlen)
            {
                int64_t v = 0;
                if (!stream_strict_ll(a[i + 1], v)) { err(rb, not_int); return -1; }
                if (v < 0) { err(rb, "The MAXLEN argument must be >= 0."); return -1; }
                t.spec.maxlen = static_cast<uint64_t>(v);
                t.spec.by = by::maxlen;
            }
            else
            {
                if (!stream_parse_id(a[i + 1], t.spec.minid, 0, true, nullptr)) { err(rb, bad_id); return -1; }
                t.spec.by = by::minid;
            }
            ++i;
        }
        else if (ieq(o, "limit") && more)
        {
            int64_t v = 0;
            if (!stream_strict_ll(a[i + 1], v)) { err(rb, not_int); return -1; }
            if (v < 0) { err(rb, "The LIMIT argument must be >= 0."); return -1; }
            t.spec.limit = v;
            limit_given = true;
            ++i;
        }
        else if (xadd && ieq(o, "nomkstream"))
            t.nomkstream = true;
        else if (xadd)
        {
            if (!stream_parse_id(o, t.id, 0, true, &t.seq_given)) { err(rb, bad_id); return -1; }
            t.id_given = true;
            break;
        }
        else
        {
            err(rb, syntax);
            return -1;
        }
    }
    if (t.spec.limit && t.spec.by == by::none)
    {
        err(rb, "syntax error, LIMIT cannot be used without specifying a trimming strategy");
        return -1;
    }
    if (!xadd && t.spec.by == by::none)
    {
        err(rb, "syntax error, XTRIM must be called with a trimming strategy");
        return -1;
    }
    if (limit_given)
    {
        if (!t.spec.approx)
        {
            err(rb, "syntax error, LIMIT cannot be used without the special ~ option");
            return -1;
        }
    }
    else
        t.spec.limit = t.spec.approx ? 100 * static_cast<int64_t>(stream_log::node_max_entries) : 0;
    return i;
}

}   // namespace

// ─── The commands ───────────────────────────────────────────────────────────

struct stream_commands
{
    using group    = stream_log::group;
    using consumer = stream_log::consumer;

    cache_instance& ci;
    std::string&    rb;

    bool readonly()
    {
        if (ci.m_mode != cache_mode_readonly) return false;
        err(rb, "readonly mode");
        return true;
    }

    // The stream at `key` or null, with `bad` set when the key holds another type.
    stream_inner* lookup(sv key, bool& bad)
    {
        if (ci.m_has_ttl_keys) ci.m_store.check_expiry(key);
        stream_inner* s = ci.m_store.stream_find(key);
        bad = !s && ci.m_store.holds_other_type(key, 'x');
        if (bad) err_code(rb, wrongtype);
        return s;
    }

    bool logging() const { return ci.mutation_log_wanted(); }

    void nogroup_key(sv key, sv grp)
    {
        rb.append("-NOGROUP No such key '");
        resp::append_one_line(rb, key);
        rb.append("' or consumer group '");
        resp::append_one_line(rb, grp);
        rb.append("'\r\n");
    }

    void nogroup_for(sv grp, sv key)
    {
        rb.append("-NOGROUP No such consumer group '");
        resp::append_one_line(rb, grp);
        rb.append("' for key name '");
        resp::append_one_line(rb, key);
        rb.append("'\r\n");
    }

    void repl_group(sv key, sv gname, const group& g)
    {
        if (!logging()) return;
        const std::string last = id_text(g.last), er = std::to_string(g.entries_read);
        ci.stream_repl(key, { "XGROUP", "SETID", key, gname, last, "ENTRIESREAD", er });
    }

    void repl_consumer(sv key, sv gname, const consumer& c)
    {
        if (!logging()) return;
        const std::string seen = std::to_string(c.seen_ms), active = std::to_string(c.active_ms);
        ci.stream_repl(key, { "XCONSUMER", key, gname, c.name, seen, active });
    }

    void repl_nack(sv key, sv gname, sv cname, stream_id id, const stream_log::nack& n)
    {
        if (!logging()) return;
        const std::string idt = id_text(id), when = std::to_string(n.delivery_ms),
                          count = std::to_string(n.count);
        ci.stream_repl(key, { "XNACK", key, gname, cname, idt, when, count });
    }

    // ─── XADD ───────────────────────────────────────────────────────────────

    void xadd(sv* a, int argc)
    {
        if (argc < 5) { err_arity(rb, "xadd"); return; }
        if (readonly()) return;
        trim_args t;
        const int idpos = parse_trim(a, argc, true, t, rb);
        if (idpos < 0) return;
        const int fpos = idpos + 1;
        if (argc - fpos < 2 || (argc - fpos) % 2) { err_arity(rb, "xadd"); return; }
        if (t.id_given && t.seq_given && t.id.is_zero())
        {
            err(rb, "The ID specified in XADD must be greater than 0-0");
            return;
        }

        const sv key = a[1];
        bool bad = false;
        stream_inner* s = lookup(key, bad);
        if (bad) return;
        if (!s && t.nomkstream) { put_null(rb); return; }

        const stream_id last = s ? s->last_id() : stream_id{};
        if (last == stream_id::max())
        {
            err(rb, "The stream has exhausted the last possible ID, unable to add more items");
            return;
        }
        stream_id id;
        if (!t.id_given)
        {
            const uint64_t ms = static_cast<uint64_t>(socketley::wall::now_ms());
            if (ms > last.ms) id = { ms, 0 };
            else { id = last; id.incr(); }
        }
        else if (t.seq_given)
            id = t.id;
        else if (t.id.ms == last.ms)
        {
            // Redis answers this one with the size error, errno being all it reads.
            if (last.seq == UINT64_MAX) { err(rb, "Elements are too large to be stored"); return; }
            id = { last.ms, last.seq + 1 };
        }
        else
            id = { t.id.ms, 0 };
        if (id <= last)
        {
            err(rb, "The ID specified in XADD is equal or smaller than the target stream top item");
            return;
        }

        const size_t pairs = static_cast<size_t>(argc - fpos) / 2;
        const size_t growth = s ? s->append_growth(id, a + fpos, pairs)
                                : stream_inner{}.append_growth(id, a + fpos, pairs);
        if (!s)                                        s = ci.m_store.stream_make(key, growth);
        else if (ci.m_store.stream_admit(key, growth)) s = ci.m_store.stream_find(key);
        else                                           s = nullptr;
        if (!s) { err_code(rb, oom); return; }

        uint64_t trimmed = 0;
        ci.m_store.stream_change(key, *s, [&](stream_inner& st) {
            st.append(id, a + fpos, pairs);
            if (t.spec.by != stream_log::trim_by::none) trimmed = st.trim(t.spec);
        });
        char idb[stream_id::text_max];
        const sv ids(idb, id.format(idb));
        resp::encode_bulk_into(rb, ids);

        if (logging())
        {
            std::vector<sv> r;
            r.reserve(static_cast<size_t>(argc - fpos) + 3);
            r.push_back("XADD");
            r.push_back(key);
            r.push_back(ids);
            r.insert(r.end(), a + fpos, a + argc);
            ci.stream_repl(key, r.data(), r.size());
            if (trimmed)
            {
                const std::string len = std::to_string(s->size());
                ci.stream_repl(key, { "XTRIM", key, "MAXLEN", "=", len });
            }
        }
        ci.stream_signal(key);
    }

    // ─── XRANGE, XREVRANGE, XLEN ────────────────────────────────────────────

    void xrange(sv* a, int argc, bool rev)
    {
        if (argc < 4) { err_arity(rb, rev ? "xrevrange" : "xrange"); return; }
        stream_id lo, hi;
        bool lox = false, hix = false;
        if (!parse_interval(rev ? a[3] : a[2], lo, lox, 0)) { err(rb, bad_id); return; }
        if (lox && !lo.incr()) { err(rb, "invalid start ID for the interval"); return; }
        if (!parse_interval(rev ? a[2] : a[3], hi, hix, UINT64_MAX)) { err(rb, bad_id); return; }
        if (hix && !hi.decr()) { err(rb, "invalid end ID for the interval"); return; }
        int64_t count = -1;
        for (int j = 4; j < argc; ++j)
        {
            if (ieq(a[j], "count") && argc - j - 1 >= 1)
            {
                if (!stream_strict_ll(a[j + 1], count)) { err(rb, not_int); return; }
                if (count < 0) count = 0;
                ++j;
            }
            else { err(rb, syntax); return; }
        }
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        if (!s) { rb.append("*0\r\n", 4); return; }
        ci.m_store.stream_get(a[1]);
        if (count == 0) { put_null_array(rb); return; }
        const uint64_t cap = count < 0 ? 0 : static_cast<uint64_t>(count);
        std::string& body = ci.m_stream_scratch;
        body.clear();
        uint64_t n = 0;
        s->walk(lo, hi, rev, [&](const stream_log::entry& e) {
            put_entry(body, e);
            ++n;
            return cap == 0 || n < cap;
        });
        resp::encode_array_header_into(rb, static_cast<int>(n));
        rb.append(body);
    }

    void xlen(sv* a, int argc)
    {
        if (argc != 2) { err_arity(rb, "xlen"); return; }
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        resp::encode_integer_into(rb, s ? static_cast<int64_t>(s->size()) : 0);
    }

    // ─── XREAD, XREADGROUP ──────────────────────────────────────────────────

    // One stream's part of an XREAD answer: its name and the entries past `gt`,
    // a group's deliveries recorded and replicated as they are made.
    void serve(sv key, stream_inner& s, stream_id gt, uint64_t count, group* g, sv gname,
               sv cname, bool noack, bool history, std::string& out)
    {
        std::string body;
        uint64_t n = 0;
        const auto more = [&] { return count == 0 || n < count; };
        if (!g)
        {
            if (gt.incr())
                s.walk(gt, stream_id::max(), false, [&](const stream_log::entry& e) {
                    put_entry(body, e);
                    ++n;
                    return more();
                });
        }
        else
        {
            const int64_t now = socketley::wall::now_ms();
            ci.m_store.stream_change(key, s, [&](stream_inner& st) {
                consumer* c = st.find_consumer(*g, cname);
                if (!c) c = st.create_consumer(*g, cname, now);
                c->seen_ms = now;
                if (history)
                {
                    stream_id start = gt;
                    start.incr();
                    for (auto it = c->pel.lower_bound(start); it != c->pel.end() && more(); ++it)
                    {
                        stream_log::entry e;
                        if (st.find(*it, e))
                        {
                            put_entry(body, e);
                            stream_log::nack* nk = st.find_nack(*g, *it);
                            nk->delivery_ms = now;
                            ++nk->count;
                            repl_nack(key, gname, cname, *it, *nk);
                            c->active_ms = now;
                        }
                        else
                        {
                            body.append("*2\r\n", 4);
                            put_id(body, *it);
                            put_null_array(body);
                        }
                        ++n;
                    }
                }
                else if (gt.incr())
                {
                    bool moved = false;
                    st.walk(gt, stream_id::max(), false, [&](const stream_log::entry& e) {
                        if (e.id > g->last) { st.advance(*g, e.id); moved = true; }
                        put_entry(body, e);
                        if (!noack)
                            repl_nack(key, gname, cname, e.id, st.deliver(*g, e.id, *c, now));
                        ++n;
                        return more();
                    });
                    if (n) c->active_ms = now;
                    if (moved) repl_group(key, gname, *g);
                }
                repl_consumer(key, gname, *c);
            });
        }
        out.append("*2\r\n", 4);
        resp::encode_bulk_into(out, key);
        resp::encode_array_header_into(out, static_cast<int>(n));
        out.append(body);
    }

    void xread(client_connection* conn, sv* a, int argc, bool grp)
    {
        if (argc < (grp ? 7 : 4)) { err_arity(rb, grp ? "xreadgroup" : "xread"); return; }
        if (grp && readonly()) return;
        int64_t timeout = -1, count = 0;
        int sarg = 0, ns = 0;
        bool noack = false, has_group = false;
        sv gname, cname;
        for (int i = 1; i < argc; ++i)
        {
            const int more = argc - i - 1;
            const sv  o = a[i];
            if (ieq(o, "block") && more)
            {
#ifndef SOCKETLEY_NO_LUA
                if (ci.m_script_depth > 0)
                {
                    rb.append("-ERR ");
                    resp::append_one_line(rb, a[0]);
                    rb.append(" command is not allowed with BLOCK option from scripts\r\n");
                    return;
                }
#endif
                ++i;
                if (!stream_strict_ll(a[i], timeout)) { err(rb, "timeout is not an integer or out of range"); return; }
                if (timeout < 0) { err(rb, "timeout is negative"); return; }
            }
            else if (ieq(o, "count") && more)
            {
                ++i;
                if (!stream_strict_ll(a[i], count)) { err(rb, not_int); return; }
                if (count < 0) count = 0;
            }
            else if (ieq(o, "streams") && more)
            {
                sarg = i + 1;
                ns = argc - sarg;
                if (ns % 2)
                {
                    err(rb, "Unbalanced XREAD list of streams: for each stream key an ID or '$' must be specified.");
                    return;
                }
                ns /= 2;
                break;
            }
            else if (ieq(o, "group") && more >= 2)
            {
                if (!grp) { err(rb, "The GROUP option is only supported by XREADGROUP. You called XREAD instead."); return; }
                gname = a[i + 1];
                cname = a[i + 2];
                has_group = true;
                i += 2;
            }
            else if (ieq(o, "noack"))
            {
                if (!grp) { err(rb, "The NOACK option is only supported by XREADGROUP. You called XREAD instead."); return; }
                noack = true;
            }
            else { err(rb, syntax); return; }
        }
        if (sarg == 0) { err(rb, syntax); return; }
        if (grp && !has_group) { err(rb, "Missing GROUP option for XREADGROUP"); return; }

        std::vector<stream_id> ids(static_cast<size_t>(ns));
        std::vector<group*> groups(has_group ? static_cast<size_t>(ns) : 0);
        for (int i = 0; i < ns; ++i)
        {
            const sv key = a[sarg + i], ida = a[sarg + ns + i];
            bool bad = false;
            stream_inner* s = lookup(key, bad);
            if (bad) return;
            if (has_group)
            {
                group* g = s ? s->find_group(gname) : nullptr;
                if (!g)
                {
                    rb.append("-NOGROUP No such key '");
                    resp::append_one_line(rb, key);
                    rb.append("' or consumer group '");
                    resp::append_one_line(rb, gname);
                    rb.append("' in XREADGROUP with GROUP option\r\n");
                    return;
                }
                groups[static_cast<size_t>(i)] = g;
            }
            stream_id& id = ids[static_cast<size_t>(i)];
            if (ida == "$")
            {
                if (grp)
                {
                    err(rb, "The $ ID is meaningless in the context of XREADGROUP: you want to read the "
                            "history of this consumer by specifying a proper ID, or use the > ID to get "
                            "new messages. The $ ID would just return an empty result set.");
                    return;
                }
                id = s ? s->last_id() : stream_id{};
                continue;
            }
            if (ida == ">")
            {
                if (!grp)
                {
                    err(rb, "The > ID can be specified only when calling XREADGROUP using the GROUP "
                            "<group> <consumer> option.");
                    return;
                }
                id = stream_id::max();
                continue;
            }
            if (!stream_parse_id(ida, id, 0, true, nullptr)) { err(rb, bad_id); return; }
        }

        std::string body;
        int served = 0;
        for (int i = 0; i < ns; ++i)
        {
            const sv key = a[sarg + i];
            stream_inner* s = ci.m_store.stream_find(key);
            if (!s) continue;
            stream_id gt = ids[static_cast<size_t>(i)];
            bool sync = false, history = false;
            group* g = has_group ? groups[static_cast<size_t>(i)] : nullptr;
            if (g)
            {
                if (gt != stream_id::max()) sync = history = true;
                else if (s->size() && s->last_live() > g->last) { sync = true; gt = g->last; }
            }
            else if (s->size() && s->last_live() > gt)
                sync = true;
            if (!sync) continue;
            ++served;
            ci.m_store.stream_get(key);
            serve(key, *s, gt, static_cast<uint64_t>(count), g, gname, cname, noack, history, body);
        }
        if (served)
        {
            resp::encode_array_header_into(rb, served);
            rb.append(body);
            return;
        }
        if (timeout == -1 || conn->in_exec) { put_null_array(rb); return; }
        if (conn->fd < 0 || conn == ci.m_request_conn.get())
        {
            rb.append("-ERR ");
            resp::append_one_line(rb, a[0]);
            rb.append(" BLOCK needs a connection to wait on, and a cross-runtime request has none\r\n");
            return;
        }
        ci.block_stream(conn, a + sarg, ids.data(), static_cast<size_t>(ns), gname, cname,
                        static_cast<uint64_t>(count), noack, timeout);
    }

    // ─── XDEL, XTRIM ────────────────────────────────────────────────────────

    void xdel(sv* a, int argc)
    {
        if (argc < 3) { err_arity(rb, "xdel"); return; }
        if (readonly()) return;
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        if (!s) { resp::encode_integer_into(rb, 0); return; }
        std::vector<stream_id> ids(static_cast<size_t>(argc - 2));
        for (int j = 2; j < argc; ++j)
            if (!stream_parse_id(a[j], ids[static_cast<size_t>(j - 2)], 0, true, nullptr)) { err(rb, bad_id); return; }
        int64_t deleted = 0;
        ci.m_store.stream_change(a[1], *s, [&](stream_inner& st) {
            for (const stream_id& id : ids) if (st.erase(id)) ++deleted;
        });
        resp::encode_integer_into(rb, deleted);
        if (deleted && logging())
        {
            std::vector<sv> r(a, a + argc);
            r[0] = "XDEL";
            ci.stream_repl(a[1], r.data(), r.size());
        }
    }

    void xtrim(sv* a, int argc)
    {
        if (argc < 4) { err_arity(rb, "xtrim"); return; }
        if (readonly()) return;
        trim_args t;
        if (parse_trim(a, argc, false, t, rb) < 0) return;
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        if (!s) { resp::encode_integer_into(rb, 0); return; }
        uint64_t deleted = 0;
        ci.m_store.stream_change(a[1], *s, [&](stream_inner& st) { deleted = st.trim(t.spec); });
        resp::encode_integer_into(rb, static_cast<int64_t>(deleted));
        if (deleted && logging())
        {
            const std::string len = std::to_string(s->size());
            ci.stream_repl(a[1], { "XTRIM", a[1], "MAXLEN", "=", len });
        }
    }

    // ─── XGROUP ─────────────────────────────────────────────────────────────

    void xgroup(sv* a, int argc)
    {
        if (argc < 2) { err_arity(rb, "xgroup"); return; }
        const sv sub = a[1];
        const bool create = ieq(sub, "create"), setid = ieq(sub, "setid"), destroy = ieq(sub, "destroy"),
                   mkcons = ieq(sub, "createconsumer"), delcons = ieq(sub, "delconsumer"),
                   help = ieq(sub, "help");
        if (!(create || setid || destroy || mkcons || delcons || help))
        {
            err_subcommand(rb, sub, "XGROUP");
            return;
        }
        const bool arity_ok = create || setid ? argc >= 5 : destroy ? argc == 4 : help ? argc == 2 : argc == 5;
        if (!arity_ok)
        {
            const std::string n = std::string("xgroup|") + (create ? "create" : setid ? "setid"
                                  : destroy ? "destroy" : mkcons ? "createconsumer"
                                  : delcons ? "delconsumer" : "help");
            err_arity(rb, n);
            return;
        }
        if (help)
        {
            static constexpr sv lines[] = {
                "XGROUP <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
                "CREATE <key> <groupname> <id|$> [option]",
                "    Create a new consumer group. Options are:",
                "    * MKSTREAM",
                "      Create the empty stream if it does not exist.",
                "    * ENTRIESREAD entries_read",
                "      Set the group's entries_read counter (internal use).",
                "CREATECONSUMER <key> <groupname> <consumer>",
                "    Create a new consumer in the specified group.",
                "DELCONSUMER <key> <groupname> <consumer>",
                "    Remove the specified consumer.",
                "DESTROY <key> <groupname>",
                "    Remove the specified group.",
                "SETID <key> <groupname> <id|$> [ENTRIESREAD entries_read]",
                "    Set the current group ID and entries_read counter.",
                "HELP",
                "    Prints this help.",
            };
            resp::encode_array_header_into(rb, static_cast<int>(std::size(lines)));
            for (sv l : lines) resp::encode_simple_into(rb, l);
            return;
        }
        if (readonly()) return;

        bool mkstream = false;
        int64_t entries_read = -1;
        for (int i = 5; i < argc;)
        {
            if (create && ieq(a[i], "mkstream")) { mkstream = true; ++i; }
            else if ((create || setid) && ieq(a[i], "entriesread") && i + 1 < argc)
            {
                if (!stream_strict_ll(a[i + 1], entries_read)) { err(rb, not_int); return; }
                if (entries_read < 0 && entries_read != -1)
                {
                    err(rb, "value for ENTRIESREAD must be positive or -1");
                    return;
                }
                i += 2;
            }
            else { err_subcommand_syntax(rb, sub, "XGROUP"); return; }
        }

        const sv key = a[2], gname = a[3];
        bool bad = false;
        stream_inner* s = lookup(key, bad);
        if (bad) return;
        group* g = s ? s->find_group(gname) : nullptr;
        if (!mkstream)
        {
            if (!s)
            {
                err(rb, "The XGROUP subcommand requires the key to exist. Note that for CREATE you may "
                        "want to use the MKSTREAM option to create an empty stream automatically.");
                return;
            }
            if (!g && (setid || mkcons || delcons)) { nogroup_for(gname, key); return; }
        }

        if (create)
        {
            if (argc > 8) { err_subcommand_syntax(rb, sub, "XGROUP"); return; }
            stream_id id;
            if (a[4] == "$") id = s ? s->last_id() : stream_id{};
            else if (!stream_parse_id(a[4], id, 0, true, nullptr)) { err(rb, bad_id); return; }
            const bool made = !s;
            if (made)
                s = ci.m_store.stream_make(key, stream_inner{}.group_growth(gname));
            else if (!g)
                s = ci.m_store.stream_admit(key, s->group_growth(gname)) ? ci.m_store.stream_find(key) : nullptr;
            if (!s) { err_code(rb, oom); return; }
            bool fresh = false;
            ci.m_store.stream_change(key, *s, [&](stream_inner& st) {
                fresh = st.create_group(gname, id, entries_read) != nullptr;
            });
            if (!fresh) { err_code(rb, "BUSYGROUP Consumer Group name already exists"); return; }
            resp::encode_ok_into(rb);
            if (logging())
            {
                const std::string ids = id_text(id), er = std::to_string(entries_read);
                if (made) ci.stream_repl(key, { "XGROUP", "CREATE", key, gname, ids, "MKSTREAM", "ENTRIESREAD", er });
                else      ci.stream_repl(key, { "XGROUP", "CREATE", key, gname, ids, "ENTRIESREAD", er });
            }
            return;
        }
        if (setid)
        {
            if (argc != 5 && argc != 7) { err_subcommand_syntax(rb, sub, "XGROUP"); return; }
            stream_id id;
            if (a[4] == "$") id = s->last_id();
            else if (!stream_parse_id(a[4], id, 0, false, nullptr)) { err(rb, bad_id); return; }
            g->last = id;
            g->entries_read = entries_read;
            ci.m_store.stream_get(key);
            resp::encode_ok_into(rb);
            repl_group(key, gname, *g);
            return;
        }
        if (destroy)
        {
            bool gone = false;
            if (g) ci.m_store.stream_change(key, *s, [&](stream_inner& st) { gone = st.destroy_group(gname); });
            resp::encode_integer_into(rb, gone ? 1 : 0);
            if (gone)
            {
                if (logging()) ci.stream_repl(key, { "XGROUP", "DESTROY", key, gname });
                ci.stream_signal(key);
            }
            return;
        }
        if (mkcons)
        {
            if (!ci.m_store.stream_admit(key, stream_log::consumer_growth(a[4]))) { err_code(rb, oom); return; }
            s = ci.m_store.stream_find(key);
            g = s->find_group(gname);
            bool made = false;
            ci.m_store.stream_change(key, *s, [&](stream_inner& st) {
                made = st.create_consumer(*g, a[4], socketley::wall::now_ms()) != nullptr;
            });
            resp::encode_integer_into(rb, made ? 1 : 0);
            if (made && logging()) ci.stream_repl(key, { "XGROUP", "CREATECONSUMER", key, gname, a[4] });
            return;
        }
        int64_t pending = -1;
        ci.m_store.stream_change(key, *s, [&](stream_inner& st) { pending = st.delete_consumer(*g, a[4]); });
        resp::encode_integer_into(rb, pending < 0 ? 0 : pending);
        if (pending >= 0 && logging()) ci.stream_repl(key, { "XGROUP", "DELCONSUMER", key, gname, a[4] });
    }

    // ─── XSETID ─────────────────────────────────────────────────────────────

    void xsetid(sv* a, int argc)
    {
        if (argc < 3) { err_arity(rb, "xsetid"); return; }
        if (readonly()) return;
        stream_id id, maxdel;
        int64_t added = -1;
        if (!stream_parse_id(a[2], id, 0, true, nullptr)) { err(rb, bad_id); return; }
        for (int i = 3; i < argc;)
        {
            const int more = argc - 1 - i;
            if (ieq(a[i], "entriesadded") && more)
            {
                if (!stream_strict_ll(a[i + 1], added)) { err(rb, not_int); return; }
                if (added < 0) { err(rb, "entries_added must be positive"); return; }
                i += 2;
            }
            else if (ieq(a[i], "maxdeletedid") && more)
            {
                if (!stream_parse_id(a[i + 1], maxdel, 0, true, nullptr)) { err(rb, bad_id); return; }
                if (id < maxdel)
                {
                    err(rb, "The ID specified in XSETID is smaller than the provided max_deleted_entry_id");
                    return;
                }
                i += 2;
            }
            else { err(rb, syntax); return; }
        }
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        if (!s) { err(rb, "no such key"); return; }
        if (s->size() > 0)
        {
            if (id < s->last_live())
            {
                err(rb, "The ID specified in XSETID is smaller than the target stream top item");
                return;
            }
            if (added != -1 && s->size() > static_cast<uint64_t>(added))
            {
                err(rb, "The entries_added specified in XSETID is smaller than the target stream length");
                return;
            }
        }
        s->set_last(id);
        if (added != -1) s->set_entries_added(static_cast<uint64_t>(added));
        if (!maxdel.is_zero()) s->set_max_deleted(maxdel);
        ci.m_store.stream_get(a[1]);
        resp::encode_ok_into(rb);
        if (logging())
        {
            std::vector<sv> r(a, a + argc);
            r[0] = "XSETID";
            ci.stream_repl(a[1], r.data(), r.size());
        }
    }

    // ─── XACK ───────────────────────────────────────────────────────────────

    void xack(sv* a, int argc)
    {
        if (argc < 4) { err_arity(rb, "xack"); return; }
        if (readonly()) return;
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { resp::encode_integer_into(rb, 0); return; }
        std::vector<stream_id> ids(static_cast<size_t>(argc - 3));
        for (int j = 3; j < argc; ++j)
            if (!stream_parse_id(a[j], ids[static_cast<size_t>(j - 3)], 0, true, nullptr)) { err(rb, bad_id); return; }
        int64_t acked = 0;
        ci.m_store.stream_change(a[1], *s, [&](stream_inner& st) {
            for (const stream_id& id : ids) if (st.ack(*g, id)) ++acked;
        });
        resp::encode_integer_into(rb, acked);
        if (acked && logging())
        {
            std::vector<sv> r(a, a + argc);
            r[0] = "XACK";
            ci.stream_repl(a[1], r.data(), r.size());
        }
    }

    // ─── XPENDING ───────────────────────────────────────────────────────────

    void xpending(sv* a, int argc)
    {
        if (argc < 3) { err_arity(rb, "xpending"); return; }
        const bool summary = argc == 3;
        if (argc != 3 && (argc < 6 || argc > 9)) { err(rb, syntax); return; }
        stream_id lo, hi;
        int64_t count = 0, minidle = 0;
        sv cname;
        bool has_consumer = false;
        if (argc >= 6)
        {
            int at = 3;
            if (ieq(a[3], "idle"))
            {
                if (!stream_strict_ll(a[4], minidle)) { err(rb, not_int); return; }
                if (argc < 8) { err(rb, syntax); return; }
                at += 2;
            }
            if (!stream_strict_ll(a[at + 2], count)) { err(rb, not_int); return; }
            if (count < 0) count = 0;
            bool lox = false, hix = false;
            if (!parse_interval(a[at], lo, lox, 0)) { err(rb, bad_id); return; }
            if (lox && !lo.incr()) { err(rb, "invalid start ID for the interval"); return; }
            if (!parse_interval(a[at + 1], hi, hix, UINT64_MAX)) { err(rb, bad_id); return; }
            if (hix && !hi.decr()) { err(rb, "invalid end ID for the interval"); return; }
            if (at + 3 < argc) { cname = a[at + 3]; has_consumer = true; }
        }
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { nogroup_key(a[1], a[2]); return; }
        ci.m_store.stream_get(a[1]);

        if (summary)
        {
            rb.append("*4\r\n", 4);
            resp::encode_integer_into(rb, static_cast<int64_t>(g->pel.size()));
            if (g->pel.empty()) { put_null(rb); put_null(rb); put_null_array(rb); return; }
            put_id(rb, g->pel.begin()->first);
            put_id(rb, std::prev(g->pel.end())->first);
            int n = 0;
            for (const auto& [name, c] : g->consumers) if (!c.pel.empty()) ++n;
            resp::encode_array_header_into(rb, n);
            for (const auto& [name, c] : g->consumers)
            {
                if (c.pel.empty()) continue;
                rb.append("*2\r\n", 4);
                resp::encode_bulk_into(rb, name);
                resp::encode_bulk_into(rb, std::to_string(c.pel.size()));
            }
            return;
        }

        consumer* only = nullptr;
        if (has_consumer)
        {
            only = s->find_consumer(*g, cname);
            if (!only) { rb.append("*0\r\n", 4); return; }
        }
        const int64_t now = socketley::wall::now_ms();
        std::string& body = ci.m_stream_scratch;
        body.clear();
        int n = 0;
        const auto one = [&](stream_id id, const stream_log::nack& nk) {
            if (minidle && now - nk.delivery_ms < minidle) return;
            ++n;
            --count;
            body.append("*4\r\n", 4);
            put_id(body, id);
            resp::encode_bulk_into(body, nk.owner ? nk.owner->name : sv{});
            const int64_t idle = now - nk.delivery_ms;
            resp::encode_integer_into(body, idle < 0 ? 0 : idle);
            resp::encode_integer_into(body, static_cast<int64_t>(nk.count));
        };
        if (only)
        {
            for (auto it = only->pel.lower_bound(lo); count && it != only->pel.end() && *it <= hi; ++it)
                one(*it, g->pel.find(*it)->second);
        }
        else
        {
            for (auto it = g->pel.lower_bound(lo); count && it != g->pel.end() && it->first <= hi; ++it)
                one(it->first, it->second);
        }
        resp::encode_array_header_into(rb, n);
        rb.append(body);
    }

    // ─── XCLAIM, XAUTOCLAIM ─────────────────────────────────────────────────

    void xclaim(sv* a, int argc)
    {
        if (argc < 6) { err_arity(rb, "xclaim"); return; }
        if (readonly()) return;
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { nogroup_key(a[1], a[2]); return; }
        int64_t minidle = 0;
        if (!stream_strict_ll(a[4], minidle)) { err(rb, "Invalid min-idle-time argument for XCLAIM"); return; }
        if (minidle < 0) minidle = 0;
        std::vector<stream_id> ids;
        int j = 5;
        for (; j < argc; ++j)
        {
            stream_id id;
            if (!stream_parse_id(a[j], id, 0, true, nullptr)) break;
            ids.push_back(id);
        }
        const int64_t now = socketley::wall::now_ms();
        int64_t delivery = -1, retry = -1;
        bool force = false, justid = false;
        stream_id lastid;
        for (; j < argc; ++j)
        {
            const int more = argc - 1 - j;
            const sv o = a[j];
            if (ieq(o, "force")) force = true;
            else if (ieq(o, "justid")) justid = true;
            else if (ieq(o, "idle") && more)
            {
                if (!stream_strict_ll(a[++j], delivery)) { err(rb, "Invalid IDLE option argument for XCLAIM"); return; }
                delivery = now - delivery;
            }
            else if (ieq(o, "time") && more)
            {
                if (!stream_strict_ll(a[++j], delivery)) { err(rb, "Invalid TIME option argument for XCLAIM"); return; }
            }
            else if (ieq(o, "retrycount") && more)
            {
                if (!stream_strict_ll(a[++j], retry)) { err(rb, "Invalid RETRYCOUNT option argument for XCLAIM"); return; }
            }
            else if (ieq(o, "lastid") && more)
            {
                if (!stream_parse_id(a[++j], lastid, 0, true, nullptr)) { err(rb, bad_id); return; }
            }
            else
            {
                rb.append("-ERR Unrecognized XCLAIM option '");
                resp::append_one_line(rb, o);
                rb.append("'\r\n");
                return;
            }
        }
        if (delivery == -1 || delivery < 0 || delivery > now) delivery = now;

        std::string& body = ci.m_stream_scratch;
        body.clear();
        int n = 0;
        const sv key = a[1], gname = a[2], cname = a[3];
        ci.m_store.stream_change(key, *s, [&](stream_inner& st) {
            const bool moved = lastid > g->last;
            if (moved) g->last = lastid;
            consumer* c = nullptr;
            for (const stream_id& id : ids)
            {
                stream_log::nack* nk = st.find_nack(*g, id);
                stream_log::entry e;
                if (!st.find(id, e))
                {
                    if (nk)
                    {
                        st.ack(*g, id);
                        if (logging()) { const std::string t = id_text(id); ci.stream_repl(key, { "XACK", key, gname, t }); }
                    }
                    continue;
                }
                if (force && !nk) nk = &st.force_nack(*g, id, now);
                if (!nk) continue;
                if (nk->owner && minidle && now - nk->delivery_ms < minidle) continue;
                if (!c)
                {
                    c = st.find_consumer(*g, cname);
                    if (!c) c = st.create_consumer(*g, cname, now);
                    c->seen_ms = now;
                }
                st.move_nack(id, *nk, *c);
                nk->delivery_ms = delivery;
                if (retry >= 0) nk->count = static_cast<uint64_t>(retry);
                else if (!justid) ++nk->count;
                if (justid) put_id(body, id);
                else        put_entry(body, e);
                ++n;
                c->active_ms = now;
                repl_nack(key, gname, cname, id, *nk);
            }
            if (c) repl_consumer(key, gname, *c);
            if (moved) repl_group(key, gname, *g);
        });
        resp::encode_array_header_into(rb, n);
        rb.append(body);
    }

    void xautoclaim(sv* a, int argc)
    {
        if (argc < 6) { err_arity(rb, "xautoclaim"); return; }
        if (readonly()) return;
        int64_t minidle = 0;
        if (!stream_strict_ll(a[4], minidle)) { err(rb, "Invalid min-idle-time argument for XAUTOCLAIM"); return; }
        if (minidle < 0) minidle = 0;
        stream_id start;
        bool ex = false;
        if (!parse_interval(a[5], start, ex, 0)) { err(rb, bad_id); return; }
        if (ex && !start.incr()) { err(rb, "invalid start ID for the interval"); return; }
        int64_t count = 100;
        bool justid = false;
        for (int j = 6; j < argc; ++j)
        {
            const int more = argc - 1 - j;
            if (ieq(a[j], "count") && more)
            {
                if (!stream_strict_ll(a[j + 1], count) || count < 1 || count > INT64_MAX / 16)
                {
                    err(rb, "COUNT must be > 0");
                    return;
                }
                ++j;
            }
            else if (ieq(a[j], "justid")) justid = true;
            else { err(rb, syntax); return; }
        }
        bool bad = false;
        stream_inner* s = lookup(a[1], bad);
        if (bad) return;
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { nogroup_key(a[1], a[2]); return; }

        const sv key = a[1], gname = a[2], cname = a[3];
        const int64_t now = socketley::wall::now_ms();
        std::string& body = ci.m_stream_scratch;
        body.clear();
        std::vector<stream_id> deleted;
        int n = 0;
        stream_id next;
        ci.m_store.stream_change(key, *s, [&](stream_inner& st) {
            int64_t attempts = count * 10;
            consumer* c = nullptr;
            auto it = g->pel.lower_bound(start);
            while (attempts-- > 0 && count > 0 && it != g->pel.end())
            {
                const stream_id id = it->first;
                stream_log::nack& nk = it->second;
                ++it;
                stream_log::entry e;
                if (!st.find(id, e))
                {
                    st.ack(*g, id);
                    deleted.push_back(id);
                    --count;
                    if (logging()) { const std::string t = id_text(id); ci.stream_repl(key, { "XACK", key, gname, t }); }
                    continue;
                }
                if (minidle && now - nk.delivery_ms < minidle) continue;
                if (!c)
                {
                    c = st.find_consumer(*g, cname);
                    if (!c) c = st.create_consumer(*g, cname, now);
                    c->seen_ms = now;
                }
                st.move_nack(id, nk, *c);
                nk.delivery_ms = now;
                if (!justid) ++nk.count;
                if (justid) put_id(body, id);
                else        put_entry(body, e);
                ++n;
                --count;
                c->active_ms = now;
                repl_nack(key, gname, cname, id, nk);
            }
            if (it != g->pel.end()) next = it->first;
            if (c) repl_consumer(key, gname, *c);
        });
        rb.append("*3\r\n", 4);
        put_id(rb, next);
        resp::encode_array_header_into(rb, n);
        rb.append(body);
        resp::encode_array_header_into(rb, static_cast<int>(deleted.size()));
        for (const stream_id& id : deleted) put_id(rb, id);
    }

    // ─── XINFO ──────────────────────────────────────────────────────────────

    void put_group_lag(std::string& out, const stream_inner& s, const group& g)
    {
        int64_t lag = 0;
        if (s.lag(g, lag)) resp::encode_integer_into(out, lag);
        else               put_null(out);
    }

    void put_entries_read(std::string& out, const group& g)
    {
        if (g.entries_read != -1) resp::encode_integer_into(out, g.entries_read);
        else                      put_null(out);
    }

    void xinfo(sv* a, int argc)
    {
        if (argc < 2) { err_arity(rb, "xinfo"); return; }
        const sv sub = a[1];
        const bool cons = ieq(sub, "consumers"), grps = ieq(sub, "groups"), strm = ieq(sub, "stream"),
                   help = ieq(sub, "help");
        if (!(cons || grps || strm || help)) { err_subcommand(rb, sub, "XINFO"); return; }
        const bool arity_ok = cons ? argc == 4 : grps ? argc == 3 : strm ? argc >= 3 : argc == 2;
        if (!arity_ok)
        {
            err_arity(rb, cons ? "xinfo|consumers" : grps ? "xinfo|groups" : strm ? "xinfo|stream" : "xinfo|help");
            return;
        }
        if (help)
        {
            static constexpr sv lines[] = {
                "XINFO <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
                "CONSUMERS <key> <groupname>",
                "    Show consumers of <groupname>.",
                "GROUPS <key>",
                "    Show the stream consumer groups.",
                "STREAM <key> [FULL [COUNT <count>]",
                "    Show information about the stream.",
                "HELP",
                "    Prints this help.",
            };
            resp::encode_array_header_into(rb, static_cast<int>(std::size(lines)));
            for (sv l : lines) resp::encode_simple_into(rb, l);
            return;
        }
        bool bad = false;
        stream_inner* s = lookup(a[2], bad);
        if (bad) return;
        if (!s) { err(rb, "no such key"); return; }
        ci.m_store.stream_get(a[2]);
        const int64_t now = socketley::wall::now_ms();

        if (cons)
        {
            const group* g = s->find_group(a[3]);
            if (!g) { nogroup_for(a[3], a[2]); return; }
            resp::encode_array_header_into(rb, static_cast<int>(g->consumers.size()));
            for (const auto& [name, c] : g->consumers)
            {
                const int64_t idle = now - c.seen_ms;
                rb.append("*6\r\n", 4);
                resp::encode_bulk_into(rb, "name");
                resp::encode_bulk_into(rb, name);
                resp::encode_bulk_into(rb, "pending");
                resp::encode_integer_into(rb, static_cast<int64_t>(c.pel.size()));
                resp::encode_bulk_into(rb, "idle");
                resp::encode_integer_into(rb, idle < 0 ? 0 : idle);
            }
            return;
        }
        if (grps)
        {
            if (!s->groups()) { rb.append("*0\r\n", 4); return; }
            resp::encode_array_header_into(rb, static_cast<int>(s->group_count()));
            for (const auto& [name, g] : *s->groups())
            {
                resp::encode_array_header_into(rb, 12);
                resp::encode_bulk_into(rb, "name");
                resp::encode_bulk_into(rb, name);
                resp::encode_bulk_into(rb, "consumers");
                resp::encode_integer_into(rb, static_cast<int64_t>(g.consumers.size()));
                resp::encode_bulk_into(rb, "pending");
                resp::encode_integer_into(rb, static_cast<int64_t>(g.pel.size()));
                resp::encode_bulk_into(rb, "last-delivered-id");
                put_id(rb, g.last);
                resp::encode_bulk_into(rb, "entries-read");
                put_entries_read(rb, g);
                resp::encode_bulk_into(rb, "lag");
                put_group_lag(rb, *s, g);
            }
            return;
        }

        bool full = false;
        int64_t count = 10;
        const int optc = argc - 3;
        if (optc)
        {
            if ((optc != 1 && optc != 3) || !ieq(a[3], "full")
                || (optc == 3 && !ieq(a[4], "count")))
            {
                err_subcommand_syntax(rb, sub, "XINFO");
                return;
            }
            if (optc == 3)
            {
                if (!stream_strict_ll(a[5], count)) { err(rb, not_int); return; }
                if (count < 0) count = 10;
            }
            full = true;
        }
        const uint64_t cap = static_cast<uint64_t>(count);
        const size_t keys = s->block_count();
        resp::encode_array_header_into(rb, full ? 18 : 20);
        resp::encode_bulk_into(rb, "length");
        resp::encode_integer_into(rb, static_cast<int64_t>(s->size()));
        resp::encode_bulk_into(rb, "radix-tree-keys");
        resp::encode_integer_into(rb, static_cast<int64_t>(keys));
        resp::encode_bulk_into(rb, "radix-tree-nodes");
        resp::encode_integer_into(rb, static_cast<int64_t>(keys ? 2 * keys + 2 : 1));
        resp::encode_bulk_into(rb, "last-generated-id");
        put_id(rb, s->last_id());
        resp::encode_bulk_into(rb, "max-deleted-entry-id");
        put_id(rb, s->max_deleted());
        resp::encode_bulk_into(rb, "entries-added");
        resp::encode_integer_into(rb, static_cast<int64_t>(s->entries_added()));
        resp::encode_bulk_into(rb, "recorded-first-entry-id");
        put_id(rb, s->first_id());
        if (!full)
        {
            resp::encode_bulk_into(rb, "groups");
            resp::encode_integer_into(rb, static_cast<int64_t>(s->group_count()));
            for (const bool last : { false, true })
            {
                resp::encode_bulk_into(rb, last ? "last-entry" : "first-entry");
                bool any = false;
                s->walk({}, stream_id::max(), last, [&](const stream_log::entry& e) {
                    put_entry(rb, e);
                    any = true;
                    return false;
                });
                if (!any) put_null(rb);
            }
            return;
        }
        resp::encode_bulk_into(rb, "entries");
        std::string body;
        uint64_t n = 0;
        s->walk({}, stream_id::max(), false, [&](const stream_log::entry& e) {
            put_entry(body, e);
            ++n;
            return cap == 0 || n < cap;
        });
        resp::encode_array_header_into(rb, static_cast<int>(n));
        rb.append(body);
        resp::encode_bulk_into(rb, "groups");
        resp::encode_array_header_into(rb, static_cast<int>(s->group_count()));
        if (!s->groups()) return;
        for (const auto& [name, g] : *s->groups())
        {
            rb.append("*14\r\n", 5);
            resp::encode_bulk_into(rb, "name");
            resp::encode_bulk_into(rb, name);
            resp::encode_bulk_into(rb, "last-delivered-id");
            put_id(rb, g.last);
            resp::encode_bulk_into(rb, "entries-read");
            put_entries_read(rb, g);
            resp::encode_bulk_into(rb, "lag");
            put_group_lag(rb, *s, g);
            resp::encode_bulk_into(rb, "pel-count");
            resp::encode_integer_into(rb, static_cast<int64_t>(g.pel.size()));
            resp::encode_bulk_into(rb, "pending");
            const uint64_t pn = cap && g.pel.size() > cap ? cap : g.pel.size();
            resp::encode_array_header_into(rb, static_cast<int>(pn));
            uint64_t k = 0;
            for (auto it = g.pel.begin(); it != g.pel.end() && k < pn; ++it, ++k)
            {
                rb.append("*4\r\n", 4);
                put_id(rb, it->first);
                resp::encode_bulk_into(rb, it->second.owner ? it->second.owner->name : sv{});
                resp::encode_integer_into(rb, it->second.delivery_ms);
                resp::encode_integer_into(rb, static_cast<int64_t>(it->second.count));
            }
            resp::encode_bulk_into(rb, "consumers");
            resp::encode_array_header_into(rb, static_cast<int>(g.consumers.size()));
            for (const auto& [cn, c] : g.consumers)
            {
                rb.append("*8\r\n", 4);
                resp::encode_bulk_into(rb, "name");
                resp::encode_bulk_into(rb, cn);
                resp::encode_bulk_into(rb, "seen-time");
                resp::encode_integer_into(rb, c.seen_ms);
                resp::encode_bulk_into(rb, "pel-count");
                resp::encode_integer_into(rb, static_cast<int64_t>(c.pel.size()));
                resp::encode_bulk_into(rb, "pending");
                const uint64_t cn_n = cap && c.pel.size() > cap ? cap : c.pel.size();
                resp::encode_array_header_into(rb, static_cast<int>(cn_n));
                uint64_t m = 0;
                for (auto it = c.pel.begin(); it != c.pel.end() && m < cn_n; ++it, ++m)
                {
                    const stream_log::nack& nk = g.pel.find(*it)->second;
                    rb.append("*3\r\n", 4);
                    put_id(rb, *it);
                    resp::encode_integer_into(rb, nk.delivery_ms);
                    resp::encode_integer_into(rb, static_cast<int64_t>(nk.count));
                }
            }
        }
    }

    // ─── The two verbs only a replication record may carry ──────────────────

    // XNACK key group consumer id delivery-ms count: one pending entry, exactly.
    void xnack(sv* a, int argc)
    {
        stream_id id;
        int64_t when = 0, count = 0;
        if (argc != 7 || !stream_parse_id(a[4], id, 0, true, nullptr)
            || !stream_strict_ll(a[5], when) || !stream_strict_ll(a[6], count) || count < 0)
        { err(rb, syntax); return; }
        stream_inner* s = ci.m_store.stream_find(a[1]);
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { nogroup_key(a[1], a[2]); return; }
        ci.m_store.stream_change(a[1], *s, [&](stream_inner& st) {
            consumer* c = st.find_consumer(*g, a[3]);
            if (!c) c = st.create_consumer(*g, a[3], when);
            stream_log::nack& nk = st.force_nack(*g, id, when);
            st.move_nack(id, nk, *c);
            nk.delivery_ms = when;
            nk.count = static_cast<uint64_t>(count);
        });
        resp::encode_ok_into(rb);
    }

    // XCONSUMER key group consumer seen-ms active-ms: one consumer's clocks, exactly.
    void xconsumer(sv* a, int argc)
    {
        int64_t seen = 0, active = 0;
        if (argc != 6 || !stream_strict_ll(a[4], seen) || !stream_strict_ll(a[5], active))
        { err(rb, syntax); return; }
        stream_inner* s = ci.m_store.stream_find(a[1]);
        group* g = s ? s->find_group(a[2]) : nullptr;
        if (!g) { nogroup_key(a[1], a[2]); return; }
        ci.m_store.stream_change(a[1], *s, [&](stream_inner& st) {
            consumer* c = st.find_consumer(*g, a[3]);
            if (!c) c = st.create_consumer(*g, a[3], seen);
            c->seen_ms = seen;
            c->active_ms = active;
        });
        resp::encode_ok_into(rb);
    }
};

// ─── Dispatch ───────────────────────────────────────────────────────────────

void cache_instance::stream_command(client_connection* conn, uint32_t h, std::string_view* args,
                                    int argc, std::string& rb)
{
    stream_commands x{ *this, rb };
    switch (h)
    {
        case fnv1a("xadd"):       x.xadd(args, argc); break;
        case fnv1a("xrange"):     x.xrange(args, argc, false); break;
        case fnv1a("xrevrange"):  x.xrange(args, argc, true); break;
        case fnv1a("xlen"):       x.xlen(args, argc); break;
        case fnv1a("xread"):      x.xread(conn, args, argc, false); break;
        case fnv1a("xreadgroup"): x.xread(conn, args, argc, true); break;
        case fnv1a("xdel"):       x.xdel(args, argc); break;
        case fnv1a("xtrim"):      x.xtrim(args, argc); break;
        case fnv1a("xgroup"):     x.xgroup(args, argc); break;
        case fnv1a("xsetid"):     x.xsetid(args, argc); break;
        case fnv1a("xack"):       x.xack(args, argc); break;
        case fnv1a("xpending"):   x.xpending(args, argc); break;
        case fnv1a("xclaim"):     x.xclaim(args, argc); break;
        case fnv1a("xautoclaim"): x.xautoclaim(args, argc); break;
        case fnv1a("xinfo"):      x.xinfo(args, argc); break;
        case fnv1a("xnack"):
        case fnv1a("xconsumer"):
            if (m_stream_internal)
            {
                if (h == fnv1a("xnack")) x.xnack(args, argc);
                else                     x.xconsumer(args, argc);
                break;
            }
            [[fallthrough]];
        default:
            rb.append("-ERR unknown command '");
            resp::append_one_line(rb, args[0]);
            rb.append("'\r\n");
            break;
    }
}

// ─── The line protocol ──────────────────────────────────────────────────────

namespace
{

// One RESP value flattened onto a line, words separated by spaces.
bool flatten(std::string_view& p, std::string& line)
{
    if (p.empty()) return false;
    const char t = p.front();
    const size_t nl = p.find("\r\n");
    if (nl == std::string_view::npos) return false;
    const std::string_view head = p.substr(1, nl - 1);
    p.remove_prefix(nl + 2);
    const auto word = [&](std::string_view w) { if (!line.empty()) line.push_back(' '); line.append(w); };
    long long n = 0;
    std::from_chars(head.data(), head.data() + head.size(), n);
    switch (t)
    {
        case '+': case ':': case '-': word(head); return true;
        case '$':
            if (n < 0) { word("nil"); return true; }
            if (p.size() < static_cast<size_t>(n) + 2) return false;
            word(p.substr(0, static_cast<size_t>(n)));
            p.remove_prefix(static_cast<size_t>(n) + 2);
            return true;
        case '*':
            if (n < 0) { word("nil"); return true; }
            for (long long i = 0; i < n; ++i) if (!flatten(p, line)) return false;
            return true;
        default: return false;
    }
}

}   // namespace

// A RESP reply in the line protocol's words: a value on its line, an array one
// element a line and then "end", and an XREAD's streams one entry a line, the
// stream's name first.
static void resp_to_text(std::string_view p, std::string& out, bool per_entry)
{
    if (p.empty()) return;
    if (p[0] == '-')
    {
        std::string_view m = p.substr(1, p.find("\r\n") - 1);
        if (m.substr(0, 4) == "ERR ") m.remove_prefix(4);
        if (m.substr(0, 10) == "WRONGTYPE ") m = "type conflict";
        out.append("error: ");
        out.append(m);
        out.push_back('\n');
        return;
    }
    if (p[0] == '+')
    {
        std::string_view m = p.substr(1, p.find("\r\n") - 1);
        out.append(m == "OK" ? std::string_view("ok") : m);
        out.push_back('\n');
        return;
    }
    if (p[0] != '*' || p.compare(0, 4, "*-1\r") == 0)
    {
        std::string line;
        flatten(p, line);
        out.append(line);
        out.push_back('\n');
        return;
    }
    const size_t nl = p.find("\r\n");
    long long n = 0;
    std::from_chars(p.data() + 1, p.data() + nl, n);
    p.remove_prefix(nl + 2);
    for (long long i = 0; i < n; ++i)
    {
        if (per_entry && p.compare(0, 4, "*2\r\n") == 0)
        {
            // One stream: its name, then each entry on a line of its own.
            p.remove_prefix(4);
            std::string key;
            if (!flatten(p, key)) return;
            const size_t hl = p.find("\r\n");
            long long m = 0;
            std::from_chars(p.data() + 1, p.data() + hl, m);
            p.remove_prefix(hl + 2);
            for (long long k = 0; k < m; ++k)
            {
                std::string line = key;
                if (!flatten(p, line)) return;
                out.append(line);
                out.push_back('\n');
            }
            continue;
        }
        std::string line;
        if (!flatten(p, line)) return;
        out.append(line);
        out.push_back('\n');
    }
    out.append("end\n", 4);
}

void cache_instance::stream_text(client_connection* conn, std::string_view cmd, std::string_view args)
{
    std::vector<std::string_view> a;
    a.push_back(cmd);
    uint32_t h = fnv1a_lower(cmd);
    const bool record = h == fnv1a("xapply");
    if (record)
    {
        // "xapply <key> <encoded arguments>": the key is only for routing.
        const size_t sp = args.find(' ');
        a.clear();
        if (sp == std::string_view::npos || !stream_args_decode(args.substr(sp + 1), a) || a.empty())
        {
            conn->response_buf.append("error: malformed stream record\n");
            return;
        }
        h = fnv1a_lower(a[0]);
    }
    else
    {
        while (!args.empty())
        {
            const size_t sp = args.find(' ');
            const std::string_view w = args.substr(0, sp);
            if (!w.empty()) a.push_back(w);
            if (sp == std::string_view::npos) break;
            args.remove_prefix(sp + 1);
        }
    }
    std::string reply;
    const bool was = m_stream_internal;
    m_stream_internal = record && m_applying_replicated;
    stream_command(conn, h, a.data(), static_cast<int>(a.size()), reply);
    m_stream_internal = was;
    if (conn->blocked) return;
    resp_to_text(reply, conn->response_buf, h == fnv1a("xread") || h == fnv1a("xreadgroup"));
}

// ─── The replication log ────────────────────────────────────────────────────

void cache_instance::stream_repl(std::string_view key, const std::string_view* a, size_t n)
{
    if (!mutation_log_wanted()) return;
    // The key leads the record unframed, so a space in it would move where the
    // follower reads it, the rule every other record here keeps too.
    if (SOCKETLEY_UNLIKELY(key.find(' ') != std::string_view::npos))
    {
        repl_unfaithful(key);
        return;
    }
    std::string rec;
    rec.reserve(8 + key.size() + 16 * n);
    rec.append("xapply ");
    rec.append(key);
    rec.push_back(' ');
    stream_args_encode(rec, a, n);
    replicate_command(rec);
}

// ─── Readers that wait ──────────────────────────────────────────────────────

void cache_instance::stream_signal(std::string_view key)
{
    if (SOCKETLEY_LIKELY(m_stream_wait_key.empty())) return;
    if (m_stream_wait_key.find(key) == m_stream_wait_key.end()) return;
    for (const auto& k : m_stream_ready) if (k == key) return;
    m_stream_ready.emplace_back(key);
}

void cache_instance::serve_stream_ready()
{
    // Again while a served reader's own pipeline added to a stream, bounded so
    // two clients feeding each other cannot hold the turn.
    for (int round = 0; round < 16 && !m_stream_ready.empty(); ++round)
    {
        std::vector<std::string> ready;
        ready.swap(m_stream_ready);
        for (const std::string& key : ready)
        {
            auto ki = m_stream_wait_key.find(key);
            if (ki == m_stream_wait_key.end()) continue;
            // Copied, because serving a reader takes it off the queue being walked.
            const std::vector<uint64_t> seqs(ki->second.begin(), ki->second.end());
            for (const uint64_t seq : seqs) serve_stream_waiter(seq, key);
        }
    }
}

void cache_instance::serve_stream_waiter(uint64_t seq, std::string_view key)
{
    auto bi = m_blocked.find(seq);
    if (bi == m_blocked.end()) return;
    const blocked_pop& w = bi->second;
    client_connection* c = (w.fd >= 0 && w.fd < MAX_FDS) ? m_conn_idx[w.fd] : nullptr;
    if (!c || c->closing || c->is_follower) { forget_waiter(seq); return; }

    size_t k = 0;
    while (k < w.keys.size() && w.keys[k] != key) ++k;
    if (k == w.keys.size()) return;

    std::string reply;
    if (m_has_ttl_keys) m_store.check_expiry(key);
    stream_inner* s = m_store.stream_find(key);
    if (!s)
    {
        // A group reader's key is gone, and with it the group it read.
        if (w.group.empty()) return;
        reply = "-UNBLOCKED the stream key no longer exists\r\n";
    }
    else
    {
        stream_id gt = w.after[k];
        stream_log::group* g = nullptr;
        if (!w.group.empty())
        {
            g = s->find_group(w.group);
            if (!g) reply = "-NOGROUP the consumer group this client was blocked on no longer exists\r\n";
            else    gt = g->last;
        }
        if (reply.empty())
        {
            if (!(s->last_id() > gt)) return;
            const std::string gname = w.group, cname = w.consumer;
            const uint64_t count = w.count;
            const bool noack = w.noack;
            reply.append("*1\r\n", 4);
            stream_commands x{ *this, reply };
            x.serve(key, *s, gt, count, g, gname, cname, noack, false, reply);
        }
    }
    forget_waiter(seq);
    deliver_late(c, reply);
}

void cache_instance::deliver_late(client_connection* c, std::string_view resp_reply)
{
    if (c->resp_mode)
        c->write_queue.push_coalesced(resp_reply, client_connection::WRITE_COALESCE_LIMIT);
    else
    {
        std::string text;
        resp_to_text(resp_reply, text, true);
        c->write_queue.push_coalesced(text, client_connection::WRITE_COALESCE_LIMIT);
    }
    c->blocked = false;
    if (!c->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(c)))
    {
        c->closing = true;
        return;
    }
    pump(c);
    if (SOCKETLEY_UNLIKELY(!flush_responses(c)))
        c->closing = true;
}

bool cache_instance::block_stream(client_connection* conn, const std::string_view* keys,
                                  const stream_id* ids, size_t n, std::string_view group,
                                  std::string_view consumer, uint64_t count, bool noack,
                                  int64_t timeout_ms)
{
    // One waiter per descriptor, block_pop()'s invariant for the same reason.
    if (SOCKETLEY_UNLIKELY(conn->blocked))
        return false;
    blocked_pop w;
    w.fd       = conn->fd;
    w.resp     = conn->resp_mode;
    w.seq      = ++m_block_seq;
    w.stream   = true;
    w.group    = group;
    w.consumer = consumer;
    w.count    = count ? count : 1000;          // Redis's XREAD_BLOCKED_DEFAULT_COUNT
    w.noack    = noack;
    for (size_t i = 0; i < n; ++i)
    {
        // A key named twice waits once, on its first id, as Redis's does.
        if (std::find(w.keys.begin(), w.keys.end(), keys[i]) != w.keys.end()) continue;
        w.keys.emplace_back(keys[i]);
        w.after.push_back(ids[i]);
    }
    // As BLPOP's: a wait past some thirty years would overflow the clock into the past.
    if (timeout_ms > 0 && timeout_ms < 1'000'000'000'000LL)
        w.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    const uint64_t seq = w.seq;
    blocked_pop& parked = m_blocked.emplace(seq, std::move(w)).first->second;
    if (parked.needs_tick())
        ++m_ticking_waiters;
    parked.slots.reserve(parked.keys.size());
    for (const auto& k : parked.keys)
    {
        auto& q = m_stream_wait_key[k];
        parked.slots.push_back(q.insert(q.end(), seq));
    }
    m_wait_fd[conn->fd] = seq;
    conn->blocked = true;
    arm_block_timer();
    return true;
}
