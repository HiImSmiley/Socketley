// Fuzz target: what a mail runtime reads from others (socketley/runtime/mail/).
//
// Reachable by any peer that can open a TCP connection to a mail runtime's SMTP port, and by any sender whose message
// one of its users reads over IMAP.  The first byte of an input chooses what it is:
//
//   0  bytes an SMTP client sends, in pieces cut where a 0xFF byte stands, to a session whose questions are answered
//      at once or later as the next byte says.  Every reply is whole lines of a three-digit code, and a message
//      taken holds no bare LF.
//   1  a message, parsed as IMAP reads it: every part lies inside it, every section asked of it is a slice
//      pointing into it or a header block made of its lines, and every literal ENVELOPE and BODYSTRUCTURE write
//      says its own length.
//   2  a message whose DKIM signatures are read and checked against a fixed key; the relaxed canonicalizations
//      give the same text twice over.
//   3  address lists, paths and an aliases file.
//   4  text written as quoted-printable, whose lines are at most 76 characters and whose bytes are all printable.
//   5  a Sieve script and a message, split at the first NUL: a script that compiles is run, and what it decides has
//      an action, a mailbox for every fileinto, at most 4 redirects and one reject, and a plain keep where it failed.
//   7  header blocks split at NULs, sorted by every key and threaded both ways: each message is in each answer
//      once, and every parenthesis has its partner.
//   6  bytes a ManageSieve client sends, in pieces cut where a 0xFF byte stands, user u password p signing in: every
//      reply is lines that are a status, a quoted string or a literal that says its own length.
//   8  bytes a POP3 client sends, in pieces cut where a 0xFF byte stands, user u password p signing in to a maildrop
//      of two: nothing is removed but at QUIT, each once, and a line of a multi-line answer that begins with a dot
//      is stuffed.
//   9  an mbox file, read message by message: each read moves on, every line of a message ends in CRLF, and a
//      message written back as an mbox entry reads back as itself, its flags and keywords with it.

#include <algorithm>
#include <cctype>

#include "fuzz_common.h"

#include "../../socketley/runtime/mail/mail_aliases.h"
#include "../../socketley/runtime/mail/mail_compose.h"
#include "../../socketley/runtime/mail/mail_dkim.h"
#include "../../socketley/runtime/mail/mail_mbox.h"
#include "../../socketley/runtime/mail/mail_mime.h"
#include "../../socketley/runtime/mail/mail_sieve.h"
#include "../../socketley/runtime/mail/mail_sieve_store.h"
#include "../../socketley/runtime/mail/managesieve_session.h"
#include "../../socketley/runtime/mail/pop3_session.h"
#include "../../socketley/runtime/mail/imap_order.h"
#include "../../socketley/runtime/mail/smtp_session.h"

#include <charconv>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include <unistd.h>

using namespace socketley::mail;

namespace
{

struct hooks : smtp_session::hooks
{
    std::string out;
    std::string body;
    std::vector<std::string> messages;
    std::deque<std::function<void()>> held;
    bool later{false};
    void answer(std::function<void()> f)
    {
        if (later)
            held.push_back(std::move(f));
        else
            f();
    }
    void reply(std::string_view b) override { out.append(b); }
    void start_tls() override {}
    void authenticate(std::string_view, std::string user, std::string,
                      std::function<void(account, std::string)> done) override
    {
        const account a = user.size() % 3 == 0 ? account::yes : user.size() % 3 == 1 ? account::no : account::unreachable;
        answer([done, user, a] { done(a, user); });
    }
    void mail_from(const address&, std::function<void(rcpt_verdict)> done) override { answer([done] { done({250, ""}); }); }
    void rcpt_to(const address& to, std::function<void(rcpt_verdict)> done) override
    {
        const int code = to.local.size() % 3 == 0 ? 550 : 250;
        answer([done, code] { done({code, ""}); });
    }
    bool data_begin() override
    {
        body.clear();
        return true;
    }
    void data_bytes(std::string_view p) override { body.append(p); }
    void data_end(std::function<void(rcpt_verdict)> done) override
    {
        messages.push_back(body);
        answer([done] { done({250, ""}); });
    }
    void data_abort(bool) override {}
    void close() override {}
};

void smtp(std::string_view in)
{
    hooks h;
    smtp_config cfg;
    cfg.hostname = "mx.test";
    cfg.max_size = 4096;
    cfg.auth_offered = true;
    cfg.auth_in_clear = true;
    cfg.tls_offered = true;
    smtp_session s(cfg, h);
    s.greet();
    size_t at = 0;
    while (at <= in.size())
    {
        const size_t cut = in.find('\xff', at);
        const std::string_view piece = in.substr(at, cut == std::string_view::npos ? std::string_view::npos : cut - at);
        h.later = !piece.empty() && (piece.front() & 1);
        s.input(piece);
        while (!h.held.empty())
        {
            auto f = std::move(h.held.front());
            h.held.pop_front();
            f();
        }
        if (cut == std::string_view::npos)
            break;
        at = cut + 1;
    }
    // Replies are lines of a code, a separator and text, each ended by CRLF.
    std::string_view r = h.out;
    while (!r.empty())
    {
        const size_t nl = r.find("\r\n");
        FUZZ_CHECK(nl != std::string_view::npos, "a reply not ended by CRLF");
        const std::string_view line = r.substr(0, nl);
        FUZZ_CHECK(line.size() >= 3 && std::isdigit(static_cast<unsigned char>(line[0])) &&
                       std::isdigit(static_cast<unsigned char>(line[1])) &&
                       std::isdigit(static_cast<unsigned char>(line[2])),
                   "a reply line without a code");
        FUZZ_CHECK(line.find('\n') == std::string_view::npos && line.find('\r') == std::string_view::npos,
                   "a line's end inside a reply line");
        r.remove_prefix(nl + 2);
    }
    for (const auto& m : h.messages)
        for (size_t i = 0; i < m.size(); ++i)
            if (m[i] == '\n')
                FUZZ_CHECK(i > 0 && m[i - 1] == '\r', "a bare LF in a message taken");
}

void check_part(const mime::part& p, size_t size, int depth)
{
    FUZZ_CHECK(depth < 40, "parts nested past the limit");
    FUZZ_CHECK(p.header_off + p.header_len <= size, "a part's header past the message");
    FUZZ_CHECK(p.body_off + p.body_len <= size, "a part's body past the message");
    FUZZ_CHECK(p.body_off == p.header_off + p.header_len, "a body that does not follow its header");
    for (const auto& c : p.children)
    {
        FUZZ_CHECK(c.header_off >= p.body_off && c.body_off + c.body_len <= p.body_off + p.body_len,
                   "a child outside its parent's body");
        check_part(c, size, depth + 1);
    }
}

// Every literal in an IMAP text says the bytes that follow it.
void check_literals(std::string_view s)
{
    for (size_t at = s.find('{'); at != std::string_view::npos; at = s.find('{', at + 1))
    {
        const size_t close = s.find('}', at);
        if (close == std::string_view::npos || s.substr(close + 1, 2) != "\r\n")
            continue;
        const std::string num(s.substr(at + 1, close - at - 1));
        if (num.empty() || num.find_first_not_of("0123456789") != std::string::npos)
            continue;
        const size_t n = std::strtoull(num.c_str(), nullptr, 10);
        FUZZ_CHECK(close + 3 + n <= s.size(), "a literal longer than what follows it");
        at = close + 2 + n;
    }
}

void mime_case(std::string_view msg)
{
    const mime::part root = mime::parse(msg);
    check_part(root, msg.size(), 0);
    static constexpr const char* specs[] = {"", "1", "2", "1.1", "1.2", "2.1", "3.1.2", "HEADER", "TEXT", "1.MIME",
                                            "2.HEADER", "HEADER.FIELDS (FROM SUBJECT)", "HEADER.FIELDS.NOT (TO)"};
    for (const char* spec : specs)
    {
        std::string_view got;
        std::string built;
        if (!mime::section_of(msg, root, spec, got, built))
            continue;
        if (std::string_view(spec).find("FIELDS") == std::string_view::npos)
            FUZZ_CHECK(got.data() >= msg.data() && got.data() + got.size() <= msg.data() + msg.size(),
                       "a section that is not a slice of the message");
        else
            FUZZ_CHECK(got.data() == built.data() && got.size() == built.size(), "a header list not the one built");
        std::string out;
        FUZZ_CHECK(mime::section(msg, root, spec, out) && out == got, "section and section_of disagree");
    }
    const std::string bs = mime::structure(root, msg, true);
    check_literals(bs);
    check_literals(mime::envelope(msg.substr(0, root.header_len)));
    if (const mime::part* text = mime::preview_part(root))
    {
        const std::string p = mime::preview(msg, *text);
        FUZZ_CHECK(p.size() <= 256 && p.find_first_of("\r\n\t") == std::string::npos && !p.ends_with(' '),
                   "a preview longer than 256 bytes, or with a line's end in it");
    }
}

void mbox_case(std::string_view text)
{
    size_t at = 0;
    mbox::message m;
    for (int n = 0; n < 1000; ++n)
    {
        const size_t before = at;
        if (!mbox::next(text, at, true, m))
            break;
        FUZZ_CHECK(at > before && at <= text.size(), "a read that does not move on");
        for (size_t i = 0; i < m.bytes.size(); ++i)
            if (m.bytes[i] == '\n')
                FUZZ_CHECK(i > 0 && m.bytes[i - 1] == '\r', "a line of a message that ends in a bare LF");
        // A message whose first line is folded would take the flags' header for the one it folds, and a line that
        // ends in a CR of its own is one an mbox's LF cannot tell from its end.
        if (m.bytes.empty() || m.bytes.front() == ' ' || m.bytes.front() == '\t' ||
            m.bytes.find("\r\r\n") != std::string::npos)
            continue;
        const std::string e = mbox::entry(m.bytes, m.flags, m.keywords, m.date_ms);
        size_t at2 = 0;
        mbox::message back;
        FUZZ_CHECK(mbox::next(e, at2, true, back) && at2 == e.size(), "an entry that does not read back whole");
        FUZZ_CHECK(back.bytes == m.bytes, "an entry that reads back as another message");
        FUZZ_CHECK(back.flags == m.flags && back.keywords == m.keywords, "an entry whose flags or keywords change");
    }
}

void dkim_case(std::string_view msg)
{
    const std::string record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0OmYp7o/anNQznPEOYYwMtebEZfJ1oPFrWbywRlRqGOOHBd6jkFYgGQe89oUDbjUewHFwBRCPNeNkBHcZSO3zkgUO64j/hpMu7RqISKGLW0+GvfEyp6AqRmhW7OddocgLQWk/eKnjeqxOIju3N5TXd3AbzJQGXk6gLBsoSsQwLwIDAQAB";
    for (const auto& sig : dkim::signatures(msg))
        (void)dkim::verify(msg, sig, record, 0);
    const std::string once = dkim::relaxed_body(msg);
    FUZZ_CHECK(dkim::relaxed_body(once) == once, "the relaxed body is not its own canonical form");
    const std::string head = dkim::relaxed_header("Name", msg.substr(0, std::min<size_t>(msg.size(), 512)));
    const size_t colon = head.find(':');
    FUZZ_CHECK(colon != std::string::npos, "a canonical header without its colon");
    FUZZ_CHECK(dkim::relaxed_header("name", head.substr(colon + 1)) == head, "the relaxed header is not stable");
}

void address_case(std::string_view in)
{
    std::vector<address> list;
    (void)parse_mailbox_list(in, list);
    for (const auto& a : list)
        FUZZ_CHECK(a.local.size() <= 64 && a.domain.size() <= 255, "an address past RFC 5321's lengths");
    address a;
    if (parse_path(in, a, true, true))
        FUZZ_CHECK(a.text().size() <= 320, "a path longer than an address can be");
    alias_table t;
    std::string why;
    (void)t.parse(in, why);
}

void qp_case(std::string_view in)
{
    const std::string qp = quoted_printable(crlf_lines(in));
    size_t line = 0;
    for (size_t i = 0; i < qp.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(qp[i]);
        if (c == '\r')
        {
            FUZZ_CHECK(i + 1 < qp.size() && qp[i + 1] == '\n', "a CR not of a CRLF");
            FUZZ_CHECK(line <= 76, "a quoted-printable line past 76");
            line = 0;
            ++i;
            continue;
        }
        FUZZ_CHECK((c >= 32 && c < 127) || c == '\t', "a byte quoted-printable should have encoded");
        ++line;
    }
}

void sieve_case(std::string_view in)
{
    const size_t nul = in.find('\0');
    const std::string_view text = in.substr(0, nul);
    const std::string_view msg = nul == std::string_view::npos ? std::string_view{} : in.substr(nul + 1);
    std::string err;
    // A script may include one of a few, itself among them, so a loop of includes is refused rather than run.
    const sieve::loader load = [text](bool global, std::string_view name, std::string& out) {
        if (name == "self")
            out = std::string(text);
        else if (name == "lib")
            out = global ? "require \"editheader\"; addheader \"X-G\" \"1\";" : "require \"include\"; return;";
        else
            return false;
        return true;
    };
    const auto s = sieve::script::compile(text, err, load);
    FUZZ_CHECK(s || err.starts_with("line "), "a script refused without the line it is wrong at");
    if (!s)
        return;
    sieve::context c;
    c.own = {"me@example.com"};
    c.now_s = 1700000000;
    c.zone_min = 60;
    c.mailbox_exists = [](std::string_view f) { return f.size() % 2 == 0; };
    c.seen = [](std::string_view key) { return key.size() % 3 == 0; };
    c.host = "mx.example.com";
    c.spam = 5;
    c.spam_percent = 50;
    const sieve::outcome o = s->run({msg, "alice@example.org", "me+tag@example.com"}, c);
    FUZZ_CHECK(!o.actions.empty(), "an outcome with no action");
    if (!o.error.empty())
    {
        FUZZ_CHECK(o.error.starts_with("line "), "a run error without its line");
        FUZZ_CHECK(o.actions.size() == 1 && o.actions[0].k == sieve::action::kind::keep && o.actions[0].flags.empty(),
                   "a failed run that does more than keep");
    }
    size_t redirects = 0, rejects = 0, vacations = 0;
    for (const auto& a : o.actions)
    {
        using k = sieve::action::kind;
        if (a.k == k::fileinto)
            FUZZ_CHECK(!a.arg.empty(), "a fileinto that names no mailbox");
        redirects += a.k == k::redirect;
        rejects += a.k == k::reject;
        vacations += a.k == k::vacation;
        FUZZ_CHECK((a.k == k::vacation) == a.v.has_value(), "a vacation action without its answer");
        if (a.v)
            FUZZ_CHECK(a.v->to == "alice@example.org" && !a.v->handle.empty(), "a vacation answering no sender");
    }
    size_t notifies = 0;
    for (const auto& a : o.actions)
        if (a.k == sieve::action::kind::notify)
        {
            ++notifies;
            std::vector<std::string> to;
            std::string subject, body;
            FUZZ_CHECK(a.n && sieve::parse_mailto(a.n->method, to, subject, body), "a notify by no mailto URI");
        }
    FUZZ_CHECK(notifies <= 3, "more than 3 notifies");
    if (o.header)
    {
        FUZZ_CHECK(o.header->ends_with("\r\n\r\n") || *o.header == "\r\n", "an edited header not ended by a blank line");
        // What editheader wrote has no line end of its own; a bare LF the message brought it passes on as it was.
        const auto bare = [](std::string_view h) {
            for (size_t i = 0; i < h.size(); ++i)
                if (h[i] == '\n' && (i == 0 || h[i - 1] != '\r'))
                    return true;
            return false;
        };
        FUZZ_CHECK(bare(header_block(msg)) || !bare(*o.header), "an edited header with a bare LF the message had not");
        FUZZ_CHECK(o.error.empty(), "an edited header from a failed run");
    }
    FUZZ_CHECK(redirects <= 4, "more than 4 redirects");
    FUZZ_CHECK(rejects <= 1 && vacations <= 1, "a second reject or vacation");
    FUZZ_CHECK(rejects == 0 || redirects + vacations == 0, "a reject beside a redirect or a vacation");
}

struct sieve_hooks : managesieve_session::hooks
{
    std::string out;
    bool closed{false};
    void reply(std::string_view b) override { out.append(b); }
    void start_tls() override {}
    void login(std::string user, std::string password, std::function<void(account, std::string)> done) override
    {
        done(user == "u" && password == "p" ? account::yes : user == "x" ? account::unreachable : account::no, user);
    }
    void close() override { closed = true; }
    void offload(std::function<void()> job, std::function<void()> done) override
    {
        job();
        done();
    }
};

void managesieve_case(std::string_view in)
{
    static sieve_store store("/tmp/fuzz-mail-sieve-" + std::to_string(::getpid()));
    sieve_hooks h;
    managesieve_config cfg;
    cfg.hostname = "mx.example.com";
    cfg.tls_offered = true;
    cfg.login_in_clear = true;
    managesieve_session s(cfg, h, store);
    s.greet();
    while (!in.empty() && !h.closed)
    {
        const size_t cut = in.find('\xff');
        s.input(in.substr(0, cut));
        in = cut == std::string_view::npos ? std::string_view{} : in.substr(cut + 1);
    }
    std::string_view r = h.out;
    while (!r.empty())
    {
        const size_t nl = r.find("\r\n");
        FUZZ_CHECK(nl != std::string_view::npos, "a reply that is no whole line");
        const std::string_view line = r.substr(0, nl);
        r.remove_prefix(nl + 2);
        if (line.starts_with("{"))
        {
            size_t n = 0;
            const auto res = std::from_chars(line.data() + 1, line.data() + line.size(), n);
            FUZZ_CHECK(res.ec == std::errc() && *res.ptr == '}' && r.size() >= n + 2 && r.substr(n, 2) == "\r\n",
                       "a literal that does not say its own length");
            r.remove_prefix(n + 2);
            continue;
        }
        FUZZ_CHECK(line.starts_with("OK") || line.starts_with("NO") || line.starts_with("BYE") || line.starts_with("\""),
                   "a reply line that is no status, string or literal");
    }
}

void order_case(std::string_view in)
{
    namespace io = socketley::mail::imap_order;
    std::vector<io::entry> v;
    while (!in.empty() && v.size() < 64)
    {
        const size_t cut = in.find('\0');
        io::entry e;
        e.number = static_cast<uint32_t>(v.size() + 1);
        e.seq = v.size();
        e.arrival_ms = static_cast<int64_t>(v.size()) * 1000;
        io::read(e, in.substr(0, cut));
        v.push_back(std::move(e));
        in = cut == std::string_view::npos ? std::string_view{} : in.substr(cut + 1);
    }
    // Every message once, by number, and the parentheses in pairs.
    const auto each_once = [&v](const std::string& t) {
        std::vector<int> seen(v.size() + 1, 0);
        long open = 0;
        for (size_t i = 0; i < t.size();)
        {
            if (t[i] == '(' || t[i] == ')')
            {
                open += t[i] == '(' ? 1 : -1;
                FUZZ_CHECK(open >= 0, "a thread closed before it opened");
                ++i;
                continue;
            }
            if (t[i] == ' ')
            {
                ++i;
                continue;
            }
            size_t n = 0;
            while (i < t.size() && t[i] >= '0' && t[i] <= '9')
                n = n * 10 + static_cast<size_t>(t[i++] - '0');
            FUZZ_CHECK(n >= 1 && n <= v.size(), "a thread names a message there is not");
            ++seen[n];
        }
        FUZZ_CHECK(open == 0, "a thread left open");
        for (size_t n = 1; n <= v.size(); ++n)
            FUZZ_CHECK(seen[n] == 1, "a message not in the threads once");
    };
    each_once(io::references(v));
    each_once(io::ordered_subject(v));
    std::vector<io::key> keys;
    for (const char* k : {"reverse", "arrival", "cc", "date", "from", "size", "subject", "to", "displayfrom", "displayto"})
    {
        std::vector<io::key> one;
        if (io::parse_keys({k, "subject"}, one))
            keys.insert(keys.end(), one.begin(), one.end());
    }
    io::sort(v, keys);
    FUZZ_CHECK(v.size() <= 64, "sort lost or made messages");
}

struct pop3_hooks : pop3_session::hooks
{
    std::string out;
    bool closed{false};
    bool quit_seen{false};
    std::vector<uint32_t> removed;
    void reply(std::string_view b) override { out.append(b); }
    void start_tls() override {}
    void login(std::string user, std::string password, std::function<void(account, std::string)> done) override
    {
        done(user == "u" && password == "p" ? account::yes : user == "x" ? account::unreachable : account::no, user);
    }
    void maildrop(const std::string&, std::function<void(bool, uint32_t, std::vector<pop3_session::message>)> done) override
    {
        done(true, 7, {{3, 40, "a"}, {9, 22, "b"}});
    }
    void read(const pop3_session::message& m, std::function<void(std::shared_ptr<const std::string>)> done) override
    {
        // The first a message whose body has a line that is a dot alone, the second one cut without a final CRLF.
        done(std::make_shared<const std::string>(m.key == "a" ? "Subject: x\r\n\r\n.\r\n..two\r\nend\r\n"
                                                              : "Subject: y\r\n\r\nno end"));
    }
    void remove(const std::string&, std::vector<uint32_t> uids, std::function<void(bool)> done) override
    {
        removed.insert(removed.end(), uids.begin(), uids.end());
        done(true);
    }
    void close() override { closed = true; }
};

void pop3_case(std::string_view in)
{
    pop3_hooks h;
    pop3_config cfg;
    cfg.hostname = "mx.example.com";
    cfg.tls_offered = true;
    cfg.login_in_clear = true;
    pop3_session s(cfg, h);
    s.greet();
    std::string upper_in(in);
    for (char& c : upper_in)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    while (!in.empty() && !h.closed)
    {
        const size_t cut = in.find('\xff');
        s.input(in.substr(0, cut));
        in = cut == std::string_view::npos ? std::string_view{} : in.substr(cut + 1);
    }
    // Nothing is deleted but at a QUIT, and only what the maildrop had, each once.
    FUZZ_CHECK(h.removed.empty() || upper_in.find("QUIT") != std::string::npos, "a message removed before QUIT");
    std::vector<uint32_t> r = h.removed;
    std::sort(r.begin(), r.end());
    FUZZ_CHECK(std::adjacent_find(r.begin(), r.end()) == r.end(), "a message removed twice");
    FUZZ_CHECK(std::all_of(r.begin(), r.end(), [](uint32_t u) { return u == 3 || u == 9; }), "a UID the maildrop lacks");
    // Every reply is whole lines, and a line of a multi-line answer that begins with a dot is stuffed.
    std::string_view o = h.out;
    FUZZ_CHECK(o.starts_with("+OK"), "a greeting that is not +OK");
    FUZZ_CHECK(o.empty() || o.ends_with("\r\n"), "a reply that is no whole line");
    for (size_t at = 0; (at = o.find("\r\n.", at)) != std::string_view::npos; at += 3)
    {
        const std::string_view after = o.substr(at + 3);
        FUZZ_CHECK(after.starts_with("\r\n") || after.starts_with("."), "a dot line neither stuffed nor the end");
    }
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::current_data() = data;
    fuzz::current_size() = size;
    if (size < 1 || size > (64u << 10))
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 10)
    {
        case 0: smtp(in); break;
        case 1: mime_case(in); break;
        case 2: dkim_case(in); break;
        case 3: address_case(in); break;
        case 4: qp_case(in); break;
        case 5: sieve_case(in); break;
        case 6: managesieve_case(in); break;
        case 7: order_case(in); break;
        case 8: pop3_case(in); break;
        case 9: mbox_case(in); break;
    }
    return 0;
}
