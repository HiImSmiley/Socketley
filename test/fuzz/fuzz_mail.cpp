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

#include "fuzz_common.h"

#include "../../socketley/runtime/mail/mail_aliases.h"
#include "../../socketley/runtime/mail/mail_compose.h"
#include "../../socketley/runtime/mail/mail_dkim.h"
#include "../../socketley/runtime/mail/mail_mime.h"
#include "../../socketley/runtime/mail/mail_sieve.h"
#include "../../socketley/runtime/mail/smtp_session.h"

#include <deque>
#include <functional>
#include <string>
#include <vector>

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
    void authenticate(std::string_view, std::string user, std::string, std::function<void(bool, std::string)> done) override
    {
        answer([done, user] { done(user.size() % 2 == 0, user); });
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
    void data_abort() override {}
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
    const auto s = sieve::script::compile(text, err);
    FUZZ_CHECK(s || err.starts_with("line "), "a script refused without the line it is wrong at");
    if (!s)
        return;
    sieve::context c;
    c.own = {"me@example.com"};
    c.now_s = 1700000000;
    c.zone_min = 60;
    c.mailbox_exists = [](std::string_view f) { return f.size() % 2 == 0; };
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
    FUZZ_CHECK(redirects <= 4, "more than 4 redirects");
    FUZZ_CHECK(rejects <= 1 && vacations <= 1, "a second reject or vacation");
    FUZZ_CHECK(rejects == 0 || redirects + vacations == 0, "a reject beside a redirect or a vacation");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::current_data() = data;
    fuzz::current_size() = size;
    if (size < 1 || size > (64u << 10))
        return 0;
    const std::string_view in(reinterpret_cast<const char*>(data) + 1, size - 1);
    switch (data[0] % 6)
    {
        case 0: smtp(in); break;
        case 1: mime_case(in); break;
        case 2: dkim_case(in); break;
        case 3: address_case(in); break;
        case 4: qp_case(in); break;
        case 5: sieve_case(in); break;
    }
    return 0;
}
