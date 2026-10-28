#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <ctime>
#include <random>
#include <filesystem>
#include <string>
#include <vector>

#include <unistd.h>

#include "runtime/mail/imap_utf7.h"
#include "runtime/mail/mail_bayes.h"
#include "runtime/mail/mail_content.h"
#include "runtime/mail/mail_sasl.h"
#include "runtime/mail/mail_setup.h"
#include "runtime/mail/mail_greylist.h"
#include "runtime/mail/mail_mbox.h"
#include "runtime/mail/mail_mime.h"
#include "runtime/mail/imap_store.h"
#include "runtime/mail/mail_reports.h"
#include "runtime/mail/mail_rspamd.h"
#include "runtime/mail/mail_srs.h"
#include "runtime/mail/mail_text.h"
#include "runtime/mail/mail_compose.h"
#include "runtime/mail/pop3_session.h"
#include "shared/crypto/mac.h"
#include "shared/util/ascii.h"
#include "shared/util/base64.h"
#include "shared/util/xml_doc.h"
#include "shared/util/inflate.h"

using namespace socketley::mail;

TEST_CASE("SRS: a forwarded sender is rewritten under this domain and read back, and a forged or old one is not")
{
    const std::string key = "a secret of the runtime's own";
    const int64_t day = 20000;
    const std::string fwd = srs::forward("alice@origin.test", "fwd.test", key, day);
    CHECK(fwd.starts_with("SRS0="));
    CHECK(fwd.ends_with("=origin.test=alice@fwd.test"));
    // The hash is eight base32 characters, 40 bits that folding case does not shrink.
    CHECK(fwd.find('=', 5) == 13);
    CHECK(fwd.substr(5, 8).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == std::string::npos);
    CHECK(srs::reverse(fwd, "fwd.test", key, day) == "alice@origin.test");
    CHECK(srs::reverse(fwd, "fwd.test", key, day + 21) == "alice@origin.test");
    CHECK(srs::reverse(fwd, "fwd.test", key, day + 22).empty());
    // The stamp counts days modulo 1024, and a day after the wrap is still one day.
    const std::string wrap = srs::forward("bob@x.test", "fwd.test", key, 1023);
    CHECK(srs::reverse(wrap, "fwd.test", key, 1024) == "bob@x.test");
    CHECK(srs::reverse(fwd, "fwd.test", "another key", day).empty());
    std::string forged = fwd;
    forged.replace(forged.find("alice@"), 5, "mallo");
    CHECK(srs::reverse(forged, "fwd.test", key, day).empty());
    // Case folded on the way still reads.
    std::string folded = fwd;
    for (char& c : folded)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    CHECK(srs::reverse(folded, "fwd.test", key, day) == "alice@origin.test");
    // A second forwarder makes SRS1, which goes back to the first forwarder as its own SRS0.
    const std::string again = srs::forward(fwd, "second.test", "second key", day);
    CHECK(again.starts_with("SRS1="));
    CHECK(again.find("=fwd.test==") != std::string::npos);
    CHECK(srs::reverse(again, "second.test", "second key", day) == fwd);
    // An SRS1 address is as old as the first forwarder's stamp inside it.
    CHECK(srs::reverse(again, "second.test", "second key", day + 21) == fwd);
    CHECK(srs::reverse(again, "second.test", "second key", day + 22).empty());
    // The four base64 characters of earlier releases are read until 2026-12-31 (day 20818), and not after.
    const int64_t late = 20810;
    const std::string stamp = srs::forward("carol@origin.test", "fwd.test", key, late).substr(14, 2);
    std::string signed_text = stamp + "origin.testcarol";
    socketley::ascii::lower_in_place(signed_text);
    const std::string old_hash = socketley::base64::encode(socketley::crypto::hmac_sha1(key, signed_text)).substr(0, 4);
    const std::string old_form = "SRS0=" + old_hash + "=" + stamp + "=origin.test=carol@fwd.test";
    CHECK(srs::reverse(old_form, "fwd.test", key, late) == "carol@origin.test");
    CHECK(srs::reverse(old_form, "fwd.test", key, 20819).empty());
    std::string wrong_old = old_form;
    wrong_old[5] = wrong_old[5] == 'A' || wrong_old[5] == 'a' ? 'B' : 'A';
    CHECK(srs::reverse(wrong_old, "fwd.test", key, late).empty());
    // A bounce, a sender of this domain and a non-SRS address are left alone.
    CHECK(srs::forward("", "fwd.test", key, day).empty());
    CHECK(srs::forward("me@fwd.test", "fwd.test", key, day) == "me@fwd.test");
    CHECK(srs::reverse("alice@fwd.test", "fwd.test", key, day).empty());
}

TEST_CASE("greylist: a first triplet waits, one that comes back after the delay passes and is let by after")
{
    const std::string dir = "/tmp/test-mail-greylist-" + std::to_string(::getpid());
    std::filesystem::create_directories(dir);
    greylist a(dir + "/g", 300000), b(dir + "/g", 300000);
    const int64_t t0 = 1'700'000'000'000;
    CHECK(greylist::network_of("192.0.2.77") == "192.0.2.0/24");
    CHECK(greylist::network_of("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64");
    const std::string net = greylist::network_of("192.0.2.77");
    CHECK(a.check(net, "s@x.test", "r@y.test", t0) == 300);
    CHECK(a.check(net, "s@x.test", "r@y.test", t0 + 60000) == 240);
    // Another shard reads what this one wrote.
    CHECK(b.check(net, "s@x.test", "r@y.test", t0 + 120000) == 180);
    CHECK(b.check(net, "s@x.test", "r@y.test", t0 + 300000) == 0);
    CHECK(a.check(net, "s@x.test", "r@y.test", t0 + 400000) == 0);
    CHECK(a.check(greylist::network_of("192.0.2.200"), "S@X.test", "r@y.test", t0 + 400000) == 0);
    CHECK(a.check(net, "other@x.test", "r@y.test", t0 + 400000) == 300);
    // One that comes back past a day starts again.
    CHECK(a.check(net, "late@x.test", "r@y.test", t0) == 300);
    CHECK(a.check(net, "late@x.test", "r@y.test", t0 + greylist::retry_window_ms + 1) == 300);
    std::filesystem::remove_all(dir);
}

namespace
{

struct pop_hooks : pop3_session::hooks
{
    std::string out;
    std::vector<uint32_t> removed;
    bool closed{false};
    std::vector<pop3_session::message> drop{{3, 0, "k3"}, {7, 0, "k7"}};
    std::string m3 = "From: a@x.test\r\nSubject: one\r\n\r\nline 1\r\n.dot line\r\nline 3\r\n";
    std::string m7 = "Subject: two\r\n\r\nbody\r\n";
    void reply(std::string_view b) override { out.append(b); }
    void start_tls() override {}
    void login(std::string u, std::string p, std::function<void(account, std::string)> done) override
    {
        done(u == "alice" && p == "pw" ? account::yes : account::no, u);
    }
    void maildrop(const std::string&, std::function<void(bool, uint32_t, std::vector<pop3_session::message>)> done) override
    {
        drop[0].size = m3.size();
        drop[1].size = m7.size();
        done(true, 42, drop);
    }
    void read(const pop3_session::message& m, std::function<void(std::shared_ptr<const std::string>)> done) override
    {
        done(std::make_shared<const std::string>(m.uid == 3 ? m3 : m7));
    }
    void remove(const std::string&, std::vector<uint32_t> uids, std::function<void(bool)> done) override
    {
        removed = uids;
        done(true);
    }
    void close() override { closed = true; }
    std::string take()
    {
        std::string s = std::move(out);
        out.clear();
        return s;
    }
};

}   // namespace

TEST_CASE("POP3: a sign-in, STAT, LIST, UIDL, RETR dot-stuffed, TOP, DELE taken back by RSET, and QUIT removing")
{
    pop_hooks h;
    pop3_config cfg;
    cfg.hostname = "mx.test";
    cfg.tls_offered = true;
    pop3_session s(cfg, h);
    s.greet();
    CHECK(h.take().starts_with("+OK mx.test POP3"));
    s.input("CAPA\r\n");
    std::string capa = h.take();
    CHECK(capa.find("STLS\r\n") != std::string::npos);
    CHECK(capa.find("USER\r\n") == std::string::npos);
    s.input("USER alice\r\n");
    CHECK(h.take().starts_with("-ERR [AUTH]"));
    s.tls_started();
    s.input("USER alice\r\nPASS wrong\r\n");
    CHECK(h.take() == "+OK send the password\r\n-ERR [AUTH] authentication failed\r\n");
    s.input("STAT\r\n");
    CHECK(h.take().starts_with("-ERR sign in first"));
    s.input("AUTH PLAIN AGFsaWNlAHB3\r\n");
    CHECK(h.take() == "+OK maildrop has 2 messages\r\n");
    s.input("STAT\r\nLIST\r\nUIDL 2\r\n");
    CHECK(h.take() == "+OK 2 " + std::to_string(h.m3.size() + h.m7.size()) + "\r\n+OK\r\n1 " +
                          std::to_string(h.m3.size()) + "\r\n2 " + std::to_string(h.m7.size()) +
                          "\r\n.\r\n+OK 2 42.7\r\n");
    s.input("RETR 1\r\n");
    CHECK(h.take() == "+OK\r\nFrom: a@x.test\r\nSubject: one\r\n\r\nline 1\r\n..dot line\r\nline 3\r\n.\r\n");
    s.input("TOP 1 1\r\n");
    CHECK(h.take() == "+OK\r\nFrom: a@x.test\r\nSubject: one\r\n\r\nline 1\r\n.\r\n");
    s.input("DELE 1\r\nDELE 1\r\nLIST\r\nRSET\r\nDELE 2\r\nQUIT\r\n");
    const std::string tail = h.take();
    CHECK(tail.find("-ERR no such message") != std::string::npos);
    CHECK(tail.find("+OK\r\n2 ") != std::string::npos);
    CHECK(tail.ends_with("+OK mx.test closing\r\n"));
    CHECK(h.removed == std::vector<uint32_t>{7});
    CHECK(h.closed);
}

TEST_CASE("modified UTF-7: RFC 3501's example, an astral character, & and what does not decode")
{
    using namespace socketley::mail;
    CHECK(imap_utf7::encode("~peter/mail/\xe5\x8f\xb0\xe5\x8c\x97/\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e") ==
          "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
    CHECK(imap_utf7::decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-") ==
          "~peter/mail/\xe5\x8f\xb0\xe5\x8c\x97/\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e");
    CHECK(imap_utf7::encode("A&B") == "A&-B");
    CHECK(imap_utf7::decode("A&-B") == "A&B");
    CHECK(imap_utf7::decode(imap_utf7::encode("\xf0\x9f\x98\x80 Smile")) == "\xf0\x9f\x98\x80 Smile");
    CHECK(imap_utf7::encode("Entw\xc3\xbcrfe") == "Entw&APw-rfe");
    CHECK(imap_utf7::decode("&AGE-").empty());
    CHECK(imap_utf7::decode("&Jjo").empty());
    CHECK(imap_utf7::encode("\xff").empty());
}

TEST_CASE("reports: a day's DMARC rows and TLS sessions become gzip'd RFC 7489 XML and RFC 8460 JSON once it ends")
{
    reports r;
    reports::dmarc_seen s;
    s.policy_domain = "origin.test";
    s.rua = "mailto:dmarc@origin.test!10m, mailto:copy@else.test";
    s.p = "reject";
    s.header_from = "origin.test";
    s.source_ip = "192.0.2.1";
    s.disposition = "reject";
    s.dkim = {{"origin.test", "fail"}};
    s.spf_domain = "origin.test";
    s.spf_result = "fail";
    r.dmarc(s);
    r.dmarc(s);
    r.tls("dest.test", "sts", {"version: STSv1", "mode: enforce"}, "mx.dest.test", false, "certificate-host-mismatch",
          "198.51.100.5", "203.0.113.1");
    r.tls("dest.test", "sts", {"version: STSv1", "mode: enforce"}, "mx.dest.test", true, "", "", "203.0.113.1");
    const int64_t now = ::time(nullptr);
    CHECK(r.due(now, "mx.here.test", "postmaster@here.test").empty());
    const auto out = r.due(now + 2 * 86400, "mx.here.test", "postmaster@here.test");
    REQUIRE(out.size() == 2);
    const auto unzip = [](const std::string& gz) {
        REQUIRE(gz.size() > 18);
        socketley::inflater in;
        in.feed(reinterpret_cast<const uint8_t*>(gz.data()) + 10, gz.size() - 18);
        std::string text;
        in.run(text, 1u << 20);
        return text;
    };
    CHECK(out[0].to == std::vector<std::string>{"dmarc@origin.test", "copy@else.test"});
    CHECK(out[0].filename.starts_with("mx.here.test!origin.test!"));
    const std::string x = unzip(out[0].data);
    CHECK(x.find("<count>2</count>") != std::string::npos);
    CHECK(x.find("<disposition>reject</disposition>") != std::string::npos);
    CHECK(x.find("<p>reject</p>") != std::string::npos);
    CHECK(out[1].to.empty());
    CHECK(out[1].content_type == "application/tlsrpt+gzip");
    const std::string j = unzip(out[1].data);
    CHECK(j.find("\"total-successful-session-count\":1,\"total-failure-session-count\":1") != std::string::npos);
    CHECK(j.find("\"result-type\":\"certificate-host-mismatch\"") != std::string::npos);
    CHECK(r.due(now + 2 * 86400, "mx.here.test", "postmaster@here.test").empty());
}

TEST_CASE("rspamd: the top-level score, not a symbol's, and the levels spamtest reads")
{
    const std::string body = R"({"symbols":{"A":{"score":9.5,"name":"A"}},"score": 7.25 ,"required_score":15,)"
                             R"("action":"add header","messages":{}})";
    CHECK(json_member(body, "score") == "7.25");
    CHECK(json_member(body, "required_score") == "15");
    CHECK(json_member(body, "action") == "add header");
    CHECK(json_member(body, "name").empty());
    spam_verdict v;
    CHECK(v.level() == 0);
    v.scored = true;
    v.score = 7.5;
    v.required = 15;
    CHECK(v.level() == 6);
    CHECK(v.percent() == 50);
    v.score = -2;
    CHECK(v.level() == 1);
    v.score = 40;
    CHECK(v.level() == 10);
}

namespace
{

// A message with what search reads in every form: a folded header, encoded words, a quoted-printable text part, a
// base64 text part in another charset, and an attachment.
std::string search_message()
{
    return "From: =?UTF-8?Q?J=C3=BCrgen_M=C3=BCller?= <jm@else.test>\r\n"
           "To: alice@example.test\r\n"
           "Subject: a subject that is folded\r\n"
           " over two lines\r\n"
           "Message-ID: <s1@else.test>\r\n"
           "MIME-Version: 1.0\r\n"
           "Content-Type: multipart/mixed; boundary=b\r\n"
           "\r\n"
           "--b\r\n"
           "Content-Type: text/plain; charset=utf-8\r\n"
           "Content-Transfer-Encoding: quoted-printable\r\n"
           "\r\n"
           "Gr=C3=BC=C3=9Fe aus K=C3=B6ln, the meeting is at noon and the long word is extraordin=\r\n"
           "arily split\r\n"
           "--b\r\n"
           "Content-Type: text/plain; charset=iso-8859-1\r\n"
           "Content-Transfer-Encoding: base64\r\n"
           "\r\n"
           "U2No9m5lIEfkc3RlIGluIExhdGluLTE=\r\n"
           "--b\r\n"
           "Content-Type: application/octet-stream\r\n"
           "Content-Disposition: attachment; filename=report.bin\r\n"
           "Content-Transfer-Encoding: base64\r\n"
           "\r\n"
           "c2VjcmV0aW5zaWRldGhlYXR0YWNobWVudA==\r\n"
           "--b--\r\n";
}

}   // namespace

TEST_CASE("search: what a client looks for is found decoded, and what an attachment holds is not")
{
    const std::string msg = search_message();
    const std::string_view head = header_block(msg);
    const mime::part root = mime::parse(msg);
    // A quoted-printable soft break, and a charset undone.
    CHECK(body_has(msg, head, &root, "extraordinarily"));
    CHECK(body_has(msg, head, &root, "GRÜßE AUS KÖLN") == false);
    CHECK(body_has(msg, head, &root, "Grüße aus Köln"));
    CHECK(body_has(msg, head, &root, "schöne gäste"));
    // As written, too.
    CHECK(body_has(msg, head, &root, "K=C3=B6ln"));
    // An encoded word, and a header the body does not hold.
    CHECK(header_has(head, "From", "jürgen müller"));
    CHECK(text_has(msg, head, &root, "jürgen"));
    CHECK(body_has(msg, head, &root, "jürgen") == false);
    // What only an attachment holds, written or decoded, is nowhere; its name is in its part's header.
    CHECK(text_has(msg, head, &root, "c2VjcmV0") == false);
    CHECK(text_has(msg, head, &root, "secretinside") == false);
    CHECK(text_has(msg, head, &root, "report.bin"));
}

TEST_CASE("search: contains_ci finds just what a plain scan with letters of either case alike finds")
{
    // Few letters, both cases and a byte past ASCII, so needles repeat themselves and their first letter is everywhere.
    std::mt19937 rng(11);
    const std::string alphabet = "aAbBn \xc3";
    const auto random_text = [&](size_t n) {
        std::string t;
        for (size_t i = 0; i < n; ++i)
            t += alphabet[rng() % alphabet.size()];
        return t;
    };
    const auto plain = [](std::string_view hay, std::string_view needle) {
        for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        {
            size_t k = 0;
            while (k < needle.size() && socketley::ascii::lower(hay[i + k]) == socketley::ascii::lower(needle[k]))
                ++k;
            if (k == needle.size())
                return true;
        }
        return false;
    };
    size_t wrong = 0, found = 0;
    for (int round = 0; round < 20000; ++round)
    {
        const std::string hay = random_text(rng() % 40), needle = random_text(1 + rng() % 6);
        const bool want = plain(hay, needle);
        found += want;
        wrong += contains_ci(hay, needle) != want;
    }
    CHECK(wrong == 0);
    // Both answers came up often enough to mean something.
    CHECK(found > 2000);
    CHECK(found < 18000);
    // A needle longer than the stack holds, and one of a repeated letter that falls back at its last byte.
    const std::string long_needle = std::string(100, 'a') + "B";
    CHECK(contains_ci(std::string(300, 'A') + "b", long_needle));
    CHECK(contains_ci(std::string(300, 'A') + "c", long_needle) == false);
}

TEST_CASE("search: a message's trigram filter lets through every string the search finds in it")
{
    const std::string msg = search_message();
    const std::string_view head = header_block(msg);
    const mime::part root = mime::parse(msg);
    const std::string filter = text_filter(msg, head, &root);
    // Every piece of the message as written, of its decoded text and of its headers as a client reads them.
    std::vector<std::string> sources = {msg, "Grüße aus Köln, the meeting is at noon and the long word is extraordinarily split",
                                        "Schöne Gäste in Latin-1", "Jürgen Müller <jm@else.test>",
                                        "a subject that is folded over two lines"};
    size_t tried = 0, missed = 0;
    for (const auto& src : sources)
        for (size_t len = 3; len <= 12; ++len)
            for (size_t at = 0; at + len <= src.size(); ++at)
            {
                const std::string_view needle(src.data() + at, len);
                // As IMAP finds it, and as JMAP reads a header: its folds undone.
                const bool found = text_has(msg, head, &root, needle) || contains_ci(header_value(head, "Subject"), needle) ||
                                   contains_ci(mime::decode_words(header_value(head, "From")), needle);
                if (!found)
                    continue;
                ++tried;
                if (!may_hold(filter, needle))
                    ++missed;
                std::string upper(needle);
                for (char& c : upper)
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                if (!may_hold(filter, upper))
                    ++missed;
            }
    CHECK(tried > 5000);
    CHECK(missed == 0);
    // A string shorter than a trigram, and a filter this build cannot read, rule nothing out.
    CHECK(may_hold(filter, "zq"));
    CHECK(may_hold("", "anything at all"));
    CHECK(may_hold(std::string("\x07\x08", 2), "anything at all"));
}

TEST_CASE("search: a trigram filter rules out nearly every string a message does not hold")
{
    const std::string msg = search_message();
    const std::string_view head = header_block(msg);
    const mime::part root = mime::parse(msg);
    const std::string filter = text_filter(msg, head, &root);
    std::mt19937 rnd(7);
    size_t through = 0;
    for (int i = 0; i < 20000; ++i)
    {
        std::string w;
        for (int k = 0; k < 8; ++k)
            w += static_cast<char>('a' + rnd() % 26);
        if (!text_has(msg, head, &root, w) && may_hold(filter, w))
            ++through;
    }
    CHECK(through < 20);
    // What only the attachment holds is ruled out like the rest.
    CHECK(may_hold(filter, "secretinsidetheattachment") == false);
}

TEST_CASE("search: a filter is as large as the different trigrams a message holds, not its length")
{
    // A newsletter of one row a hundred and twenty times over has some 600 trigrams in 16 KB.
    std::string rows;
    for (int i = 0; i < 120; ++i)
        rows += "<table><tr><td style=\"padding:0;font-family:Arial\"><a href=\"https://news.example.com/track?id=" +
                std::to_string(i) + "\">Article " + std::to_string(i) + "</a></td></tr></table>\r\n";
    const std::string letter = "From: news@example.com\r\nSubject: this week\r\nContent-Type: text/html\r\n\r\n" + rows;
    const mime::part root = mime::parse(letter);
    const std::string filter = text_filter(letter, header_block(letter), &root);
    CHECK(filter.size() <= 2 + 512);
    for (const char* held : {"Article 117", "track?id=99", "font-family:Arial", "this week"})
        CHECK(may_hold(filter, held));
    std::mt19937 rnd(5);
    size_t through = 0;
    for (int i = 0; i < 20000; ++i)
    {
        std::string w;
        for (int k = 0; k < 8; ++k)
            w += static_cast<char>('a' + rnd() % 26);
        through += !contains_ci(letter, w) && may_hold(filter, w);
    }
    CHECK(through < 20);
    // Text of many different words gets the largest filter.
    std::string varied = "Subject: words\r\n\r\n";
    while (varied.size() < 200000)
    {
        for (int k = 0; k < 7; ++k)
            varied += static_cast<char>('a' + rnd() % 26);
        varied += ' ';
    }
    const mime::part vroot = mime::parse(varied);
    CHECK(text_filter(varied, header_block(varied), &vroot).size() == 2 + 4096);
}

TEST_CASE("search: past a mebibyte a message's filter holds anything, and an empty message's nothing")
{
    std::string big = "Subject: big\r\n\r\n";
    for (int i = 0; i < 40000; ++i)
        big += "line " + std::to_string(i) + " of a long message\r\n";
    const mime::part root = mime::parse(big);
    CHECK(may_hold(text_filter(big, header_block(big), &root), "nowhere in it"));
    const std::string empty = "\r\n";
    const mime::part none = mime::parse(empty);
    CHECK(may_hold(text_filter(empty, header_block(empty), &none), "anything") == false);
}

namespace
{

std::string sample_mail(const std::string& subject, const std::string& body, const std::string& from = "a@b.test")
{
    return "From: " + from + "\r\nTo: u@x.test\r\nSubject: " + subject + "\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n";
}

const char* const spammy[] = {"cheap pills online pharmacy discount", "win money lottery prize claim now",
                              "viagra cialis cheap pharmacy order", "casino bonus free spins jackpot win",
                              "crypto investment guaranteed profit double money"};
const char* const hammy[] = {"meeting notes from tuesday about the release plan", "lunch on friday with the team at noon",
                             "please review the pull request for the parser", "the invoice for september is attached",
                             "family dinner sunday with grandma and the kids"};

}   // namespace

TEST_CASE("bayes: a message's words are its subject's, its text's and its From's domain, each once")
{
    const auto t = spam_tokens(sample_mail("Hello Hello", "hello world, the world is round", "Ann <ann@Example.TEST>"));
    const auto again = spam_tokens(sample_mail("Hello Hello", "hello world, the world is round", "Ann <ann@Example.TEST>"));
    CHECK(t == again);
    CHECK(t.size() == 6);   // s:hello, f:example.test, hello, world, the, round
    const auto html = spam_tokens("Subject: x\r\nContent-Type: text/html\r\n\r\n<style>.a{color:red}</style><p>Visit <a "
                                  "href=\"https://shop.example.test/x\">here</a></p>\r\n");
    const auto plain = spam_tokens("Subject: x\r\nContent-Type: text/plain\r\n\r\nVisit here\r\n");
    CHECK(html.size() == plain.size() + 1);   // the link's host, and no word of the style
}

TEST_CASE("bayes: trained on what users said, it tells spam it has not seen from the rest, and learns a message once")
{
    bayes b;
    std::mt19937 rng(7);
    const auto mixed = [&](const char* const* set) {
        std::string s;
        for (int i = 0; i < 3; ++i)
            s += std::string(set[rng() % 5]) + " ";
        return s;
    };
    CHECK(b.score(spam_tokens(sample_mail("x", "cheap pills"))) == 0.5);
    for (uint64_t i = 0; i < 30; ++i)
    {
        CHECK(b.learn(i, true, spam_tokens(sample_mail("offer", mixed(spammy), "x@spam.test"))));
        CHECK(b.learn(1000 + i, false, spam_tokens(sample_mail("work", mixed(hammy), "y@work.test"))));
    }
    REQUIRE(b.trained());
    CHECK(b.score(spam_tokens(sample_mail("claim your prize", "free money jackpot pharmacy discount"))) >= bayes::spam_at);
    CHECK(b.score(spam_tokens(sample_mail("release", "review the release notes with the team on tuesday"))) <= 0.2);
    // Learned again as the same, nothing changes; said otherwise, it is unlearned first.
    const auto t = spam_tokens(sample_mail("offer", "casino bonus"));
    CHECK_FALSE(b.learn(5, true, spam_tokens(sample_mail("offer", mixed(spammy)))));
    CHECK(b.learn(5000, true, t));
    CHECK(b.spam_learned() == 31);
    CHECK(b.learn(5000, false, t));
    CHECK(b.spam_learned() == 30);
    CHECK(b.ham_learned() == 31);
}

TEST_CASE("bayes: the table survives its file and its journal's lines, a line cut off left for the next read")
{
    bayes b;
    const auto t = spam_tokens(sample_mail("offer", "cheap pills"));
    std::string journal = bayes::line(1, true, t) + bayes::line(2, false, spam_tokens(sample_mail("hi", "meeting notes")));
    const std::string cut = bayes::line(3, true, t);
    journal += cut.substr(0, cut.size() / 2);
    CHECK(b.apply(journal) == journal.size() - cut.size() / 2);
    CHECK(b.spam_learned() == 1);
    CHECK(b.ham_learned() == 1);
    const std::string path = std::filesystem::temp_directory_path() / ("bayes-" + std::to_string(::getpid()));
    std::string why;
    REQUIRE(b.save(path, why));
    bayes back;
    REQUIRE(back.load(path, why));
    CHECK(back.spam_learned() == 1);
    CHECK(back.words() == b.words());
    CHECK_FALSE(back.learn(1, true, t));
    std::filesystem::remove(path);
    bayes none;
    CHECK(none.load(path, why));
    CHECK(none.words() == 0);
}

TEST_CASE("sasl: XOAUTH2 and OAUTHBEARER give their user and token, and anything else none")
{
    std::string user, token;
    CHECK(sasl_bearer("XOAUTH2", std::string("user=alice@x.test\x01" "auth=Bearer tok.en-1\x01\x01"), user, token));
    CHECK(user == "alice@x.test");
    CHECK(token == "tok.en-1");
    CHECK(sasl_bearer("OAUTHBEARER", std::string("n,a=bob,\x01host=mail\x01port=993\x01" "auth=Bearer abc\x01\x01"), user, token));
    CHECK(user == "bob");
    CHECK(token == "abc");
    CHECK(sasl_bearer("OAUTHBEARER", std::string("n,,\x01" "auth=Bearer abc\x01\x01"), user, token));
    CHECK(user.empty());
    CHECK_FALSE(sasl_bearer("XOAUTH2", std::string("user=a\x01" "auth=Basic abc\x01\x01"), user, token));
    CHECK_FALSE(sasl_bearer("XOAUTH2", std::string("user=a\x01" "auth=Bearer \x01\x01"), user, token));
    CHECK_FALSE(sasl_bearer("PLAIN", std::string("\0a\0b", 4), user, token));
}

TEST_CASE("content: an attachment of a kind that runs is named, an ordinary one and a list of none are not")
{
    const auto with = [](const std::string& name) {
        return "From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
               "Content-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/octet-stream; name=\"" + name +
               "\"\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\n\r\nxx\r\n--b--\r\n";
    };
    CHECK(refused_attachment(with("Setup.EXE"), "default") == "Setup.EXE");
    CHECK(refused_attachment(with("budget.xlsm"), "default") == "budget.xlsm");
    CHECK(refused_attachment(with("report.pdf"), "default").empty());
    CHECK(refused_attachment(with("setup.exe"), "none").empty());
    CHECK(refused_attachment(with("report.pdf"), "pdf, .zip") == "report.pdf");
    CHECK(refused_attachment("From: a@b\r\nSubject: plain\r\n\r\nno parts\r\n", "default").empty());
}

TEST_CASE("setup: what Thunderbird, Outlook and an Apple device are told names the host, the TLS ports and the address")
{
    client_settings s;
    s.hostname = "mail.x.test";
    s.email = "a&b@x.test";
    s.domain = "x.test";
    s.imaps = 993;
    s.submission = 587;
    const std::string tb = thunderbird_autoconfig(s);
    CHECK(tb.find("<hostname>mail.x.test</hostname>") != std::string::npos);
    CHECK(tb.find("<port>993</port>\n      <socketType>SSL</socketType>") != std::string::npos);
    CHECK(tb.find("<port>587</port>\n      <socketType>STARTTLS</socketType>") != std::string::npos);
    CHECK(tb.find("pop3") == std::string::npos);
    const std::string ol = outlook_autodiscover(s);
    CHECK(ol.find("<LoginName>a&amp;b@x.test</LoginName>") != std::string::npos);
    CHECK(ol.find("<Encryption>TLS</Encryption>") != std::string::npos);
    const std::string ap = apple_mobileconfig(s);
    CHECK(ap.find("<key>EmailAddress</key><string>a&amp;b@x.test</string>") != std::string::npos);
    CHECK(ap == apple_mobileconfig(s));
    CHECK(autodiscover_address("<Request><EMailAddress> u@x.test </EMailAddress></Request>") == "u@x.test");
    CHECK(autodiscover_address("<EMailAddress>bad\"x</EMailAddress>").empty());
    CHECK(outlook_autodiscover_json("autodiscover.x.test") ==
          "{\"Protocol\":\"AutodiscoverV1\",\"Url\":\"https://autodiscover.x.test/autodiscover/autodiscover.xml\"}");
}

TEST_CASE("mbox: a message written out reads back as itself, its flags, keywords and date with it")
{
    const std::string msg = "Subject: hi\r\n\r\nFrom the start\r\n>From before\r\nlast\r\n\r\n";
    const std::string e = mbox::entry(msg, flag_seen | flag_flagged | flag_answered, {"$Forwarded", "work"},
                                      1792900800000);
    CHECK(e.starts_with("From MAILER-DAEMON Sun Oct 25 04:00:00 2026\nStatus: RO\nX-Status: AF\n"
                        "X-Keywords: $Forwarded work\nSubject: hi\n\n>From the start\n>>From before\n"));
    CHECK(e.find('\r') == std::string::npos);
    // Two entries one after the other, the first ending in an empty line of its own.
    const std::string two = e + mbox::entry("Subject: two\r\n\r\nbody\r\n", 0, {}, 0);
    size_t at = 0;
    mbox::message m;
    REQUIRE(mbox::next(two, at, true, m));
    CHECK(m.bytes == msg);
    CHECK(m.flags == (flag_seen | flag_flagged | flag_answered));
    CHECK(m.keywords == std::vector<std::string>{"$Forwarded", "work"});
    CHECK(m.date_ms == 1792900800000);
    REQUIRE(mbox::next(two, at, true, m));
    CHECK(m.bytes == "Subject: two\r\n\r\nbody\r\n");
    CHECK(m.flags == 0);
    CHECK(at == two.size());
    CHECK_FALSE(mbox::next(two, at, true, m));
    // A message still being read is not taken until what follows it is.
    at = 0;
    CHECK(mbox::next(two, at, false, m));
    CHECK_FALSE(mbox::next(two, at, false, m));
    // An empty message between two is one, and no part of the next.
    const std::string empty = "From a Thu Jan  1 00:00:00 2026\nFrom b Thu Jan  1 00:00:00 2026\nX: y\n";
    at = 0;
    REQUIRE(mbox::next(empty, at, true, m));
    CHECK(m.bytes.empty());
    REQUIRE(mbox::next(empty, at, true, m));
    CHECK(m.bytes == "X: y\r\n");
}

TEST_CASE("mbox: a Takeout's labels say the folder and the flags")
{
    uint8_t f = 0;
    CHECK(mbox::folder_of_labels("Inbox,Opened,Category Updates", f) == "INBOX");
    CHECK(f == flag_seen);
    f = 0;
    CHECK(mbox::folder_of_labels("Spam,Unread", f) == "Junk");
    CHECK(f == 0);
    f = 0;
    CHECK(mbox::folder_of_labels("Important,Work/Projects,Starred", f) == "Work/Projects");
    CHECK(f == (flag_seen | flag_flagged));
    f = 0;
    CHECK(mbox::folder_of_labels("Archived,Opened", f) == "Archive");
    CHECK(mbox::folder_of_labels("\"Clients, old\",Opened", f) == "Clients, old");
    CHECK(mbox::folder_of_labels("Inbox,Sent", f) == "Sent");
    CHECK(mbox::folder_of_labels("Trash,Inbox", f) == "Trash");
    const std::string takeout = "From 1234@xxx Mon Oct 19 10:00:00 +0000 2026\r\nX-GM-THRID: 1\r\n"
                                "X-Gmail-Labels: Inbox,\r\n Unread\r\nSubject: s\r\n\r\nb\r\n";
    size_t at = 0;
    mbox::message m;
    REQUIRE(mbox::next(takeout, at, true, m));
    CHECK(m.folder == "INBOX");
    CHECK(m.flags == 0);
    CHECK(m.date_ms == 1792404000000);
    CHECK(m.bytes == "X-GM-THRID: 1\r\nSubject: s\r\n\r\nb\r\n");
}

TEST_CASE("preview: a message's text from its start, its white space one space and its tags out, of 256 bytes")
{
    const std::string msg = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
                            "Content-Type: text/plain; name=x.txt\r\nContent-Disposition: attachment\r\n\r\nnot this\r\n"
                            "--b\r\nContent-Type: text/html\r\n\r\n<p>Hello\r\n  <b>there</b></p>  \r\n--b--\r\n";
    const mime::part root = mime::parse(msg);
    const mime::part* text = mime::preview_part(root);
    REQUIRE(text);
    CHECK(text->subtype == "html");
    CHECK(mime::preview(msg, *text) == "Hello there");
    const std::string longer = "Subject: x\r\n\r\n" + std::string(300, 'a');
    const mime::part r2 = mime::parse(longer);
    CHECK(mime::preview(longer, *mime::preview_part(r2)).size() == 256);
    const std::string umlauts = "Content-Type: text/plain; charset=utf-8\r\n\r\n" + std::string(255, 'a') + "\xc3\xa4";
    const mime::part r3 = mime::parse(umlauts);
    CHECK(mime::preview(umlauts, *mime::preview_part(r3)) == std::string(255, 'a'));
}

TEST_CASE("preview: what a reply says, without what it quotes, as Outlook, Gmail and plain quoting mark it")
{
    const auto of = [](const std::string& body, const char* type = "text/plain") {
        const std::string msg = std::string("Content-Type: ") + type + "; charset=utf-8\r\n\r\n" + body;
        const mime::part root = mime::parse(msg);
        return mime::preview(msg, *mime::preview_part(root));
    };
    CHECK(of("yea\r\n________________________________\r\nVon: smiley@smileygames.online <smiley@smileygames.online>\r\n"
             "Gesendet: Dienstag\r\n\r\nTrue\r\n") == "yea");
    CHECK(of("test\r\nOn Tue, Oct 27, 2026, 03:43 PM, Jonas Schenk wrote:\r\n> yea\r\n") == "test");
    CHECK(of("ok\r\n\r\nAm 27.10.2026 um 15:42 schrieb smiley <smiley@x.de>:\r\n> True\r\n") == "ok");
    CHECK(of("<div>moin</div><div id=\"appendonsend\"></div><hr><div id=\"divRplyFwdMsg\">Von: a@b</div>", "text/html") ==
          "moin");
    CHECK(of("<p>fine</p><blockquote type=\"cite\">earlier</blockquote>", "text/html") == "fine");
    // A message that is nothing but a quote, a forward, still says what it holds.
    CHECK(of("> only quoted\r\n> lines\r\n") == "> only quoted > lines");
    // A From: line without an address is the message's own words.
    CHECK(of("From: the start, as agreed\r\nmore") == "From: the start, as agreed more");
}

TEST_CASE("xml: elements know their namespace through prefixes and defaults, attributes and entities are read")
{
    socketley::xml::node doc;
    REQUIRE(socketley::xml::reader("\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<!-- c --><d:propfind xmlns:d=\"DAV:\">"
                                   "<d:prop xmlns=\"urn:x\"><a/><d:b q='1 &gt; 0'/><c xmlns=\"\">&lt;&#x41;&#66;&amp;</c></d:prop>"
                                   "</d:propfind>").document(doc));
    CHECK(doc.name == "propfind");
    CHECK(doc.ns == "DAV:");
    const socketley::xml::node* prop = doc.child("prop", "DAV:");
    REQUIRE(prop);
    REQUIRE(prop->kids.size() == 3);
    CHECK(prop->kids[0].ns == "urn:x");
    CHECK(prop->kids[1].ns == "DAV:");
    CHECK(prop->kids[1].attr("q") == "1 > 0");
    CHECK(prop->kids[2].ns.empty());
    CHECK(prop->kids[2].text == "<AB&");
    for (const char* bad : {"<a>", "<a></b>", "<a><![CDATA[x]]></a>", "<!DOCTYPE a><a/>", "<a>x<b/></a>", "<a b=c/>",
                            "<a>&bogus;</a>", "<a/><b/>", "<a/>junk"})
    {
        socketley::xml::node n;
        CHECK_FALSE(socketley::xml::reader(bad).document(n));
    }
    std::string deep;
    for (int i = 0; i < 40; ++i)
        deep += "<a>";
    socketley::xml::node n;
    CHECK_FALSE(socketley::xml::reader(deep).document(n));
    std::string back;
    CHECK(socketley::xml::unescape(socketley::xml::escape("a<b>&\"c'\x01"), back));
    CHECK(back == "a<b>&\"c'");
}
