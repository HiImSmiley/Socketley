#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <ctime>
#include <filesystem>
#include <string>
#include <vector>

#include <unistd.h>

#include "runtime/mail/imap_utf7.h"
#include "runtime/mail/mail_greylist.h"
#include "runtime/mail/mail_reports.h"
#include "runtime/mail/mail_rspamd.h"
#include "runtime/mail/mail_srs.h"
#include "runtime/mail/pop3_session.h"
#include "shared/util/inflate.h"

using namespace socketley::mail;

TEST_CASE("SRS: a forwarded sender is rewritten under this domain and read back, and a forged or old one is not")
{
    const std::string key = "a secret of the runtime's own";
    const int64_t day = 20000;
    const std::string fwd = srs::forward("alice@origin.test", "fwd.test", key, day);
    CHECK(fwd.starts_with("SRS0="));
    CHECK(fwd.ends_with("=origin.test=alice@fwd.test"));
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
