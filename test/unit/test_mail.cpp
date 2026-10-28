#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <filesystem>
#include <vector>

#include <unistd.h>

#include "runtime/mail/mail_aliases.h"
#include "runtime/mail/mail_arc.h"
#include "runtime/mail/mail_compose.h"
#include "runtime/mail/mail_dkim.h"
#include "runtime/mail/mail_mime.h"
#include "runtime/mail/mail_tls_policy.h"
#include "runtime/mail/mail_sieve_store.h"
#include "runtime/mail/managesieve_session.h"
#include "runtime/mail/imap_order.h"
#include "runtime/mail/mail_verify.h"
#include "runtime/mail/smtp_session.h"
#include "shared/net/idna.h"
#include "shared/net/public_suffix.h"
#include "shared/util/base64.h"
#include "shared/util/deflate.h"
#include "shared/util/inflate.h"

using namespace socketley::mail;
namespace dkim = socketley::mail::dkim;

namespace
{

// A session's other side: what it says is kept, and every question is answered at once or held for the test.
struct fake : smtp_session::hooks
{
    std::string out;
    std::vector<std::string> messages;
    std::string body;
    bool closed{false};
    bool tls{false};
    bool hold{false};
    bool refuse_data{false};
    int aborted{0};
    std::deque<std::function<void()>> held;
    std::function<rcpt_verdict(const address&)> rcpt_rule = [](const address&) { return rcpt_verdict{250, ""}; };
    std::function<bool(const std::string&, const std::string&)> password = [](const std::string& u,
                                                                            const std::string& p) {
        return u == "alice" && p == "secret";
    };

    void answer(std::function<void()> f)
    {
        if (hold)
            held.push_back(std::move(f));
        else
            f();
    }
    void release()
    {
        while (!held.empty())
        {
            auto f = std::move(held.front());
            held.pop_front();
            f();
        }
    }
    void reply(std::string_view b) override { out.append(b); }
    void start_tls() override { tls = true; }
    void authenticate(std::string_view, std::string user, std::string secret,
                      std::function<void(account, std::string)> done) override
    {
        const bool ok = password(user, secret);
        answer([done, ok, user] { done(ok ? account::yes : account::no, user); });
    }
    void mail_from(const address&, std::function<void(rcpt_verdict)> done) override
    {
        answer([done] { done({250, ""}); });
    }
    void rcpt_to(const address& to, std::function<void(rcpt_verdict)> done) override
    {
        const rcpt_verdict v = rcpt_rule(to);
        answer([done, v] { done(v); });
    }
    bool data_begin() override
    {
        if (refuse_data)
            return false;
        body.clear();
        return true;
    }
    void data_bytes(std::string_view p) override { body.append(p); }
    void data_end(std::function<void(rcpt_verdict)> done) override
    {
        messages.push_back(body);
        answer([done] { done({250, "queued"}); });
    }
    void data_abort(bool) override
    {
        ++aborted;
    }
    void close() override { closed = true; }

    // The reply codes said since the last call, in order.
    std::vector<int> codes()
    {
        std::vector<int> c;
        size_t at = 0;
        while (at < out.size())
        {
            const size_t nl = out.find("\r\n", at);
            if (nl == std::string::npos)
                break;
            const std::string line = out.substr(at, nl - at);
            if (line.size() >= 4 && line[3] == ' ')
                c.push_back(std::stoi(line.substr(0, 3)));
            at = nl + 2;
        }
        out.clear();
        return c;
    }
};

// Signed by dkimpy 1.1, its key's record below: the vectors of the DKIM tests.
const std::string dkim_record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0OmYp7o/anNQznPEOYYwMtebEZfJ1oPFrWbywRlRqGOOHBd6jkFYgGQe89oUDbjUewHFwBRCPNeNkBHcZSO3zkgUO64j/hpMu7RqISKGLW0+GvfEyp6AqRmhW7OddocgLQWk/eKnjeqxOIju3N5TXd3AbzJQGXk6gLBsoSsQwLwIDAQAB";
const std::string dkim_signed_relaxed = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test;\r\n"
    " i=@example.test; q=dns/txt; s=skl; t=1792553002; h=from : to : subject\r\n"
    " : date : message-id; bh=LPJyf0TSjlshXtMhRZTZeGRtSPkTOX71Ks5ftyjz2xc=;\r\n"
    " b=pb92pzZFjun/K3ljHrvySrbAlAnd7IpoLkAD22aS5aAF4jLaGNmY/QWi13erHMg5IkuBX\r\n"
    " bC4+/8OTX6RpdRYuNjgX+lK/8+ah64RTVRoZuCVRdnm63ePhLLJwPN7dpWbBZOXKGbflHr3\r\n"
    " H2bTOw6AyORAoGveJf5gPvYUUKAzSa8=\r\n"
    "From: Alice <alice@example.test>\r\n"
    "To: bob@remote.test\r\n"
    "Subject:  Hello   there \r\n"
    "\twrapped\r\n"
    "Date: Wed, 21 Oct 2026 03:00:00 +0000\r\n"
    "Message-ID: <v1@example.test>\r\n"
    "\r\n"
    "Body line one  \r\n"
    "  indented\twith tab \r\n"
    "\r\n"
    "\r\n"
    "";
const std::string dkim_signed_simple = "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.test;\r\n"
    " i=@example.test; q=dns/txt; s=skl; t=1792553002; h=from : to : subject\r\n"
    " : date : message-id; bh=1gNY5oeOVcvTugDME0A/TCf3x/rY50inNVHjD4V9+lc=;\r\n"
    " b=TBp0g+YTE/xmr0ZGyammHx3wHEyjPceFoaqTv78lAzxT44Nsimu0qeu5MNsv4rufjlMVO\r\n"
    " ZiY7K8ce2a+NtMUlPGjWw9PdjtA0cVxYRopxzgAohk6DW6uQJuOUwTYUuCf4z9bRBoo041S\r\n"
    " cFQGIyTimVInzUmLUXAGMFzQ34ylksk=\r\n"
    "From: Alice <alice@example.test>\r\n"
    "To: bob@remote.test\r\n"
    "Subject:  Hello   there \r\n"
    "\twrapped\r\n"
    "Date: Wed, 21 Oct 2026 03:00:00 +0000\r\n"
    "Message-ID: <v1@example.test>\r\n"
    "\r\n"
    "Body line one  \r\n"
    "  indented\twith tab \r\n"
    "\r\n"
    "\r\n"
    "";

smtp_config plain_config()
{
    smtp_config c;
    c.hostname = "mx.example.com";
    c.max_size = 1 << 20;
    return c;
}

}   // namespace

TEST_CASE("addresses: paths and plain addresses as RFC 5321 writes them")
{
    address a;
    CHECK(parse_path("<Alice@Example.COM>", a, false, false));
    CHECK(a.local == "Alice");
    CHECK(a.domain == "example.com");
    CHECK(parse_path("<>", a, true, false));
    CHECK(a.empty());
    CHECK_FALSE(parse_path("<>", a, false, false));
    CHECK(parse_path("<\"john doe\"@example.com>", a, false, false));
    CHECK(parse_path("<@relay.example:bob@example.org>", a, false, false));
    CHECK(a.text() == "bob@example.org");
    CHECK(parse_path("<postmaster>", a, false, false));
    CHECK(a.local == "postmaster");
    CHECK(a.domain.empty());
    CHECK(parse_path("<x@[192.0.2.1]>", a, false, false));
    CHECK_FALSE(parse_path("alice@example.com", a, false, false));
    CHECK_FALSE(parse_path("<alice>", a, false, false));
    CHECK_FALSE(parse_path("<a..b@example.com>", a, false, false));
    CHECK_FALSE(parse_path("<.a@example.com>", a, false, false));
    CHECK_FALSE(parse_path("<a@-example.com>", a, false, false));
    CHECK_FALSE(parse_path("<a@exa_mple.com>", a, false, false));
    CHECK_FALSE(parse_path("<" + std::string(65, 'x') + "@example.com>", a, false, false));
    CHECK_FALSE(parse_path("<j\xc3\xb6rg@example.com>", a, false, false));
    CHECK(parse_path("<j\xc3\xb6rg@example.com>", a, false, true));
}

TEST_CASE("a whole conversation pipelined in one read is answered in order, its message unstuffed")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.greet();
    CHECK(f.codes() == std::vector<int>{220});
    s.input("EHLO client.example\r\nMAIL FROM:<a@example.org> SIZE=100 BODY=8BITMIME\r\n"
            "RCPT TO:<b@example.com>\r\nRCPT TO:<c@example.com>\r\nDATA\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 250, 354});
    s.input("Subject: hi\r\n\r\n..leading dot\r\n.\r\nQUIT\r\n");
    CHECK(f.codes() == std::vector<int>{250, 221});
    REQUIRE(f.messages.size() == 1);
    CHECK(f.messages[0] == "Subject: hi\r\n\r\n.leading dot\r\n");
    CHECK(f.closed);
    CHECK(s.messages() == 1);
}

TEST_CASE("BDAT: chunks cut anywhere are the message as sent, a bare LF made CRLF, and a dot ends nothing")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.greet();
    f.codes();
    s.input("EHLO c\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.com>\r\nBDAT 12\r\nSubject: x\r");
    CHECK(f.codes() == std::vector<int>{250, 250, 250});
    // The CR of a line's end in one chunk, its LF in the next.
    s.input("\nBDAT 9 LAST\r\n\n.\r\nbare\n");
    CHECK(f.codes() == std::vector<int>{250, 250});
    REQUIRE(f.messages.size() == 1);
    CHECK(f.messages[0] == "Subject: x\r\n\r\n.\r\nbare\r\n");
    // A zero chunk with LAST ends a message; one byte at a time is the same message.
    s.input("MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.com>\r\nBDAT 3\r\n");
    for (const char c : std::string("abc"))
        s.input(std::string(1, c));
    s.input("BDAT 0 LAST\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 250});
    REQUIRE(f.messages.size() == 2);
    CHECK(f.messages[1] == "abc");
    // DATA after a chunk is refused, and RSET drops what the chunks began.
    s.input("MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.com>\r\nBDAT 2\r\nhiDATA\r\nRSET\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 503, 250});
    CHECK(f.aborted == 1);
    CHECK(f.messages.size() == 2);
    // A recipient named after the first chunk is refused, not answered 250 and left out of the message.
    std::vector<std::string> asked;
    f.rcpt_rule = [&asked](const address& to) {
        asked.push_back(to.text());
        return rcpt_verdict{250, ""};
    };
    s.input("MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.com>\r\nBDAT 2\r\nhiRCPT TO:<c@example.com>\r\n"
            "BDAT 0 LAST\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 503, 250});
    CHECK(asked == std::vector<std::string>{"b@example.com"});
    REQUIRE(f.messages.size() == 3);
    CHECK(f.messages[2] == "hi");
}

TEST_CASE("DSN: NOTIFY, ORCPT, RET and ENVID are read, kept with each recipient, and refused when malformed")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.greet();
    f.codes();
    s.input("EHLO c\r\nMAIL FROM:<a@example.org> RET=HDRS ENVID=QQ+2B1\r\n"
            "RCPT TO:<b@example.com> NOTIFY=SUCCESS,DELAY ORCPT=rfc822;b+40example.com\r\n"
            "RCPT TO:<c@example.com> NOTIFY=NEVER\r\nRCPT TO:<d@example.com>\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 250, 250});
    CHECK(s.ret() == 2);
    CHECK(s.envid() == "QQ+2B1");
    REQUIRE(s.recipients_dsn().size() == 3);
    CHECK(s.recipients_dsn()[0].notify == (notify_success | notify_delay));
    CHECK(s.recipients_dsn()[0].orcpt == "rfc822;b+40example.com");
    CHECK(s.recipients_dsn()[1].notify == notify_never);
    CHECK(s.recipients_dsn()[2].notify == 0);
    s.input("RCPT TO:<e@example.com> NOTIFY=NEVER,SUCCESS\r\nRCPT TO:<e@example.com> NOTIFY=SOMETIMES\r\n"
            "RCPT TO:<e@example.com> ORCPT=rfc822;bad=x\r\nRCPT TO:<e@example.com> FOO=1\r\nRSET\r\n"
            "MAIL FROM:<a@example.org> RET=FULL RET=HDRS\r\nMAIL FROM:<a@example.org> ENVID=a+zz\r\n");
    CHECK(f.codes() == std::vector<int>{501, 501, 501, 555, 250, 501, 501});
    std::string plain;
    CHECK(xtext_decode("a+2Bb+3Dc", plain));
    CHECK(plain == "a+b=c");
    CHECK(xtext_encode("a+b=c d") == "a+2Bb+3Dc+20d");
    CHECK_FALSE(xtext_decode("a+2", plain));
    CHECK_FALSE(xtext_decode("a=b", plain));
}

TEST_CASE("EHLO says what is offered, and only where it may be used")
{
    fake f;
    smtp_config c = plain_config();
    c.tls_offered = true;
    c.auth_offered = true;
    smtp_session s(c, f);
    s.input("EHLO x\r\n");
    CHECK(f.out.find("250-STARTTLS") != std::string::npos);
    CHECK(f.out.find("AUTH") == std::string::npos);
    CHECK(f.out.find("250-SIZE 1048576") != std::string::npos);
    CHECK(f.out.find("250 ENHANCEDSTATUSCODES") != std::string::npos);
    f.out.clear();
    s.input("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
    CHECK(f.codes() == std::vector<int>{538});
}

TEST_CASE("the end of a message is found wherever the reads cut it")
{
    const std::string wire = "Subject: x\r\n\r\nline one\r\n..two\r\n.\r\n";
    const std::string want = "Subject: x\r\n\r\nline one\r\n.two\r\n";
    for (size_t cut = 1; cut < wire.size(); ++cut)
    {
        fake f;
        smtp_session s(plain_config(), f);
        s.input("HELO x\r\nMAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
        s.input(wire.substr(0, cut));
        s.input(wire.substr(cut));
        REQUIRE_MESSAGE(f.messages.size() == 1, cut);
        CHECK_MESSAGE(f.messages[0] == want, cut);
    }
    // And a byte at a time.
    fake f;
    smtp_session s(plain_config(), f);
    s.input("HELO x\r\nMAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
    for (char ch : wire)
        s.input(std::string_view(&ch, 1));
    REQUIRE(f.messages.size() == 1);
    CHECK(f.messages[0] == want);
}

TEST_CASE("a message past fifty Received lines is a loop, refused by DATA and BDAT alike, and fifty pass")
{
    std::string many, fifty;
    for (int i = 0; i < 51; ++i)
        many += "Received: from h" + std::to_string(i) + " by x\r\n";
    for (int i = 0; i < 50; ++i)
        fifty += "received: from h" + std::to_string(i) + " by x\r\n";
    fake f;
    smtp_session s(plain_config(), f);
    s.input("HELO x\r\nMAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
    f.codes();
    s.input(many + "Subject: loop\r\n\r\nbody\r\nReceived: in the body counts for nothing\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{554});
    CHECK(f.messages.empty());
    CHECK(f.aborted == 1);
    // Fifty pass, and Received lines past the header do not count.
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n" + fifty + "\r\n" + many + ".\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 354, 250});
    CHECK(f.messages.size() == 1);
    // BDAT, the header cut across chunks.
    const std::string msg = many + "\r\nbody\r\n";
    const std::string a = msg.substr(0, 700), b = msg.substr(700);
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nBDAT " + std::to_string(a.size()) + "\r\n" + a + "BDAT " +
            std::to_string(b.size()) + " LAST\r\n" + b);
    CHECK(f.codes() == std::vector<int>{250, 250, 250, 554});
    CHECK(f.messages.size() == 1);
}

TEST_CASE("a bare LF is a line's end written as CRLF, and a dot after one ends nothing")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.input("HELO x\r\nMAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
    f.codes();
    // The smuggling of 2023: a sender that ends at LF.LF would see a second message here, and this server sees one.
    s.input("one\n.\nMAIL FROM:<evil@b.org>\r\nRCPT TO:<victim@d.org>\r\nDATA\r\nforged\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{250});
    REQUIRE(f.messages.size() == 1);
    CHECK(f.messages[0] == "one\r\n.\r\nMAIL FROM:<evil@b.org>\r\nRCPT TO:<victim@d.org>\r\nDATA\r\nforged\r\n");
    // Nor does a dot after a bare LF and before a CRLF, as a server that ends lines only at CRLF would read it.
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\none\n.\r\nMAIL FROM:<evil@b.org>\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 354, 250});
    REQUIRE(f.messages.size() == 2);
    CHECK(f.messages[1] == "one\r\n.\r\nMAIL FROM:<evil@b.org>\r\n");
    // Nor one after a dot ended by a bare LF.
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\none\r\n.\n.\r\nRSET\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 354, 250});
    REQUIRE(f.messages.size() == 3);
    CHECK(f.messages[2] == "one\r\n\r\n.\r\nRSET\r\n");
    // A lone CR is a line's end too, so a server that ends lines at one reads the lines this one read.
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\nx\ry\r.\r\nz\r\n.\r\n");
    REQUIRE(f.messages.size() == 4);
    CHECK(f.messages[3] == "x\r\ny\r\n.\r\nz\r\n");
}

TEST_CASE("a message past the size is read to its end and refused, and the next one is taken")
{
    fake f;
    smtp_config c = plain_config();
    c.max_size = 100;
    smtp_session s(c, f);
    s.input("EHLO x\r\nMAIL FROM:<a@b.org> SIZE=101\r\n");
    CHECK(f.codes() == std::vector<int>{250, 552});
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
    f.codes();
    s.input(std::string(150, 'x') + "\r\n" + std::string(50, 'y') + "\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{552});
    CHECK(f.aborted == 1);
    CHECK(f.messages.empty());
    s.input("MAIL FROM:<a@b.org>\r\nRCPT TO:<c@d.org>\r\nDATA\r\nsmall\r\n.\r\n");
    CHECK(f.codes() == std::vector<int>{250, 250, 354, 250});
    CHECK(f.messages.size() == 1);
}

TEST_CASE("answers that come later are said in the order of the commands they answer")
{
    fake f;
    f.hold = true;
    f.rcpt_rule = [](const address& a) {
        return a.local == "nobody" ? rcpt_verdict{550, "No such user"} : rcpt_verdict{250, ""};
    };
    smtp_session s(plain_config(), f);
    s.input("EHLO x\r\nMAIL FROM:<a@b.org>\r\nRCPT TO:<one@d.org>\r\nRCPT TO:<nobody@d.org>\r\n"
            "RCPT TO:<two@d.org>\r\nDATA\r\nbody\r\n.\r\nNOOP\r\n");
    CHECK(f.codes() == std::vector<int>{250});
    for (int round = 0; round < 10 && !f.held.empty(); ++round)
        f.release();
    CHECK(f.codes() == std::vector<int>{250, 250, 550, 250, 354, 250, 250});
    CHECK(s.recipients().empty());
    REQUIRE(f.messages.size() == 1);
    CHECK(f.messages[0] == "body\r\n");
}

TEST_CASE("STARTTLS drops what was pipelined behind it and starts the conversation over")
{
    fake f;
    smtp_config c = plain_config();
    c.tls_offered = true;
    c.auth_offered = true;
    smtp_session s(c, f);
    s.input("EHLO x\r\nSTARTTLS\r\nMAIL FROM:<injected@b.org>\r\n");
    CHECK(f.codes() == std::vector<int>{250, 220});
    CHECK(f.tls);
    s.tls_started();
    CHECK(f.out.empty());
    s.input("MAIL FROM:<a@b.org>\r\n");
    CHECK(f.codes() == std::vector<int>{503});
    s.input("EHLO x\r\n");
    CHECK(f.out.find("STARTTLS") == std::string::npos);
    CHECK(f.out.find("250-AUTH PLAIN LOGIN") != std::string::npos);
    f.out.clear();
    s.input("STARTTLS\r\n");
    CHECK(f.codes() == std::vector<int>{503});
}

TEST_CASE("AUTH PLAIN and LOGIN sign in, a wrong password is refused, and a submission port asks for it")
{
    fake f;
    smtp_config c = plain_config();
    c.auth_offered = true;
    c.auth_in_clear = true;
    c.auth_required = true;
    smtp_session s(c, f);
    s.input("EHLO x\r\nMAIL FROM:<a@b.org>\r\n");
    CHECK(f.codes() == std::vector<int>{250, 530});
    const std::string bad = socketley::base64::encode(std::string("\0alice\0wrong", 12));
    s.input("AUTH PLAIN " + bad + "\r\n");
    CHECK(f.codes() == std::vector<int>{535});
    s.input("AUTH LOGIN\r\n");
    CHECK(f.out == "334 VXNlcm5hbWU6\r\n");
    f.out.clear();
    s.input(socketley::base64::encode("alice") + "\r\n");
    CHECK(f.out == "334 UGFzc3dvcmQ6\r\n");
    f.out.clear();
    s.input(socketley::base64::encode("secret") + "\r\n");
    CHECK(f.codes() == std::vector<int>{235});
    CHECK(s.user() == "alice");
    s.input("AUTH PLAIN\r\n");
    CHECK(f.codes() == std::vector<int>{503});
    s.input("MAIL FROM:<a@b.org>\r\n");
    CHECK(f.codes() == std::vector<int>{250});

    fake g;
    smtp_session t(c, g);
    t.input("EHLO x\r\nAUTH PLAIN\r\n");
    CHECK(g.out.substr(g.out.size() - 6) == "334 \r\n");
    g.out.clear();
    t.input(socketley::base64::encode(std::string("alice\0alice\0secret", 18)) + "\r\n");
    CHECK(g.codes() == std::vector<int>{235});
    // An identity asked for that is not the one signed in as is refused.
    fake h;
    smtp_session u(c, h);
    u.input("EHLO x\r\nAUTH PLAIN " + socketley::base64::encode(std::string("bob\0alice\0secret", 17)) + "\r\n");
    CHECK(h.codes() == std::vector<int>{250, 535});
}

TEST_CASE("errors past the limit close the connection, and a long line is refused without being kept")
{
    fake f;
    smtp_session s(plain_config(), f);
    std::string many;
    for (uint32_t i = 0; i < smtp_session::max_errors; ++i)
        many += "BOGUS\r\n";
    s.input(many);
    const auto c = f.codes();
    CHECK(c.back() == 421);
    CHECK(f.closed);
    fake g;
    smtp_session t(plain_config(), g);
    t.input(std::string(smtp_session::max_command + 10, 'x'));
    CHECK(g.codes() == std::vector<int>{500});
    t.input("\r\nNOOP\r\n");
    CHECK(g.codes().back() == 250);
}

TEST_CASE("VRFY confirms no user, EXPN expands no list, HELP points at the RFC, and none of them ends the session")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.input("VRFY alice\r\nEXPN staff\r\nHELP\r\nNOOP\r\n");
    CHECK(f.codes() == std::vector<int>{252, 502, 214, 250});
    CHECK_FALSE(f.closed);
}

TEST_CASE("commands out of order, and a DATA the store cannot take")
{
    fake f;
    smtp_session s(plain_config(), f);
    s.input("MAIL FROM:<a@b.org>\r\n");
    CHECK(f.codes() == std::vector<int>{503});
    s.input("HELO x\r\nRCPT TO:<c@d.org>\r\nDATA\r\n");
    CHECK(f.codes() == std::vector<int>{250, 503, 503});
    s.input("MAIL FROM:<a@b.org>\r\nMAIL FROM:<a@b.org>\r\nDATA\r\n");
    CHECK(f.codes() == std::vector<int>{250, 503, 554});
    f.refuse_data = true;
    s.input("RCPT TO:<c@d.org>\r\nDATA\r\n");
    CHECK(f.codes() == std::vector<int>{250, 451});
    s.input("RCPT TO:<c@d.org>\r\n");
    CHECK(f.codes() == std::vector<int>{503});
    s.input("GET / HTTP/1.1\r\n");
    CHECK(f.codes() == std::vector<int>{554});
    CHECK(f.closed);
}

TEST_CASE("DKIM: dkimpy's signatures verify here, in both canonicalizations, and a changed message does not")
{
    for (const std::string* m : {&dkim_signed_relaxed, &dkim_signed_simple})
    {
        const auto sigs = dkim::signatures(*m);
        REQUIRE(sigs.size() == 1);
        CHECK(sigs[0].d == "example.test");
        CHECK(sigs[0].s == "skl");
        std::string why;
        CHECK_MESSAGE(dkim::verify(*m, sigs[0], dkim_record, 1792552976, &why) == dkim::result::pass, why);
        // A word of the body changed, and a header the signature covers.
        std::string body = *m;
        body.replace(body.find("Body line one"), 4, "Bodx");
        CHECK(dkim::verify(body, sigs[0], dkim_record, 1792552976) == dkim::result::fail);
        std::string head = *m;
        head.replace(head.find("bob@remote.test"), 3, "eve");
        CHECK(dkim::verify(head, sigs[0], dkim_record, 1792552976) == dkim::result::fail);
    }
    const auto sigs = dkim::signatures(dkim_signed_relaxed);
    REQUIRE(sigs.size() == 1);
    CHECK(dkim::verify(dkim_signed_relaxed, sigs[0], "", 0) == dkim::result::permerror);
    CHECK(dkim::verify(dkim_signed_relaxed, sigs[0], "v=DKIM1; p=", 0) == dkim::result::fail);
    // Whitespace the relaxed canonicalization is allowed to take changes nothing.
    std::string spaced = dkim_signed_relaxed;
    spaced.replace(spaced.find("Body line one"), 13, "Body   line\tone");
    CHECK(dkim::verify(spaced, sigs[0], dkim_record, 1792552976) == dkim::result::pass);
}

TEST_CASE("DKIM: what this signs, it verifies, and the canonicalizations are RFC 6376's examples")
{
    // RFC 6376 3.4.5.
    CHECK(dkim::relaxed_header("A", " X") == "a:X");
    CHECK(dkim::relaxed_header("B ", " Y\t\r\n\tZ  ") == "b:Y Z");
    CHECK(dkim::relaxed_body(" C \r\nD \t E\r\n\r\n\r\n") == " C\r\nD E\r\n");
    CHECK(dkim::simple_body(" C \r\nD \t E\r\n\r\n\r\n") == " C \r\nD \t E\r\n");
    CHECK(dkim::relaxed_body("") == "");
    CHECK(dkim::simple_body("") == "\r\n");
    std::string why;
    char tmpl[] = "/tmp/test_mail_dkim_XXXXXX";
    REQUIRE(mkdtemp(tmpl) != nullptr);
    const std::string path = std::string(tmpl) + "/k.pem";
    const auto key = dkim::load_or_make(path, why);
    REQUIRE_MESSAGE(key, why);
    // Kept, and the same key read back.
    const auto again = dkim::load_or_make(path, why);
    REQUIRE(again);
    CHECK(dkim::public_record(key.get()) == dkim::public_record(again.get()));
    const std::string msg = "From: a@example.test\r\nTo: b@remote.test\r\nSubject: hi\r\n\r\nbody\r\n";
    const std::string signed_msg = dkim::sign(msg, "example.test", "skl", key.get(), 1000) + msg;
    const auto sigs = dkim::signatures(signed_msg);
    REQUIRE(sigs.size() == 1);
    CHECK(dkim::verify(signed_msg, sigs[0], dkim::public_record(key.get()), 1000) == dkim::result::pass);
    // A second From added on the way is caught, since From is signed once more than it is there.
    std::string two = signed_msg;
    two.insert(two.find("To: "), "From: evil@else.test\r\n");
    CHECK(dkim::verify(two, sigs[0], dkim::public_record(key.get()), 1000) == dkim::result::fail);
    // A message with two From before it is signed is signed whole, and a third added after still breaks it.
    const std::string twice = "From: a@example.test\r\nFrom: c@example.test\r\nTo: b@remote.test\r\n\r\nbody\r\n";
    const std::string signed_twice = dkim::sign(twice, "example.test", "skl", key.get(), 1000) + twice;
    const auto ts = dkim::signatures(signed_twice);
    REQUIRE(ts.size() == 1);
    CHECK(dkim::verify(signed_twice, ts[0], dkim::public_record(key.get()), 1000) == dkim::result::pass);
    std::string thrice = signed_twice;
    thrice.insert(thrice.find("To: "), "From: evil@else.test\r\n");
    CHECK(dkim::verify(thrice, ts[0], dkim::public_record(key.get()), 1000) == dkim::result::fail);
    // x= is when the signature stops vouching: it passes before and fails after (RFC 6376 3.5).
    const std::string expiring = dkim::sign(msg, "example.test", "skl", key.get(), 1000, "DKIM-Signature", "x=1500; ") + msg;
    const auto xs = dkim::signatures(expiring);
    REQUIRE(xs.size() == 1);
    CHECK(dkim::verify(expiring, xs[0], dkim::public_record(key.get()), 1400) == dkim::result::pass);
    CHECK(dkim::verify(expiring, xs[0], dkim::public_record(key.get()), 1600) == dkim::result::fail);
    std::filesystem::remove_all(tmpl);
}

TEST_CASE("compose: headers encoded, text quoted-printable, parts and attachments, and no recipient refused")
{
    compose c;
    c.to = {"Bob Smith <bob@remote.test>", "carol@remote.test"};
    c.bcc = {"hidden@remote.test"};
    c.subject = "Grüße";
    c.text = "Zeile mit Umlaut ä\n.Punkt\n";
    c.html = "<p>hi</p>";
    c.attachments.push_back({"a.txt", "text/plain", "attached"});
    address from;
    REQUIRE(parse_address("alice@example.test", from));
    composed out;
    std::string why;
    REQUIRE_MESSAGE(compose_message(c, from, "Alice Ä", "id1@example.test", 0, out, why), why);
    CHECK(out.from == "alice@example.test");
    CHECK(out.rcpts == std::vector<std::string>{"bob@remote.test", "carol@remote.test", "hidden@remote.test"});
    const std::string_view h = header_block(out.message);
    CHECK(header_value(h, "Subject") == "=?UTF-8?B?R3LDvMOfZQ==?=");
    CHECK(header_value(h, "From") == "=?UTF-8?B?QWxpY2Ugw4Q=?= <alice@example.test>");
    CHECK(header_value(h, "To") == "Bob Smith <bob@remote.test>, carol@remote.test");
    CHECK(header_value(h, "Bcc").empty());
    CHECK(header_value(h, "Date") == "Thu, 01 Jan 1970 00:00:00 +0000");
    CHECK(header_value(h, "Content-Type").starts_with("multipart/mixed; boundary="));
    CHECK(out.message.find("multipart/alternative") != std::string::npos);
    CHECK(out.message.find("Zeile mit Umlaut =C3=A4\r\n.Punkt\r\n") != std::string::npos);
    CHECK(out.message.find("YXR0YWNoZWQ=\r\n") != std::string::npos);
    // Every line ends in CRLF.
    for (size_t i = 0; i < out.message.size(); ++i)
        if (out.message[i] == '\n')
            REQUIRE((i > 0 && out.message[i - 1] == '\r'));
    CHECK(out.message.find("\r\r") == std::string::npos);
    compose none;
    CHECK_FALSE(compose_message(none, from, "", "x@y", 0, out, why));
    compose injected = c;
    injected.headers = {"X-Ok: fine\r\nBcc: evil@else.test"};
    CHECK_FALSE(compose_message(injected, from, "", "x@y", 0, out, why));
    compose own = c;
    own.headers = {"Subject: second"};
    CHECK_FALSE(compose_message(own, from, "", "x@y", 0, out, why));
}

TEST_CASE("quoted-printable keeps lines under 76 and a trailing space safe")
{
    const std::string qp = quoted_printable(std::string(200, 'a') + " \r\nend\r\n");
    size_t line = 0;
    for (size_t i = 0; i < qp.size(); ++i)
    {
        if (qp[i] == '\r')
        {
            CHECK(line <= 76);
            line = 0;
            ++i;
            continue;
        }
        ++line;
    }
    CHECK(qp.find("=20\r\nend") != std::string::npos);
    CHECK(quoted_printable("a=b") == "a=3Db");
}

TEST_CASE("aliases: addresses and catch-alls, refused when a line is none")
{
    alias_table t;
    std::string why;
    REQUIRE(t.parse("# who gets what\ninfo@Example.test  alice, bob@remote.test\n*@example.test carol\n", why));
    const auto* a = t.find("INFO", "example.test");
    REQUIRE(a);
    CHECK(*a == std::vector<std::string>{"alice", "bob@remote.test"});
    const auto* any = t.find("whoever", "example.test");
    REQUIRE(any);
    CHECK(*any == std::vector<std::string>{"carol"});
    CHECK(t.find("x", "other.test") == nullptr);
    CHECK_FALSE(t.parse("info@example.test\n", why));
    CHECK_FALSE(t.parse("not-an-address alice\n", why));
    CHECK_FALSE(t.parse("a@example.test bad@@x\n", why));
}

namespace
{

// Records of a test's own, by name; a name named nowhere does not exist.
struct table_resolver : check_resolver
{
    std::map<std::string, std::vector<std::string>> txts, addresses, mxs;
    bool txt(const std::string& name, std::vector<std::string>& out, bool& nx) override { return get(txts, name, out, nx); }
    bool addrs(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return get(addresses, name, out, nx);
    }
    bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) override { return get(mxs, name, out, nx); }
    bool get(const std::map<std::string, std::vector<std::string>>& m, const std::string& name,
             std::vector<std::string>& out, bool& nx)
    {
        const auto it = m.find(name);
        nx = it == m.end();
        if (!nx)
            out = it->second;
        return true;
    }
};

}   // namespace

TEST_CASE("SPF: mechanisms, qualifiers, include, redirect, macros and the lookup limit")
{
    table_resolver r;
    r.txts["example.org"] = {"v=spf1 ip4:192.0.2.0/24 a:mail.example.org mx include:_spf.partner.test -all"};
    r.addresses["mail.example.org"] = {"198.51.100.7"};
    r.mxs["example.org"] = {"mx1.example.org"};
    r.addresses["mx1.example.org"] = {"203.0.113.9", "2001:db8::25"};
    r.txts["_spf.partner.test"] = {"v=spf1 ip4:10.1.0.0/16 ~all"};
    CHECK(spf_check("192.0.2.44", "example.org", "a@example.org", r) == "pass");
    CHECK(spf_check("198.51.100.7", "example.org", "a@example.org", r) == "pass");
    CHECK(spf_check("203.0.113.9", "example.org", "a@example.org", r) == "pass");
    CHECK(spf_check("10.1.2.3", "example.org", "a@example.org", r) == "pass");
    CHECK(spf_check("8.8.8.8", "example.org", "a@example.org", r) == "fail");
    r.txts["soft.test"] = {"v=spf1 ?ip4:1.2.3.4 ~all"};
    CHECK(spf_check("1.2.3.4", "soft.test", "x@soft.test", r) == "neutral");
    CHECK(spf_check("1.2.3.5", "soft.test", "x@soft.test", r) == "softfail");
    CHECK(spf_check("1.2.3.5", "nowhere.test", "x@nowhere.test", r) == "none");
    r.txts["two.test"] = {"v=spf1 -all", "v=spf1 +all"};
    CHECK(spf_check("1.2.3.5", "two.test", "x@two.test", r) == "permerror");
    r.txts["redir.test"] = {"v=spf1 redirect=example.org"};
    CHECK(spf_check("192.0.2.1", "redir.test", "x@redir.test", r) == "pass");
    CHECK(spf_check("9.9.9.9", "redir.test", "x@redir.test", r) == "fail");
    r.txts["macro.test"] = {"v=spf1 exists:%{i}.%{l}._spf.%{d} -all"};
    r.addresses["192.0.2.5.alice._spf.macro.test"] = {"127.0.0.2"};
    CHECK(spf_check("192.0.2.5", "macro.test", "alice@macro.test", r) == "pass");
    CHECK(spf_check("192.0.2.5", "macro.test", "bob@macro.test", r) == "fail");
    // An include that loops on itself runs out of lookups rather than recursing for ever.
    r.txts["loop.test"] = {"v=spf1 include:loop.test -all"};
    CHECK(spf_check("1.1.1.1", "loop.test", "x@loop.test", r) == "permerror");
    r.txts["cidr.test"] = {"v=spf1 a:host.cidr.test/24 -all"};
    r.addresses["host.cidr.test"] = {"192.0.2.200"};
    CHECK(spf_check("192.0.2.9", "cidr.test", "x@cidr.test", r) == "pass");
    CHECK(spf_check("192.0.3.9", "cidr.test", "x@cidr.test", r) == "fail");
    // ip6 with and without a length, and an IPv6 client against ip4 alone.
    r.txts["six.test"] = {"v=spf1 ip6:2001:db8::/32 ip6:2001:db9::7 ip4:192.0.2.0/24 -all"};
    CHECK(spf_check("2001:db8:ffff::1", "six.test", "x@six.test", r) == "pass");
    CHECK(spf_check("2001:db9::7", "six.test", "x@six.test", r) == "pass");
    CHECK(spf_check("2001:db9::8", "six.test", "x@six.test", r) == "fail");
    CHECK(spf_check("2001:db7::1", "six.test", "x@six.test", r) == "fail");
    r.txts["badsix.test"] = {"v=spf1 ip6:2001:db8::/129 -all"};
    CHECK(spf_check("2001:db8::1", "badsix.test", "x@badsix.test", r) == "permerror");
    // ptr matches nothing, as RFC 7208 5.5 says not to rely on it, and the mechanisms after it still decide.
    r.txts["ptr.test"] = {"v=spf1 ptr ip4:192.0.2.0/24 -all"};
    CHECK(spf_check("192.0.2.1", "ptr.test", "x@ptr.test", r) == "pass");
    CHECK(spf_check("198.51.100.1", "ptr.test", "x@ptr.test", r) == "fail");
    // exp= explains a fail and changes nothing of it; a modifier twice is no record, whatever matches first.
    r.txts["exp.test"] = {"v=spf1 -all exp=explain.%{d}"};
    CHECK(spf_check("1.2.3.4", "exp.test", "x@exp.test", r) == "fail");
    r.txts["twice.test"] = {"v=spf1 +all exp=a.test exp=b.test"};
    CHECK(spf_check("1.2.3.4", "twice.test", "x@twice.test", r) == "permerror");
    r.txts["redir2.test"] = {"v=spf1 redirect=example.org redirect=soft.test"};
    CHECK(spf_check("192.0.2.1", "redir2.test", "x@redir2.test", r) == "permerror");
    r.txts["unknown.test"] = {"v=spf1 future=thing ip4:1.2.3.4 -all"};
    CHECK(spf_check("1.2.3.4", "unknown.test", "x@unknown.test", r) == "pass");
}

TEST_CASE("DMARC: aligned SPF or DKIM passes, a policy is taken from the organizational domain")
{
    table_resolver r;
    const std::string msg = "From: Alice <alice@news.example.test>\r\nTo: b@here.test\r\nSubject: x\r\n\r\nbody\r\n";
    r.txts["example.test"] = {"v=spf1 ip4:192.0.2.1 -all"};
    r.txts["_dmarc.example.test"] = {"v=DMARC1; p=reject; sp=quarantine"};
    // A subdomain is the parent's organization by the system's suffix list; without one alignment is strict.
    const bool psl = !socketley::public_suffix::system_list().empty();
    if (!psl)
        MESSAGE("no system public suffix list: news.example.test is its own organization, with no policy");
    // SPF passes for the parent domain, aligned under relaxed alignment.
    auto res = check_inbound(msg, "192.0.2.1", "mx.example.test", "bounce@example.test", r, 0);
    CHECK(res.spf == "pass");
    CHECK(res.dmarc == (psl ? "pass" : "none"));
    CHECK_FALSE(res.reject());
    // From another address: SPF fails, nothing aligned, and the subdomain's policy is sp=quarantine.
    res = check_inbound(msg, "203.0.113.5", "evil.test", "x@example.test", r, 0);
    CHECK(res.spf == "fail");
    CHECK(res.dmarc == (psl ? "fail" : "none"));
    CHECK(res.dmarc_policy == (psl ? "quarantine" : ""));
    CHECK(res.quarantine() == psl);
    if (psl)
        CHECK(res.header().find("dmarc=fail header.from=news.example.test (p=quarantine)") != std::string::npos);
    // The domain's own address is the policy's own p=.
    const std::string own = "From: alice@example.test\r\n\r\nx\r\n";
    res = check_inbound(own, "203.0.113.5", "evil.test", "x@else.test", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.reject());
    // No record: none, whatever SPF says.
    res = check_inbound("From: a@nodmarc.test\r\n\r\nx\r\n", "1.2.3.4", "h", "a@nodmarc.test", r, 0);
    CHECK(res.dmarc == "none");
    // Authors of two domains pass for no domain's policy, and are refused as a failing one would be.
    res = check_inbound("From: a@example.test, b@else.test\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.reject());
    // A bounce's SPF is HELO's.
    res = check_inbound(own, "192.0.2.1", "example.test", "", r, 0);
    CHECK(res.spf_domain == "example.test");
    CHECK(res.spf == "pass");
    CHECK(organizational_domain("a.b.example.test") == (psl ? "example.test" : "a.b.example.test"));
    CHECK(organizational_domain("example") == "example");
}

TEST_CASE("DMARC: a From written with a space before its colon is an author, counted as every other")
{
    table_resolver r;
    r.txts["_dmarc.example.test"] = {"v=DMARC1; p=reject"};
    // The name is trimmed as header_value, IMAP's ENVELOPE and JMAP read it, so its domain's policy holds.
    auto res = check_inbound("From : ceo@example.test\r\nSubject: x\r\n\r\nbody\r\n", "203.0.113.5", "evil.test",
                             "x@else.test", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.reject());
    // Beside another From it is a second author, and the message is refused as one whose author cannot be told.
    res = check_inbound("From: a@nodmarc.test\r\nFrom\t: ceo@example.test\r\n\r\nbody\r\n", "203.0.113.5", "evil.test",
                        "a@nodmarc.test", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.reject());
    CHECK(from_headers("From : a@b.test\r\nfrom: c@d.test\r\n FROM: folded\r\n\r\n") == 2);
    // A From behind a bare LF is one a reader may see; header_value does not, so its author reads as none.
    std::string first;
    CHECK(from_headers("Subject: x\nFrom: ceo@example.test\r\n\r\n", &first) == 1);
    CHECK(first.empty());
    CHECK(from_headers("FROM :  a@b.test \r\n\r\n", &first) == 1);
    CHECK(first == "a@b.test");
    res = check_inbound("Subject: x\nFrom: ceo@example.test\r\n\r\nbody\r\n", "203.0.113.5", "evil.test", "x@else.test", r, 0);
    CHECK(res.reject());
}

TEST_CASE("Submission: a From is the user's own, one From at most, or none")
{
    const auto alice = [](const address& a) { return a.local == "alice" && a.domain == "example.test"; };
    CHECK(authors_owned("Subject: x\r\n\r\n", alice));
    CHECK(authors_owned("From: Alice <alice@example.test>\r\n\r\n", alice));
    CHECK_FALSE(authors_owned("From: ceo@example.test\r\n\r\n", alice));
    CHECK_FALSE(authors_owned("From: alice@example.test, ceo@example.test\r\n\r\n", alice));
    CHECK_FALSE(authors_owned("From: alice@example.test\r\nFrom : alice@example.test\r\n\r\n", alice));
    CHECK_FALSE(authors_owned("From: <\r\n\r\n", alice));
    CHECK_FALSE(authors_owned("Subject: x\nFrom: ceo@example.test\r\n\r\n", alice));
}

TEST_CASE("DMARC: a DKIM signature of the From domain passes where SPF does not")
{
    table_resolver r;
    r.txts["skl._domainkey.example.test"] = {dkim_record};
    r.txts["_dmarc.example.test"] = {"v=DMARC1; p=reject; adkim=s"};
    auto res = check_inbound(dkim_signed_relaxed, "203.0.113.5", "h", "x@else.test", r, 1792552976);
    REQUIRE(res.dkim.size() == 1);
    CHECK(res.dkim[0].first == "pass");
    CHECK(res.dkim[0].second == "example.test");
    CHECK(res.dmarc == "pass");
    std::string changed = dkim_signed_relaxed;
    changed.replace(changed.find("Body line one"), 4, "Bodx");
    res = check_inbound(changed, "203.0.113.5", "h", "x@else.test", r, 1792552976);
    CHECK(res.dkim[0].first == "fail");
    CHECK(res.reject());
}

namespace
{

const std::string mime_msg =
    "From: \"Alice A.\" <alice@example.test>\r\n"
    "To: bob@remote.test, Undisclosed: carol@x.test, dan@y.test;\r\n"
    "Subject: =?UTF-8?B?R3LDvMOfZQ==?=\r\n"
    "Date: Wed, 21 Oct 2026 03:00:00 +0000\r\n"
    "Message-ID: <m1@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"outer\"\r\n"
    "\r\n"
    "preamble\r\n"
    "--outer\r\n"
    "Content-Type: multipart/alternative; boundary=inner\r\n"
    "\r\n"
    "--inner\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "plain text\r\n"
    "second line\r\n"
    "--inner\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<p>html</p>\r\n"
    "--inner--\r\n"
    "--outer\r\n"
    "Content-Type: application/pdf; name=\"a.pdf\"\r\n"
    "Content-Disposition: attachment; filename=\"a.pdf\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "JVBERi0=\r\n"
    "--outer\r\n"
    "Content-Type: message/rfc822\r\n"
    "\r\n"
    "From: inner@z.test\r\n"
    "Subject: enclosed\r\n"
    "\r\n"
    "inner body\r\n"
    "--outer--\r\n"
    "epilogue\r\n";

}   // namespace

TEST_CASE("MIME: a message's parts, nested multiparts and an enclosed message")
{
    const auto root = mime::parse(mime_msg);
    CHECK(root.multipart());
    REQUIRE(root.children.size() == 3);
    CHECK(root.children[0].subtype == "alternative");
    REQUIRE(root.children[0].children.size() == 2);
    CHECK(root.children[0].children[0].lines == 2);
    CHECK(root.children[1].type == "application");
    CHECK(root.children[1].encoding == "BASE64");
    CHECK(root.children[1].disposition == "attachment");
    CHECK(root.children[2].message());
    REQUIRE(root.children[2].children.size() == 1);
    std::string out;
    REQUIRE(mime::section(mime_msg, root, "1.1", out));
    CHECK(out == "plain text\r\nsecond line");
    REQUIRE(mime::section(mime_msg, root, "1.2", out));
    CHECK(out == "<p>html</p>");
    REQUIRE(mime::section(mime_msg, root, "2", out));
    CHECK(out == "JVBERi0=");
    REQUIRE(mime::section(mime_msg, root, "2.MIME", out));
    CHECK(out.find("Content-Disposition: attachment") != std::string::npos);
    REQUIRE(mime::section(mime_msg, root, "3.HEADER", out));
    CHECK(out == "From: inner@z.test\r\nSubject: enclosed\r\n\r\n");
    REQUIRE(mime::section(mime_msg, root, "3.TEXT", out));
    CHECK(out == "inner body");
    REQUIRE(mime::section(mime_msg, root, "3.1", out));
    CHECK(out == "inner body");
    REQUIRE(mime::section(mime_msg, root, "HEADER.FIELDS (SUBJECT DATE)", out));
    CHECK(out == "Subject: =?UTF-8?B?R3LDvMOfZQ==?=\r\nDate: Wed, 21 Oct 2026 03:00:00 +0000\r\n\r\n");
    REQUIRE(mime::section(mime_msg, root, "HEADER.FIELDS.NOT (SUBJECT DATE FROM TO MESSAGE-ID MIME-VERSION)", out));
    CHECK(out == "Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n");
    REQUIRE(mime::section(mime_msg, root, "TEXT", out));
    CHECK(out.starts_with("preamble\r\n--outer"));
    REQUIRE(mime::section(mime_msg, root, "", out));
    CHECK(out == mime_msg);
    CHECK_FALSE(mime::section(mime_msg, root, "4", out));
    CHECK_FALSE(mime::section(mime_msg, root, "1.3", out));
    CHECK_FALSE(mime::section(mime_msg, root, "0", out));
}

TEST_CASE("MIME: ENVELOPE and BODYSTRUCTURE as RFC 3501 writes them")
{
    const auto root = mime::parse(mime_msg);
    const std::string env = mime::envelope(std::string_view(mime_msg).substr(0, root.header_len));
    CHECK(env == "(\"Wed, 21 Oct 2026 03:00:00 +0000\" \"=?UTF-8?B?R3LDvMOfZQ==?=\" "
                 "((\"Alice A.\" NIL \"alice\" \"example.test\")) ((\"Alice A.\" NIL \"alice\" \"example.test\")) "
                 "((\"Alice A.\" NIL \"alice\" \"example.test\")) "
                 "((NIL NIL \"bob\" \"remote.test\")(NIL NIL \"Undisclosed\" NIL)(NIL NIL \"carol\" \"x.test\")"
                 "(NIL NIL \"dan\" \"y.test\")(NIL NIL NIL NIL)) NIL NIL NIL \"<m1@example.test>\")");
    const std::string bs = mime::structure(root, mime_msg, true);
    CHECK(bs.starts_with("(((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"utf-8\") NIL NIL \"7BIT\" 23 2 NIL NIL NIL NIL)"));
    CHECK(bs.find("(\"APPLICATION\" \"PDF\" (\"NAME\" \"a.pdf\") NIL NIL \"BASE64\" 8 NIL (\"ATTACHMENT\" "
                  "(\"FILENAME\" \"a.pdf\")) NIL NIL)") != std::string::npos);
    CHECK(bs.find("(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\"") != std::string::npos);
    CHECK(bs.find("\"MIXED\" (\"BOUNDARY\" \"outer\") NIL NIL NIL)") != std::string::npos);
    const std::string body = mime::structure(root, mime_msg, false);
    CHECK(body.find("(\"BOUNDARY\"") == std::string::npos);
    CHECK(body.find("ATTACHMENT") == std::string::npos);
    // A message that is no MIME at all is one text part.
    const std::string plain = "Subject: x\r\n\r\nhello\r\nworld\r\n";
    const auto p = mime::parse(plain);
    CHECK(mime::structure(p, plain, false) == "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 14 2)");
    std::string out;
    REQUIRE(mime::section(plain, p, "1", out));
    CHECK(out == "hello\r\nworld\r\n");
    CHECK(mime::imap_string("a\"b") == "\"a\\\"b\"");
    CHECK(mime::imap_string("Gr\xc3\xbc\xc3\x9f") == "{6}\r\nGr\xc3\xbc\xc3\x9f");
}

TEST_CASE("MTA-STS: the record's id, the policy's fields, the exchangers it names, and the cache line")
{
    namespace tp = socketley::mail::tls_policy;
    std::string id;
    CHECK(tp::sts_record_id("v=STSv1; id=20261021T1", id));
    CHECK(id == "20261021T1");
    CHECK(tp::sts_record_id("v=STSv1;id=a1;", id));
    CHECK_FALSE(tp::sts_record_id("id=a1; v=STSv1", id));
    CHECK_FALSE(tp::sts_record_id("v=STSv2; id=a1", id));
    CHECK_FALSE(tp::sts_record_id("v=STSv1; id=bad-id", id));
    CHECK_FALSE(tp::sts_record_id("v=spf1 -all", id));
    tp::sts p;
    int64_t age = 0;
    std::string why;
    REQUIRE(tp::parse_sts("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.Example.NET.\r\n"
                          "max_age: 99999999\r\n", p, age, why));
    CHECK(p.mode == tp::sts_mode::enforce);
    CHECK(age == 31557600);
    CHECK(tp::mx_matches(p, "MAIL.example.com."));
    CHECK(tp::mx_matches(p, "mx1.example.net"));
    CHECK_FALSE(tp::mx_matches(p, "example.net"));
    CHECK_FALSE(tp::mx_matches(p, "a.b.example.net"));
    CHECK_FALSE(tp::mx_matches(p, "evilexample.net"));
    CHECK_FALSE(tp::parse_sts("version: STSv1\nmode: enforce\nmax_age: 60\n", p, age, why));
    CHECK_FALSE(tp::parse_sts("version: STSv1\nmode: sometimes\nmx: a\nmax_age: 60\n", p, age, why));
    CHECK_FALSE(tp::parse_sts("mode: testing\nmx: a\nmax_age: 60\n", p, age, why));
    REQUIRE(tp::parse_sts("version: STSv1\nmode: none\nmax_age: 60\n", p, age, why));
    p.id = "x1";
    p.mode = tp::sts_mode::testing;
    p.mx = {"a.test", "*.b.test"};
    p.expires_s = 1792553002;
    std::string domain;
    tp::sts back;
    REQUIRE(tp::from_cache_line(tp::cache_line("b.test", p), domain, back));
    CHECK(domain == "b.test");
    CHECK(back.id == "x1");
    CHECK(back.mode == tp::sts_mode::testing);
    CHECK(back.mx == p.mx);
    CHECK(back.expires_s == p.expires_s);
}

TEST_CASE("DANE: TLSA records SMTP can use, and those it cannot")
{
    namespace tp = socketley::mail::tls_policy;
    tp::tlsa t;
    REQUIRE(tp::parse_tlsa(std::string("\x03\x01\x01", 3) + std::string(32, 'a'), t));
    CHECK(t.usage == 3);
    CHECK(tp::usable(t));
    t.data.resize(31);
    CHECK_FALSE(tp::usable(t));
    REQUIRE(tp::parse_tlsa(std::string("\x02\x00\x02", 3) + std::string(64, 'b'), t));
    CHECK(tp::usable(t));
    REQUIRE(tp::parse_tlsa(std::string("\x01\x01\x01", 3) + std::string(32, 'c'), t));
    CHECK_FALSE(tp::usable(t));
    REQUIRE(tp::parse_tlsa(std::string("\x03\x01\x00", 3) + "der", t));
    CHECK(tp::usable(t));
    CHECK_FALSE(tp::parse_tlsa("\x03\x01\x01", t));
}

TEST_CASE("the Public Suffix List: rules, wildcards and exceptions decide the registrable domain")
{
    socketley::public_suffix::list l;
    l.load("// a comment\ncom\nuk\nco.uk\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n");
    CHECK(l.registrable("mail.example.co.uk") == "example.co.uk");
    CHECK(l.registrable("Example.CO.UK.") == "example.co.uk");
    CHECK(l.registrable("co.uk") == "co.uk");
    CHECK(l.registrable("a.b.example.com") == "example.com");
    CHECK(l.registrable("x.y.ck") == "x.y.ck");
    CHECK(l.registrable("z.x.y.ck") == "x.y.ck");
    CHECK(l.registrable("www.ck") == "www.ck");
    CHECK(l.registrable("a.www.ck") == "www.ck");
    CHECK(l.registrable("me.blogspot.com") == "me.blogspot.com");
    CHECK(l.registrable("a.b.example.test") == "example.test");
    CHECK(l.registrable("localhost") == "localhost");
    // The system's list where the publicsuffix package put one, and a name its own where it did not.
    if (!socketley::public_suffix::system_list().empty())
    {
        CHECK(organizational_domain("mail.example.co.uk") == "example.co.uk");
        CHECK(organizational_domain("a.b.example.com.au") == "example.com.au");
    }
    else
    {
        MESSAGE("no system public suffix list: alignment is strict");
        CHECK(organizational_domain("mail.example.co.uk") == "mail.example.co.uk");
    }
}

TEST_CASE("ManageSieve: a sign-in answered at once, the commands pipelined behind it, a literal cut anywhere")
{
    struct h : managesieve_session::hooks
    {
        std::string out;
        void reply(std::string_view b) override { out.append(b); }
        void start_tls() override {}
        void login(std::string u, std::string p, std::function<void(account, std::string)> done) override
        {
            done(u == "alice" && p == "pw" ? account::yes : account::no, u);
        }
        void close() override {}
        void offload(std::function<void()> job, std::function<void()> done) override
        {
            job();
            done();
        }
    } hooks;
    const std::string dir = "/tmp/test-mail-sieve-" + std::to_string(::getpid());
    std::filesystem::remove_all(dir);
    sieve_store store(dir);
    managesieve_config cfg;
    cfg.hostname = "mx.test";
    cfg.login_in_clear = true;
    managesieve_session s(cfg, hooks, store);
    s.greet();
    CHECK(hooks.out.find("\"SASL\" \"PLAIN\"") != std::string::npos);
    hooks.out.clear();
    // The response on a line of its own, answered at once, with a PUTSCRIPT whose literal follows in the same read.
    const std::string all = std::string("AUTHENTICATE \"PLAIN\"\r\n\"") + socketley::base64::encode(std::string("\0alice\0pw", 9)) +
                            "\"\r\nPUTSCRIPT \"s\" {5+}\r\nkeep;\r\nSETACTIVE \"s\"\r\n";
    s.input(all);
    CHECK(s.user() == "alice");
    CHECK(hooks.out.find("OK \"Putscript completed\"") != std::string::npos);
    CHECK(hooks.out.find("OK \"Setactive completed\"") != std::string::npos);
    CHECK(store.active_name("alice") == "s");
    CHECK(store.active("alice") != nullptr);
    hooks.out.clear();
    s.input("GETSCRIPT \"s\"\r\nDELETESCRIPT \"s\"\r\nRENAMESCRIPT \"s\" \"t\"\r\nLISTSCRIPTS\r\n");
    CHECK(hooks.out.find("{5}\r\nkeep;\r\nOK") != std::string::npos);
    CHECK(hooks.out.find("NO (ACTIVE)") != std::string::npos);
    CHECK(hooks.out.find("\"t\" ACTIVE") != std::string::npos);
    // The same conversation cut every three bytes.
    hooks.out.clear();
    managesieve_session cut(cfg, hooks, store);
    for (size_t i = 0; i < all.size(); i += 3)
        cut.input(all.substr(i, 3));
    CHECK(cut.user() == "alice");
    CHECK(hooks.out.find("OK \"Setactive completed\"") != std::string::npos);
    std::filesystem::remove_all(dir);
}

TEST_CASE("SORT and THREAD: the base subject, the keys, and threads by subject and by references")
{
    namespace io = socketley::mail::imap_order;
    bool reply = false;
    CHECK(io::base_subject("Re: Re:  Lunch   plans (fwd)", &reply) == "Lunch plans");
    CHECK(reply);
    CHECK(io::base_subject("[list] Fwd: [x] re : Budget", &reply) == "Budget");
    CHECK(io::base_subject("[fwd: Re: Lunch]", &reply) == "Lunch");
    CHECK(io::base_subject("[only a blob]", &reply) == "[only a blob]");
    CHECK(io::base_subject("Budget", &reply) == "Budget");
    CHECK_FALSE(reply);
    CHECK(io::base_subject("=?utf-8?q?R=C3=A9sum=C3=A9?=") == "R\xc3\xa9sum\xc3\xa9");
    std::vector<io::key> keys;
    CHECK(io::parse_keys({"REVERSE", "date", "SUBJECT"}, keys));
    CHECK(keys.size() == 2);
    CHECK(keys[0].reverse);
    CHECK_FALSE(io::parse_keys({"REVERSE"}, keys));
    CHECK_FALSE(io::parse_keys({"COLOUR"}, keys));
    const auto make = [](uint32_t n, std::string head) {
        io::entry e;
        e.number = n;
        e.seq = n - 1;
        e.arrival_ms = 1000;
        io::read(e, head + "\r\n");
        return e;
    };
    std::vector<io::entry> v = {
        make(1, "Subject: A\r\nMessage-ID: <1@x>\r\nDate: Mon, 19 Oct 2026 10:00:00 +0000\r\n"),
        make(2, "Subject: Re: A\r\nMessage-ID: <2@x>\r\nReferences: <1@x>\r\nDate: Mon, 19 Oct 2026 11:00:00 +0000\r\n"),
        make(3, "Subject: Re: A\r\nMessage-ID: <3@x>\r\nReferences: <1@x>\r\nDate: Mon, 19 Oct 2026 12:00:00 +0000\r\n"),
        make(4, "Subject: B\r\nMessage-ID: <4@x>\r\nIn-Reply-To: <gone@x>\r\nDate: Sun, 18 Oct 2026 10:00:00 +0000\r\n"),
        make(5, "Subject: B\r\nMessage-ID: <5@x>\r\nReferences: <gone@x>\r\nDate: Tue, 20 Oct 2026 10:00:00 +0000\r\n"),
    };
    // A parent never seen is a placeholder over its two replies; 1 has two children, so they are branches.
    CHECK(io::references(v) == "((4)(5))(1 (2)(3))");
    CHECK(io::ordered_subject(v) == "(4 5)(1 (2)(3))");
    io::sort(v, {{io::key::kind::date, true}});
    CHECK(v.front().number == 5);
    // A loop in the references and a chain far deeper than any thread are taken without a loop or a crash.
    std::vector<io::entry> deep;
    for (uint32_t i = 1; i <= 3000; ++i)
        deep.push_back(make(i, "Subject: d\r\nMessage-ID: <" + std::to_string(i) + "@d>\r\nReferences: <" +
                                   std::to_string(i + 1) + "@d>\r\n"));
    const std::string t = io::references(deep);
    CHECK(t.find("3000") != std::string::npos);
    CHECK(std::count(t.begin(), t.end(), '(') == std::count(t.begin(), t.end(), ')'));
    std::vector<io::entry> loop = {make(1, "Message-ID: <a@l>\r\nReferences: <b@l>"),
                                   make(2, "Message-ID: <b@l>\r\nReferences: <a@l>")};
    CHECK(io::references(loop).size() > 2);
}

TEST_CASE("DEFLATE: what the compressor writes in pieces, each flushed, the inflater opens as it comes")
{
    socketley::deflater d;
    socketley::inflater in;
    std::string sent, got, wire;
    std::string text;
    for (int i = 0; i < 4000; ++i)
        text += "* " + std::to_string(i) + " FETCH (UID " + std::to_string(i + 100) + " FLAGS (\\Seen))\r\n";
    uint32_t x = 12345;
    std::string noise(70000, '\0');
    for (char& c : noise)
    {
        x = x * 1103515245u + 12345u;
        c = static_cast<char>(x >> 24);
    }
    const std::string runs(100000, 'a');
    // Many pieces, small and large, across the 32 KiB the history holds; each one opens fully on its own arrival.
    for (const std::string* part : std::initializer_list<const std::string*>{&text, &noise, &runs, &text})
        for (size_t at = 0; at < part->size();)
        {
            const size_t n = std::min<size_t>(part->size() - at, 1 + (at * 7919) % 20000);
            const std::string piece = part->substr(at, n);
            at += n;
            std::string z;
            d.compress(piece, z);
            wire += z;
            sent += piece;
            in.feed(reinterpret_cast<const uint8_t*>(z.data()), z.size());
            for (;;)
            {
                const auto r = in.run(got, 1u << 20);
                if (r != socketley::inflater::result::output_full)
                {
                    CHECK(r == socketley::inflater::result::need_input);
                    break;
                }
            }
            REQUIRE(got.size() == sent.size());
        }
    CHECK(got == sent);
    // Text compresses; noise grows by little.
    CHECK(wire.size() < sent.size() - noise.size() / 2);
}

TEST_CASE("MIME: hostile shapes cost their length, and parameters and charsets read as clients write them")
{
    using clock = std::chrono::steady_clock;
    // A header of a million bytes of words never closed, and of a quarter million "Re: ", each read in linear time.
    std::string open_words;
    while (open_words.size() < (1u << 20))
        open_words += "=?x?q?a";
    auto t0 = clock::now();
    CHECK(mime::decode_words(open_words).size() == open_words.size());
    std::string res;
    while (res.size() < (1u << 20))
        res += "Re: ";
    res += "Lunch";
    CHECK(socketley::mail::imap_order::base_subject(res) == "Lunch");
    CHECK(clock::now() - t0 < std::chrono::seconds(2));
    // Fifty thousand empty parts are read as ten thousand at most.
    std::string many = "Content-Type: multipart/mixed; boundary=b\r\n\r\n";
    for (int i = 0; i < 50000; ++i)
        many += "--b\r\n\r\n";
    many += "--b--\r\n";
    CHECK(mime::parse(many).children.size() < 10000);
    // A line the boundary only begins is no delimiter (RFC 2046 5.1.1).
    const std::string prefix = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\none\r\n--bXYZ\r\nstill one\r\n"
                               "--b  \r\n\r\ntwo\r\n--b--\r\n";
    const auto p = mime::parse(prefix);
    REQUIRE(p.children.size() == 2);
    std::string out;
    REQUIRE(mime::section(prefix, p, "1", out));
    CHECK(out == "one\r\n--bXYZ\r\nstill one");
    CHECK_FALSE(mime::section(prefix, p, "18446744073709551617", out));
    // RFC 2231: continuations joined, the encoded value kept as name* for BODYSTRUCTURE and read as UTF-8.
    const std::string named = "Content-Type: application/pdf; name*0*=utf-8''r%C3%A9; name*1=sum.pdf\r\n"
                              "Content-Disposition: attachment; filename*=iso-8859-1'en'%E9t%E9.txt\r\n\r\nx";
    const auto q = mime::parse(named);
    CHECK(mime::param(q.params, "name") == "r\xc3\xa9sum.pdf");
    CHECK(mime::param(q.disposition_params, "filename") == "\xc3\xa9t\xc3\xa9.txt");
    REQUIRE(q.params.size() == 1);
    CHECK(q.params[0].first == "name*");
    CHECK(mime::structure(q, named, true).find("\"NAME*\" \"utf-8''r%C3%A9sum.pdf\"") != std::string::npos);
    CHECK(mime::to_utf8("\x80", "windows-1252") == "\xe2\x82\xac");
}

TEST_CASE("compose: an attachment's name past ASCII is written by RFC 2231")
{
    compose c;
    c.to = {"bob@remote.test"};
    c.text = "hi";
    c.attachments.push_back({"Résumé.pdf", "application/pdf", "x"});
    address from;
    REQUIRE(parse_address("alice@example.test", from));
    composed out;
    std::string why;
    REQUIRE_MESSAGE(compose_message(c, from, "", "id@example.test", 0, out, why), why);
    CHECK(out.message.find("name*=UTF-8''R%C3%A9sum%C3%A9.pdf") != std::string::npos);
    CHECK(out.message.find("filename*=UTF-8''R%C3%A9sum%C3%A9.pdf") != std::string::npos);
    CHECK(out.message.find("name=\"=?") == std::string::npos);
    const auto root = mime::parse(out.message);
    REQUIRE(root.children.size() == 2);
    CHECK(mime::param(root.children[1].params, "name") == "Résumé.pdf");
}

TEST_CASE("SORT and THREAD: a display name with a comma, and a reply chain fifty thousand long in time")
{
    namespace io = socketley::mail::imap_order;
    io::entry e;
    io::read(e, "From: \"Doe, John\" <john@example.com>\r\nTo: Zed <z@x>, Amy <a@x>\r\n\r\n");
    CHECK(e.display_from == "doe, john");
    CHECK(e.display_to == "zed");
    std::vector<io::entry> chain;
    for (uint32_t i = 1; i <= 50000; ++i)
    {
        io::entry c;
        c.number = i;
        c.seq = i - 1;
        io::read(c, "Subject: s\r\nMessage-ID: <" + std::to_string(i) + "@c>\r\n" +
                        (i > 1 ? "In-Reply-To: <" + std::to_string(i - 1) + "@c>\r\n" : std::string()) + "\r\n");
        chain.push_back(std::move(c));
    }
    // Many replies to parents not here: one placeholder each, pruned in one pass.
    for (uint32_t i = 1; i <= 20000; ++i)
    {
        io::entry c;
        c.number = 50000 + i;
        c.seq = 50000 + i - 1;
        io::read(c, "Subject: o" + std::to_string(i) + "\r\nMessage-ID: <o" + std::to_string(i) + "@c>\r\nIn-Reply-To: <gone" +
                        std::to_string(i) + "@c>\r\n\r\n");
        chain.push_back(std::move(c));
    }
    const auto t0 = std::chrono::steady_clock::now();
    const std::string t = io::references(chain);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3));
    CHECK(t.find("(50000") == std::string::npos);
    CHECK(std::count(t.begin(), t.end(), '(') == std::count(t.begin(), t.end(), ')'));
}

TEST_CASE("DKIM: Ed25519 signs and verifies, l= short of the body is no pass, and a weak or wrong key is refused")
{
    char tmpl[] = "/tmp/test_mail_ed_XXXXXX";
    REQUIRE(mkdtemp(tmpl) != nullptr);
    std::string why;
    const auto ed = dkim::load_or_make(std::string(tmpl) + "/ed.pem", why, true);
    REQUIRE_MESSAGE(ed, why);
    CHECK(dkim::algorithm_of(ed.get()) == "ed25519-sha256");
    const std::string record = dkim::public_record(ed.get());
    CHECK(record.starts_with("v=DKIM1; k=ed25519; p="));
    const std::string msg = "From: a@example.test\r\nTo: b@remote.test\r\nSubject: hi\r\n\r\nbody\r\n";
    const std::string signed_msg = dkim::sign(msg, "example.test", "skl-ed", ed.get(), 1000) + msg;
    auto sigs = dkim::signatures(signed_msg);
    REQUIRE(sigs.size() == 1);
    CHECK(sigs[0].a == "ed25519-sha256");
    CHECK(dkim::verify(signed_msg, sigs[0], record, 1000, &why) == dkim::result::pass);
    std::string changed = signed_msg;
    changed.replace(changed.find("Subject: hi"), 11, "Subject: ho");
    CHECK(dkim::verify(changed, sigs[0], record, 1000) == dkim::result::fail);
    // An RSA key record for an Ed25519 signature is a key of another algorithm.
    const auto rsa = dkim::load_or_make(std::string(tmpl) + "/rsa.pem", why);
    REQUIRE(rsa);
    CHECK(dkim::verify(signed_msg, sigs[0], dkim::public_record(rsa.get()), 1000) == dkim::result::permerror);
    // A 512-bit RSA key says nothing of who signed.
    EVP_PKEY* weak = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(512));
    REQUIRE(weak);
    const std::string weak_signed = dkim::sign(msg, "example.test", "w", weak, 1000) + msg;
    sigs = dkim::signatures(weak_signed);
    REQUIRE(sigs.size() == 1);
    CHECK(dkim::verify(weak_signed, sigs[0], dkim::public_record(weak), 1000, &why) == dkim::result::permerror);
    CHECK(why.find("1024") != std::string::npos);
    EVP_PKEY_free(weak);
    // l= naming less than the body: what follows could be anyone's, so it is neutral, not a pass.
    const std::string m2 = "From: a@example.test\r\nSubject: l\r\n\r\nline one\r\n";
    const std::string s2 = dkim::sign(m2, "example.test", "skl", rsa.get(), 1000, "DKIM-Signature", "v=1; l=10; ") + m2;
    auto s = dkim::signatures(s2);
    REQUIRE(s.size() == 1);
    CHECK(s[0].l == "10");
    CHECK(dkim::verify(s2, s[0], dkim::public_record(rsa.get()), 1000) == dkim::result::pass);
    const std::string appended = s2 + "a line of someone else's\r\n";
    const auto appended_sigs = dkim::signatures(appended);
    REQUIRE(appended_sigs.size() == 1);
    CHECK(dkim::verify(appended, appended_sigs[0], dkim::public_record(rsa.get()), 1000) ==
          dkim::result::neutral);
    // A d= with a space in it would write a result of its own into this host's Authentication-Results.
    std::string spaced = s2;
    spaced.replace(spaced.find("d=example.test"), 14, "d=example.test dkim=pass");
    CHECK(dkim::signatures(spaced).empty());
    std::filesystem::remove_all(tmpl);
}

TEST_CASE("DKIM: h= names past 256 are refused, and one signature's body is canonicalized once for all")
{
    std::string h;
    for (int i = 0; i < 300; ++i)
        h += "from:";
    const std::string m = "DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=skl; c=relaxed/relaxed; h=" + h +
                          "subject; bh=" + std::string(44, 'A') + "; b=AAAA\r\nFrom: a@example.test\r\n\r\nbody\r\n";
    const auto sigs = dkim::signatures(m);
    REQUIRE(sigs.size() == 1);
    std::string why;
    dkim::bodies cache;
    const auto r = dkim::verify(m, sigs[0], "v=DKIM1; p=AAAA", 0, &why, &cache);
    CHECK(r == dkim::result::fail);
    CHECK(cache.have_relaxed);
}

TEST_CASE("SPF: IPv6 %{i}, %{h} from HELO, other delimiters, upper-case escapes, strict CIDR and exists by A alone")
{
    table_resolver r;
    r.txts["six.test"] = {"v=spf1 exists:%{ir}.%{v}._spf.six.test -all"};
    r.addresses["1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.six.test"] = {"127.0.0.2"};
    CHECK(spf_check("2001:db8::1", "six.test", "x@six.test", r) == "pass");
    r.txts["helo.test"] = {"v=spf1 exists:%{h}.ok.helo.test -all"};
    r.addresses["mx.sender.test.ok.helo.test"] = {"127.0.0.2"};
    CHECK(spf_check("192.0.2.1", "helo.test", "x@helo.test", r, "mx.sender.test") == "pass");
    r.txts["dash.test"] = {"v=spf1 exists:%{l1r-}.dash.test -all"};
    r.addresses["first.dash.test"] = {"127.0.0.2"};
    CHECK(spf_check("192.0.2.1", "dash.test", "first-second@dash.test", r) == "pass");
    r.txts["esc.test"] = {"v=spf1 exists:%{L}.esc.test -all"};
    r.addresses["a%2Bb.esc.test"] = {"127.0.0.2"};
    CHECK(spf_check("192.0.2.1", "esc.test", "a+b@esc.test", r) == "pass");
    // An empty or wrong length is a syntax error, never /0, which would take the whole internet.
    r.txts["slash.test"] = {"v=spf1 ip4:192.0.2.1/ -all"};
    CHECK(spf_check("8.8.8.8", "slash.test", "x@slash.test", r) == "permerror");
    r.txts["bits.test"] = {"v=spf1 a:h.bits.test/33 -all"};
    CHECK(spf_check("8.8.8.8", "bits.test", "x@bits.test", r) == "permerror");
    r.txts["ex.test"] = {"v=spf1 exists:only6.ex.test -all"};
    r.addresses["only6.ex.test"] = {"2001:db8::5"};
    CHECK(spf_check("192.0.2.1", "ex.test", "x@ex.test", r) == "fail");
}

TEST_CASE("DMARC: pct= samples the policy, two records are none, a name past ASCII is its A-labels")
{
    table_resolver r;
    r.txts["_dmarc.sample.test"] = {"v=DMARC1; p=reject; pct=0"};
    auto res = check_inbound("From: a@sample.test\r\nMessage-ID: <1@x>\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.dmarc_policy == "quarantine");
    r.txts["_dmarc.sample.test"] = {"v=DMARC1; p=quarantine; pct=0"};
    res = check_inbound("From: a@sample.test\r\nMessage-ID: <1@x>\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0);
    CHECK(res.dmarc_policy == "none");
    int rejected = 0;
    r.txts["_dmarc.sample.test"] = {"v=DMARC1; p=reject; pct=50"};
    for (int i = 0; i < 200; ++i)
        rejected += check_inbound("From: a@sample.test\r\nMessage-ID: <" + std::to_string(i) + "@x>\r\n\r\nx\r\n",
                                  "1.2.3.4", "h", "", r, 0).reject();
    CHECK(rejected > 60);
    CHECK(rejected < 140);
    // Forty Message-IDs an unkeyed FNV-1a puts past the sample are sampled as any others are, so no sender picks.
    int picked = 0, sampled = 0;
    for (int i = 0; picked < 40; ++i)
    {
        const std::string id = "<" + std::to_string(i) + "@x>";
        uint64_t h = 1469598103934665603ull;
        for (const unsigned char c : id)
            h = (h ^ c) * 1099511628211ull;
        if (h % 100 < 50)
            continue;
        ++picked;
        sampled += check_inbound("From: a@sample.test\r\nMessage-ID: " + id + "\r\n\r\nx\r\n", "1.2.3.4", "h", "", r,
                                 0).reject();
    }
    CHECK(sampled > 0);
    CHECK(sampled < 40);
    r.txts["_dmarc.two.test"] = {"v=DMARC1; p=reject", "v=DMARC1; p=none"};
    CHECK(check_inbound("From: a@two.test\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0).dmarc == "none");
    r.txts["_dmarc.ver.test"] = {"v=DMARC1x; p=reject"};
    CHECK(check_inbound("From: a@ver.test\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0).dmarc == "none");
    r.txts["_dmarc.xn--bcher-kva.test"] = {"v=DMARC1; p=reject"};
    res = check_inbound("From: a@b\xc3\xbc" "cher.test\r\n\r\nx\r\n", "1.2.3.4", "h", "", r, 0);
    CHECK(res.from_domain == "xn--bcher-kva.test");
    CHECK(res.reject());
    CHECK(socketley::idna::to_ascii("M\xc3\xbcnchen.DE") == "xn--mnchen-3ya.de");
}

TEST_CASE("DMARC: the From domain's policy is read first, so names a sender makes slow cannot spend its budget")
{
    // A resolver whose budget is one lookup, as the twenty seconds are once a sender's slow names have taken them.
    struct one_lookup : table_resolver
    {
        int left{1};
        bool txt(const std::string& name, std::vector<std::string>& out, bool& nx) override
        {
            return left-- > 0 && table_resolver::txt(name, out, nx);
        }
        bool addrs(const std::string& name, std::vector<std::string>& out, bool& nx) override
        {
            return left-- > 0 && table_resolver::addrs(name, out, nx);
        }
        bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) override
        {
            return left-- > 0 && table_resolver::mx(name, out, nx);
        }
    };
    one_lookup r;
    r.txts["_dmarc.victim.test"] = {"v=DMARC1; p=reject"};
    r.txts["attacker.test"] = {"v=spf1 a -all"};
    const auto res = check_inbound("From: ceo@victim.test\r\nMessage-ID: <1@x>\r\n\r\nx\r\n", "1.2.3.4", "h",
                                   "x@attacker.test", r, 0);
    CHECK(res.dmarc == "fail");
    CHECK(res.reject());
}

TEST_CASE("PSL: a rule past ASCII matches its A-labels, so two tenants under it are two organizations")
{
    socketley::public_suffix::list l;
    l.load("cn\n\xe5\x85\xac\xe5\x8f\xb8.cn\n");
    CHECK(l.registrable("a.xn--55qx5d.cn") == "a.xn--55qx5d.cn");
    CHECK(l.registrable("x.a.xn--55qx5d.cn") == "a.xn--55qx5d.cn");
    CHECK(l.registrable("x.b.\xe5\x85\xac\xe5\x8f\xb8.cn") == "b.xn--55qx5d.cn");
}

TEST_CASE("ARC: a set sealed here verifies, a chain broken on the way fails, and a trusted sealer vouches")
{
    char tmpl[] = "/tmp/test_mail_arc_XXXXXX";
    REQUIRE(mkdtemp(tmpl) != nullptr);
    std::string why;
    const auto key = dkim::load_or_make(std::string(tmpl) + "/k.pem", why);
    REQUIRE(key);
    const auto ed = dkim::load_or_make(std::string(tmpl) + "/e.pem", why, true);
    REQUIRE(ed);
    table_resolver r;
    r.txts["arc._domainkey.fwd.test"] = {dkim::public_record(key.get())};
    r.txts["arc2._domainkey.second.test"] = {dkim::public_record(ed.get())};
    const auto key_of = [&r](const std::string& name, std::string& record) {
        std::vector<std::string> t;
        bool nx = false;
        r.txt(name, t, nx);
        record = t.empty() ? std::string() : t.front();
        return true;
    };
    const std::string msg = "From: a@origin.test\r\nTo: list@fwd.test\r\nSubject: hello\r\n\r\nbody\r\n";
    CHECK(arc::verify(msg, key_of, 1000).result == "none");
    const std::string one = arc::seal(msg, "mx.fwd.test", "spf=pass smtp.mailfrom=origin.test", "fwd.test", "arc",
                                      key.get(), 1000, "none") + msg;
    CHECK(one.starts_with("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=fwd.test; s=arc;"));
    auto c = arc::verify(one, key_of, 1000);
    CHECK_MESSAGE(c.result == "pass", c.why);
    CHECK(c.count == 1);
    CHECK(c.sealer == "fwd.test");
    // A second hop seals over the first, by Ed25519.
    const std::string two = arc::seal(one, "mx.second.test", "arc=pass", "second.test", "arc2", ed.get(), 1001, "pass") + one;
    c = arc::verify(two, key_of, 1001);
    CHECK_MESSAGE(c.result == "pass", c.why);
    CHECK(c.count == 2);
    CHECK(c.sealer == "second.test");
    // The body changed after the last seal breaks its message signature; a results header changed breaks a seal.
    std::string body = two;
    body.replace(body.find("body\r\n"), 4, "evil");
    CHECK(arc::verify(body, key_of, 1001).result == "fail");
    std::string results = two;
    results.replace(results.find("spf=pass"), 8, "spf=fail");
    CHECK(arc::verify(results, key_of, 1001).result == "fail");
    // A set given twice is no chain.
    CHECK(arc::verify(one.substr(0, one.find("From: ")) + one, key_of, 1000).result == "fail");
    // DMARC: a failing message whose chain a trusted forwarder sealed is let through; an untrusted one's is not.
    r.txts["_dmarc.origin.test"] = {"v=DMARC1; p=reject"};
    auto res = check_inbound(one, "203.0.113.9", "mx.fwd.test", "list@fwd.test", r, 1000, {"fwd.test"});
    CHECK(res.arc == "pass");
    CHECK(res.dmarc == "fail");
    CHECK(res.arc_vouched);
    CHECK_FALSE(res.reject());
    CHECK(res.header().find("arc=pass (i=1 d=fwd.test, vouched)") != std::string::npos);
    CHECK(inbound_result::arc_passed(res.header()));
    res = check_inbound(one, "203.0.113.9", "mx.fwd.test", "list@fwd.test", r, 1000, {"other.test"});
    CHECK(res.reject());
    // A seal whose d= is no name fails and is told with no sealer, so its bytes cannot make a forward seal cv=pass.
    std::string odd = one;
    odd.replace(odd.find("d=fwd.test; s=arc;"), 18, "d=xarc=pass; s=arc;");
    c = arc::verify(odd, key_of, 1000);
    CHECK(c.result == "fail");
    CHECK(c.sealer.empty());
    res = check_inbound(odd, "203.0.113.9", "mx.fwd.test", "list@fwd.test", r, 1000);
    CHECK(res.arc == "fail");
    CHECK(res.header().find("arc=pass") == std::string::npos);
    CHECK_FALSE(inbound_result::arc_passed(res.header()));
    CHECK_FALSE(inbound_result::arc_passed("spf=none; dkim=none; dmarc=none; arc=fail (i=1 d=xarc=pass)"));
    std::filesystem::remove_all(tmpl);
}
