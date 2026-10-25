// The DNS runtime's core without a socket: zone files read and refused, names in and out of wire form, and the answer
// to each kind of query -- found, absent, aliased, wildcarded, delegated, too large for UDP, malformed or not ours.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <algorithm>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

#include <unistd.h>

#include "shared/crypto/jws.h"
#include "shared/util/base64.h"

#include "runtime/dns/dns_answer.h"
#include "runtime/dns/dns_sign.h"
#include "runtime/dns/dns_wire.h"
#include "runtime/dns/dns_zone.h"

using namespace socketley::dns;

namespace
{

const char* example_zone = R"(
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1 hostmaster ( 2026100701 1h 15m 1w 300 )
        IN NS  ns1
        IN NS  ns2.example.net.
        IN MX  10 mail
        IN A   192.0.2.1
        IN AAAA 2001:db8::1
        IN CAA 0 issue "letsencrypt.org"
ns1     IN A   192.0.2.53
mail    IN A   192.0.2.25
www     IN CNAME @
alias   IN CNAME www
away    IN CNAME www.example.org.
*.apps  IN A   192.0.2.80
txt     IN TXT "v=spf1 -all" "second"
_sip._tcp IN SRV 10 60 5060 sip
sip     IN A   192.0.2.60
sub     IN NS  ns.sub
ns.sub  IN A   192.0.2.99
deep.a.b 600 IN A 192.0.2.7
)";

zone load(const char* text)
{
    zone z;
    std::string why;
    REQUIRE_MESSAGE(parse_zone(text, {}, z, why), why);
    return z;
}

std::string wire(const char* text)
{
    std::string w;
    REQUIRE(name_from_text(text, {}, w));
    return w;
}

std::string query(const char* name, uint16_t qtype, bool edns = true, uint16_t udp = 1232, uint16_t qclass = 1,
                  uint8_t version = 0)
{
    std::string q;
    const auto p16 = [&](uint16_t v) { q += static_cast<char>(v >> 8); q += static_cast<char>(v & 0xFF); };
    p16(0xBEEF);
    p16(0x0100);   // RD, as a stub would send
    p16(1);
    p16(0);
    p16(0);
    p16(edns ? 1 : 0);
    q += wire(name);
    p16(qtype);
    p16(qclass);
    if (edns)
    {
        q += '\0';
        p16(type::OPT);
        p16(udp);
        q += '\0';
        q += static_cast<char>(version);
        p16(0);
        p16(0);
    }
    return q;
}

// A reply read back: its flags and counts, and each record's owner, type and data, names decompressed.
struct rr_out
{
    std::string owner;
    uint16_t type;
    uint32_t ttl;
    std::string rdata;   // raw, as sent
    size_t rdata_at;
};
struct reply
{
    uint16_t id, flags, qd, an, ns, ar;
    std::vector<rr_out> rrs;
    size_t size;
    uint8_t rcode() const { return flags & 0xF; }
    bool aa() const { return flags & 0x0400; }
    bool tc() const { return flags & 0x0200; }
    std::vector<rr_out> section(int s) const
    {
        size_t from = s == 0 ? 0 : s == 1 ? an : an + ns;
        size_t n = s == 0 ? an : s == 1 ? ns : ar;
        return {rrs.begin() + from, rrs.begin() + from + n};
    }
};

reply parse(const uint8_t* m, size_t len)
{
    reply r{};
    REQUIRE(len >= 12);
    r.size = len;
    r.id = rd16(m);
    r.flags = rd16(m + 2);
    r.qd = rd16(m + 4);
    r.an = rd16(m + 6);
    r.ns = rd16(m + 8);
    r.ar = rd16(m + 10);
    size_t off = 12;
    uint8_t nm[256];
    for (int i = 0; i < r.qd; ++i)
    {
        size_t next = 0;
        REQUIRE(read_name(m, len, off, nm, next) > 0);
        off = next + 4;
    }
    for (int i = 0; i < r.an + r.ns + r.ar; ++i)
    {
        size_t next = 0;
        const size_t n = read_name(m, len, off, nm, next);
        REQUIRE(n > 0);
        REQUIRE(next + 10 <= len);
        rr_out o;
        o.owner.assign(reinterpret_cast<char*>(nm), n);
        o.type = rd16(m + next);
        o.ttl = rd32(m + next + 4);
        const uint16_t rl = rd16(m + next + 8);
        REQUIRE(next + 10 + rl <= len);
        o.rdata.assign(reinterpret_cast<const char*>(m) + next + 10, rl);
        o.rdata_at = next + 10;
        r.rrs.push_back(o);
        off = next + 10 + rl;
    }
    CHECK(off == len);
    return r;
}

struct ask_result
{
    reply r;
    answer_meta meta;
    std::vector<uint8_t> raw;
};

ask_result ask(const zone_set& zs, const std::string& q, bool tcp = false, bool xfr = false, size_t cap = 65535)
{
    ask_result a;
    a.raw.resize(65535);
    const size_t n = answer(zs, reinterpret_cast<const uint8_t*>(q.data()), q.size(), a.raw.data(), cap, tcp, xfr,
                            a.meta);
    a.raw.resize(n);
    if (n)
        a.r = parse(a.raw.data(), n);
    return a;
}

// The name in record data at `at` of the message, decompressed.
std::string name_at(const std::vector<uint8_t>& m, size_t at)
{
    uint8_t nm[256];
    size_t next = 0;
    const size_t n = read_name(m.data(), m.size(), at, nm, next);
    return std::string(reinterpret_cast<char*>(nm), n);
}

zone_set one(const zone& z)
{
    zone_set zs;
    zs.zones.push_back(std::make_shared<zone>(z));
    return zs;
}

}   // namespace

TEST_CASE("names: presentation form to wire form and back")
{
    std::string w;
    CHECK(name_from_text("Example.COM.", {}, w));
    CHECK(w == std::string("\7example\3com\0", 13));
    CHECK(to_text(w) == "example.com.");
    const std::string origin = w;
    CHECK(name_from_text("www", origin, w));
    CHECK(to_text(w) == "www.example.com.");
    CHECK(name_from_text("@", origin, w));
    CHECK(w == origin);
    CHECK(name_from_text("a\\.b.example.com.", {}, w));
    CHECK(label_count(w) == 3);
    CHECK(name_from_text("\\065bc.", {}, w));
    CHECK(w == std::string("\3abc\0", 5));
    CHECK_FALSE(name_from_text("a..b.", {}, w));
    CHECK_FALSE(name_from_text(".a.", {}, w));
    CHECK_FALSE(name_from_text("relative", {}, w));
    CHECK_FALSE(name_from_text(std::string(64, 'x') + ".", {}, w));
    std::string long_name;
    for (int i = 0; i < 64; ++i)
        long_name += "abc.";
    CHECK_FALSE(name_from_text(long_name, {}, w));
    CHECK(is_subdomain(wire("a.example.com."), wire("example.com.")));
    CHECK(is_subdomain(wire("example.com."), wire("example.com.")));
    CHECK_FALSE(is_subdomain(wire("aexample.com."), wire("example.com.")));
    CHECK_FALSE(is_subdomain(wire("com."), wire("example.com.")));
}

TEST_CASE("zone: a file read whole")
{
    const zone z = load(example_zone);
    CHECK(to_text(z.origin) == "example.com.");
    CHECK(z.serial == 2026100701u);
    CHECK(z.negative_ttl == 300u);
    CHECK(z.has_cuts);
    REQUIRE(z.find(wire("sub.example.com.")));
    CHECK(z.find(wire("sub.example.com."))->cut);
    // The names between a name and the apex exist, empty.
    REQUIRE(z.find(wire("a.b.example.com.")));
    CHECK(z.find(wire("a.b.example.com."))->sets.empty());
    REQUIRE(z.find(wire("deep.a.b.example.com.")));
    CHECK(z.find(wire("deep.a.b.example.com."))->find(type::A)->ttl == 600u);
    // Two strings of a TXT record are two character-strings.
    const rrset* txt = z.find(wire("txt.example.com."))->find(type::TXT);
    REQUIRE(txt);
    CHECK(txt->rdata[0] == std::string("\x0bv=spf1 -all\x06second"));
    // A string past 255 bytes is split, as a DKIM key is.
    zone big = load(("$ORIGIN x.\n@ 60 SOA a b 1 1 1 1 1\n@ 60 NS a\nk 60 TXT \"" + std::string(600, 'k') + "\"\n").c_str());
    const auto& rd = big.find(wire("k.x."))->find(type::TXT)->rdata[0];
    CHECK(rd.size() == 603);
    CHECK(static_cast<uint8_t>(rd[0]) == 255);
    CHECK(static_cast<uint8_t>(rd[256]) == 255);
    CHECK(static_cast<uint8_t>(rd[512]) == 90);
}

TEST_CASE("zone: what is refused, with the line")
{
    const auto refuse = [](const std::string& text, const char* part)
    {
        zone z;
        std::string why;
        CHECK_FALSE(parse_zone(text, {}, z, why));
        CHECK_MESSAGE(why.find(part) != std::string::npos, why);
    };
    const std::string head = "$ORIGIN x.\n$TTL 60\n@ SOA a b 1 1 1 1 1\n@ NS a\n";
    refuse("$ORIGIN x.\n$TTL 60\n@ NS a\n", "no SOA");
    refuse("$ORIGIN x.\n$TTL 60\n@ SOA a b 1 1 1 1 1\n", "no NS");
    refuse(head + "www CNAME a\nwww A 1.2.3.4\n", "CNAME and other");
    refuse(head + "www CNAME a\nwww CNAME b\n", "second CNAME");
    refuse(head + "y. A 1.2.3.4\n", "outside the zone");
    refuse(head + "$INCLUDE /etc/passwd\n", "not supported");
    refuse(head + "www A 999.1.1.1\n", "line 5");
    refuse(head + "www 1h30 A 1.2.3.4\n", "not a time");
    refuse(head + "www BOGUS 1\n", "not a record type");
    refuse(head + "sub NS ns.other.\nsub MX 10 mail\n", "delegated");
    refuse(head + "sub NS ns.other.\nwww.sub TXT \"hidden\"\n", "delegated");
    refuse(head + "www TXT \"open\n", "does not end");
    refuse(head + "www ( A 1.2.3.4\n", "never closed");
    refuse("www A 1.2.3.4\n", "relative and no $ORIGIN");
    // A relative $ORIGIN is made from the one before it (found by fuzzing: it was read into itself).
    {
        zone rel;
        std::string w;
        CHECK_MESSAGE(parse_zone("$ORIGIN example.com.\n$ORIGIN sub\n$TTL 60\n@ SOA a b 1 1 1 1 1\n@ NS a\n", {}, rel, w), w);
        CHECK(to_text(rel.origin) == "sub.example.com.");
        CHECK_FALSE(parse_zone("$ORIGIN 0\n@ SOA n h 1 1 1 1 1\n", {}, rel, w));
    }
    // Glue beneath a cut is what a cut may hold.
    zone z;
    std::string why;
    CHECK_MESSAGE(parse_zone(head + "sub NS ns.sub\nns.sub A 1.2.3.4\nns.sub AAAA ::1\n", {}, z, why), why);
    // RFC 3597's form, for a type without a parser here.
    CHECK_MESSAGE(parse_zone(head + "t TYPE65280 \\# 3 abcdef\n", {}, z, why), why);
    CHECK(z.find(wire("t.x."))->find(65280)->rdata[0] == "\xab\xcd\xef");
}

TEST_CASE("answer: a name found, with the addresses of what it names")
{
    const auto zs = one(load(example_zone));
    auto a = ask(zs, query("example.com.", type::A));
    CHECK(a.r.id == 0xBEEF);
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK(a.r.aa());
    CHECK((a.r.flags & 0x0100) != 0);   // RD echoed
    CHECK((a.r.flags & 0x0080) == 0);   // never RA: this server recurses for nobody
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].rdata == std::string("\xc0\x00\x02\x01", 4));
    // The answer's owner points at the question: compression worked.
    CHECK(a.raw.size() < 80);
    CHECK(a.r.ar == 1);   // the OPT
    CHECK(a.r.rrs.back().type == type::OPT);

    a = ask(zs, query("EXAMPLE.com.", type::MX));
    REQUIRE(a.r.an == 1);
    CHECK(name_at(a.raw, a.r.rrs[0].rdata_at + 2) == wire("mail.example.com."));
    // The mail host's address in the additional section, then the OPT.
    REQUIRE(a.r.ar == 2);
    CHECK(a.r.section(2)[0].type == type::A);
    CHECK(a.r.section(2)[0].owner == wire("mail.example.com."));

    a = ask(zs, query("_sip._tcp.example.com.", type::SRV));
    REQUIRE(a.r.an == 1);
    // SRV's target is never compressed (RFC 2782).
    CHECK(a.r.rrs[0].rdata.size() == 6 + wire("sip.example.com.").size());
}

TEST_CASE("answer: what is not there")
{
    const auto zs = one(load(example_zone));
    auto a = ask(zs, query("nothing.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NXDOMAIN);
    CHECK(a.r.aa());
    REQUIRE(a.r.ns == 1);
    CHECK(a.r.section(1)[0].type == type::SOA);
    CHECK(a.r.section(1)[0].ttl == 300u);   // the negative TTL, not the SOA's own

    a = ask(zs, query("www2.example.com.", type::AAAA));
    CHECK(a.r.rcode() == rcode::NXDOMAIN);
    // A name that exists without the type: NODATA.
    a = ask(zs, query("mail.example.com.", type::AAAA));
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK(a.r.an == 0);
    CHECK(a.r.ns == 1);
    // An empty non-terminal exists.
    a = ask(zs, query("a.b.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK(a.r.an == 0);
}

TEST_CASE("answer: aliases followed within the zone, not beyond")
{
    const auto zs = one(load(example_zone));
    auto a = ask(zs, query("alias.example.com.", type::A));
    REQUIRE(a.r.an == 3);
    CHECK(a.r.rrs[0].type == type::CNAME);
    CHECK(a.r.rrs[1].type == type::CNAME);
    CHECK(a.r.rrs[1].owner == wire("www.example.com."));
    CHECK(a.r.rrs[2].type == type::A);
    CHECK(a.r.rrs[2].owner == wire("example.com."));

    a = ask(zs, query("away.example.com.", type::A));
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].type == type::CNAME);
    CHECK(a.r.rcode() == rcode::NOERROR);

    // Asked for the CNAME itself, it is the answer.
    a = ask(zs, query("www.example.com.", type::CNAME));
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].type == type::CNAME);

    // A loop ends.
    const auto loop = one(load("$ORIGIN x.\n$TTL 60\n@ SOA a b 1 1 1 1 1\n@ NS a\nl1 CNAME l2\nl2 CNAME l1\n"));
    a = ask(loop, query("l1.x.", type::A));
    CHECK(a.r.an == 8);
}

TEST_CASE("answer: a wildcard stands for the names it covers, and not for those that exist")
{
    const auto zs = one(load(example_zone));
    auto a = ask(zs, query("anything.apps.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NOERROR);
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].owner == wire("anything.apps.example.com."));
    a = ask(zs, query("deeper.anything.apps.example.com.", type::A));
    CHECK(a.r.an == 1);
    // A wildcard has the types it has.
    a = ask(zs, query("x.apps.example.com.", type::MX));
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK(a.r.an == 0);
    // Not across an existing name: below mail, which exists and has no wildcard of its own, there is nothing.
    a = ask(zs, query("x.mail.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NXDOMAIN);
}

TEST_CASE("answer: a delegation is referred, with its glue")
{
    const auto zs = one(load(example_zone));
    auto a = ask(zs, query("host.sub.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK_FALSE(a.r.aa());
    CHECK(a.meta.referral);
    CHECK(a.r.an == 0);
    REQUIRE(a.r.ns == 1);
    CHECK(a.r.section(1)[0].type == type::NS);
    CHECK(a.r.section(1)[0].owner == wire("sub.example.com."));
    REQUIRE(a.r.ar == 2);
    CHECK(a.r.section(2)[0].owner == wire("ns.sub.example.com."));
    // The cut itself is referred too, except for DS, which the parent answers.
    a = ask(zs, query("sub.example.com.", type::A));
    CHECK(a.meta.referral);
    a = ask(zs, query("sub.example.com.", type::DS));
    CHECK_FALSE(a.meta.referral);
    CHECK(a.r.aa());
}

TEST_CASE("answer: what this server does not answer")
{
    const auto zs = one(load(example_zone));
    // Not one of its zones: refused, never looked up elsewhere.
    auto a = ask(zs, query("example.org.", type::A));
    CHECK(a.r.rcode() == rcode::REFUSED);
    CHECK_FALSE(a.r.aa());
    CHECK(a.r.an + a.r.ns == 0);
    // CHAOS's version.bind.
    a = ask(zs, query("version.bind.", type::TXT, true, 1232, rclass::CH));
    CHECK(a.r.rcode() == rcode::REFUSED);
    // ANY: one small record.
    a = ask(zs, query("example.com.", type::ANY));
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].type == type::HINFO);
    // A whole zone: not over UDP, not to a stranger.
    a = ask(zs, query("example.com.", type::AXFR), false, true);
    CHECK(a.r.rcode() == rcode::REFUSED);
    a = ask(zs, query("example.com.", type::AXFR), true, false);
    CHECK(a.r.rcode() == rcode::REFUSED);
    a = ask(zs, query("example.com.", type::AXFR), true, true);
    CHECK(a.raw.empty());
    CHECK(a.meta.xfr != nullptr);
    // IXFR over UDP from a secondary: the SOA, to come back over TCP.
    a = ask(zs, query("example.com.", type::IXFR), false, true);
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].type == type::SOA);
    // An EDNS version past 0: BADVERS, 16, half of it in the OPT.
    a = ask(zs, query("example.com.", type::A, true, 1232, 1, 1));
    CHECK(a.r.rcode() == 0);
    REQUIRE(a.r.ar == 1);
    CHECK(static_cast<uint8_t>(a.raw[a.raw.size() - 11 + 5]) == 1);
}

TEST_CASE("answer: what does not fit UDP is truncated whole")
{
    std::string text = "$ORIGIN x.\n$TTL 60\n@ SOA a b 1 1 1 1 1\n@ NS a\n";
    for (int i = 0; i < 40; ++i)
        text += "big TXT \"" + std::string(60, static_cast<char>('a' + i % 26)) + std::to_string(i) + "\"\n";
    const auto zs = one(load(text.c_str()));
    // Without EDNS: 512 bytes.
    auto a = ask(zs, query("big.x.", type::TXT, false));
    CHECK(a.r.tc());
    CHECK(a.r.an == 0);
    CHECK(a.r.size <= 512);
    // With EDNS at 4096 the server still keeps to 1232.
    a = ask(zs, query("big.x.", type::TXT, true, 4096));
    CHECK(a.r.tc());
    CHECK(a.r.ar == 1);
    // Over TCP it is whole.
    a = ask(zs, query("big.x.", type::TXT, true, 4096), true);
    CHECK_FALSE(a.r.tc());
    CHECK(a.r.an == 40);
}

TEST_CASE("answer: what is not a query")
{
    const auto zs = one(load(example_zone));
    answer_meta m;
    uint8_t out[1500];
    // Too short to be anything.
    CHECK(answer(zs, reinterpret_cast<const uint8_t*>("abc"), 3, out, sizeof out, false, false, m) == 0);
    // A response is never answered.
    std::string q = query("example.com.", type::A);
    q[2] = static_cast<char>(q[2] | 0x80);
    CHECK(answer(zs, reinterpret_cast<const uint8_t*>(q.data()), q.size(), out, sizeof out, false, false, m) == 0);
    // A compression pointer that loops on itself.
    std::string loop("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01", 18);
    auto a = ask(zs, loop);
    CHECK(a.r.rcode() == rcode::FORMERR);
    // A question whose name points into the header (found by fuzzing): the reply would copy the pointer under
    // another header.
    std::string into_header("\x12\x34\x01\x00\x00\x01\x00\x00\xff\x00\x00\x00\xc0\x00\x01\x00\x00\xff\x00\x00"
                            "\x00\xc0\x0c", 23);
    a = ask(zs, into_header);
    CHECK(a.r.rcode() == rcode::FORMERR);
    CHECK(a.r.qd == 0);
    // Two questions.
    q = query("example.com.", type::A, false);
    q[5] = 2;
    a = ask(zs, q);
    CHECK(a.r.rcode() == rcode::FORMERR);
    // An update is not served.
    q = query("example.com.", type::SOA);
    q[2] = static_cast<char>(5 << 3);
    a = ask(zs, q);
    CHECK(a.r.rcode() == rcode::NOTIMP);
    // Random bytes never crash it and never make it answer a response.
    std::mt19937 rng(7);
    for (int i = 0; i < 200000; ++i)
    {
        std::string junk = query("www.example.com.", type::A);
        const int flips = 1 + static_cast<int>(rng() % 6);
        for (int k = 0; k < flips; ++k)
            junk[rng() % junk.size()] = static_cast<char>(rng());
        if (rng() % 4 == 0)
            junk.resize(rng() % (junk.size() + 1));
        const size_t n = answer(zs, reinterpret_cast<const uint8_t*>(junk.data()), junk.size(), out, sizeof out,
                                rng() % 2, false, m);
        if (n)
        {
            CHECK(n <= sizeof out);
            CHECK((out[2] & 0x80) != 0);
        }
    }
}

TEST_CASE("transfer: SOA, every record, SOA, across messages")
{
    std::string text = "$ORIGIN x.\n$TTL 60\n@ SOA a b 7 1 1 1 1\n@ NS a\n";
    for (int i = 0; i < 6000; ++i)
        text += "h" + std::to_string(i) + " A 10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256) + "\n";
    const zone z = load(text.c_str());
    const std::string q = query("x.", type::AXFR, false);
    std::vector<reply> msgs;
    std::vector<std::vector<uint8_t>> raws;
    transfer(z, reinterpret_cast<const uint8_t*>(q.data()), q.size(), [&](const uint8_t* p, size_t n)
             {
                 raws.emplace_back(p, p + n);
                 msgs.push_back(parse(p, n));
             });
    REQUIRE(msgs.size() >= 2);
    size_t total = 0;
    for (const auto& m : msgs)
    {
        CHECK(m.size <= 65535);
        CHECK(m.aa());
        total += m.an;
    }
    CHECK(total == 6000 + 1 + 2);
    CHECK(msgs.front().qd == 1);
    CHECK(msgs.back().qd == 0);
    CHECK(msgs.front().rrs.front().type == type::SOA);
    CHECK(msgs.back().rrs.back().type == type::SOA);

    uint8_t buf[512];
    const size_t n = make_notify(z, 77, buf, sizeof buf);
    const reply r = parse(buf, n);
    CHECK(((r.flags >> 11) & 0xF) == opcode::NOTIFY);
    CHECK(r.aa());
    CHECK(r.qd == 1);
}

TEST_CASE("published names and DNS-01 answers join a zone; what the file says wins")
{
    zone z = load(example_zone);
    const uint32_t before = z.serial;
    extra_records x;
    x.names = {"chat", "api.example.com", "*.files.example.com", "files.example.com", "www", "mail", "*.rel",
               "other.example.org", "host.sub.example.com", "deep.new.example.com."};
    x.v4 = {std::string("\xc6\x33\x64\x0a", 4)};
    x.v6 = {std::string(16, '\x01')};
    x.challenges = {{"example.com", "abc"}, {"example.com", "def"}, {"example.org", "nope"}};
    x.serial_add = 1000;
    add_extra(z, x);
    const auto zs = one(z);

    auto a = ask(zs, query("chat.example.com.", type::A));
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].rdata == std::string("\xc6\x33\x64\x0a", 4));
    CHECK(a.r.rrs[0].ttl == published_ttl);
    CHECK(ask(zs, query("chat.example.com.", type::AAAA)).r.an == 1);
    CHECK(ask(zs, query("api.example.com.", type::A)).r.an == 1);
    CHECK(ask(zs, query("bucket.files.example.com.", type::A)).r.an == 1);
    CHECK(ask(zs, query("deep.new.example.com.", type::A)).r.an == 1);
    // "*.rel" is relative too: the buckets of a storage runtime named "rel".
    CHECK(ask(zs, query("bucket.rel.example.com.", type::A)).r.an == 1);
    // The names on the way to a new one exist, empty.
    a = ask(zs, query("new.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NOERROR);
    CHECK(a.r.an == 0);
    // An alias keeps being one, and a name with an address of its own keeps that address.
    a = ask(zs, query("www.example.com.", type::A));
    REQUIRE(a.r.an == 2);
    CHECK(a.r.rrs[0].type == type::CNAME);
    a = ask(zs, query("mail.example.com.", type::A));
    REQUIRE(a.r.an == 1);
    CHECK(a.r.rrs[0].rdata == std::string("\xc0\x00\x02\x19", 4));
    // Outside the zone, or beneath a delegation, nothing is added.
    CHECK(ask(zs, query("host.sub.example.com.", type::A)).meta.referral);
    // Both DNS-01 answers of a name, as one set.
    a = ask(zs, query("_acme-challenge.example.com.", type::TXT));
    REQUIRE(a.r.an == 2);
    CHECK(a.r.rrs[0].ttl == challenge_ttl);
    // The serial grew, and the SOA record carries it -- what a secondary compares.
    CHECK(z.serial == before + 1000);
    a = ask(zs, query("example.com.", type::SOA));
    REQUIRE(a.r.an == 1);
    CHECK(rd32(reinterpret_cast<const uint8_t*>(a.r.rrs[0].rdata.data()) + a.r.rrs[0].rdata.size() - 20) == before + 1000);
}

namespace
{

// The query with the DO bit set in its OPT, as a validating resolver sends it.
std::string query_do(const char* name, uint16_t qtype)
{
    std::string q = query(name, qtype);
    q[q.size() - 4] = static_cast<char>(0x80);
    return q;
}

zone signed_example(zone_key& key)
{
    zone z = load(example_zone);
    const std::string dir = (std::filesystem::temp_directory_path() / ("skl-dnssec-" + std::to_string(::getpid()))).string();
    std::string why;
    REQUIRE_MESSAGE(load_or_make_key(dir, z.origin, key, why), why);
    REQUIRE(sign_zone(z, key, 1800000000));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    return z;
}

bool has_type(const std::vector<rr_out>& rrs, uint16_t t)
{
    return std::any_of(rrs.begin(), rrs.end(), [&](const rr_out& r) { return r.type == t; });
}

}   // namespace

TEST_CASE("DNSSEC: the key tag and DS of RFC 6605's example, and RFC 4034's canonical order")
{
    std::string pub;
    REQUIRE(socketley::base64::decode("GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==", pub));
    zone_key k;
    k.dnskey = std::string("\x01\x01\x03\x0d", 4) + pub;
    k.tag = key_tag(k.dnskey);
    CHECK(k.tag == 55648);
    CHECK(ds_text(wire("example.net."), k) ==
          "example.net. IN DS 55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17");
    const std::vector<std::string> order = {wire("example."), wire("a.example."), wire("yljkjljk.a.example."),
                                            wire("z.a.example."), wire("zabc.a.example."), wire("z.example."),
                                            std::string("\x01\x01\x01z\x07" "example\x00", 12), wire("*.z.example."),
                                            std::string("\x01\x80\x01z\x07" "example\x00", 12)};
    for (size_t i = 0; i + 1 < order.size(); ++i)
    {
        CHECK(canonical_less(order[i], order[i + 1]));
        CHECK_FALSE(canonical_less(order[i + 1], order[i]));
    }
}

TEST_CASE("DNSSEC: a signed zone holds its key, a chain through its own names and a signature over each set")
{
    zone_key key;
    const zone z = signed_example(key);
    const node* apex = z.find(z.origin);
    REQUIRE(apex);
    REQUIRE(apex->find(type_sec::DNSKEY));
    CHECK(apex->find(type_sec::DNSKEY)->rdata[0] == key.dnskey);
    // Glue and the empty names between are no owners; the cut is.
    CHECK(std::find(z.chain.begin(), z.chain.end(), wire("ns.sub.example.com.")) == z.chain.end());
    CHECK(std::find(z.chain.begin(), z.chain.end(), wire("a.b.example.com.")) == z.chain.end());
    CHECK(std::find(z.chain.begin(), z.chain.end(), wire("sub.example.com.")) != z.chain.end());
    CHECK(z.chain.front() == z.origin);
    for (size_t i = 0; i < z.chain.size(); ++i)
    {
        const node* n = z.find(z.chain[i]);
        REQUIRE(n);
        const rrset* nsec = n->find(type_sec::NSEC);
        REQUIRE(nsec);
        const std::string& next = z.chain[(i + 1) % z.chain.size()];
        CHECK(nsec->rdata[0].compare(0, next.size(), next) == 0);
        for (const auto& s : n->sets)
        {
            const rrset* sig = n->sig(s.type);
            if (n->cut && s.type == type::NS)
            {
                CHECK_FALSE(sig);
                continue;
            }
            REQUIRE(sig);
            // The signed data rebuilt as a validator does, and the signature checked against the key.
            const std::string& rd = sig->rdata[0];
            const size_t fixed = 18 + z.origin.size();
            std::string data = rd.substr(0, fixed);
            std::vector<std::string> sorted = s.rdata;
            std::sort(sorted.begin(), sorted.end());
            for (const auto& r : sorted)
            {
                data += z.chain[i];
                const auto p16 = [&](uint16_t v) { data += static_cast<char>(v >> 8); data += static_cast<char>(v & 0xFF); };
                p16(s.type);
                p16(1);
                p16(static_cast<uint16_t>(s.ttl >> 16));
                p16(static_cast<uint16_t>(s.ttl & 0xFFFF));
                p16(static_cast<uint16_t>(r.size()));
                data += r;
            }
            CHECK(socketley::jws::es256_verify(key.pkey.get(), data, rd.substr(fixed)));
        }
    }
    // Signed by the week, whichever moment of it: the serial raised by the week's number, in the SOA as well.
    const int64_t week = 1800000000 / (7 * 86400);
    CHECK(z.sig_expires_s == week * 7 * 86400 + 21 * 86400);
    CHECK(z.serial == 2026100701u + static_cast<uint32_t>(week));
    const std::string& soa = z.find(z.origin)->find(type::SOA)->rdata[0];
    CHECK(rd32(reinterpret_cast<const uint8_t*>(soa.data()) + soa.size() - 20) == z.serial);
}

TEST_CASE("DNSSEC: an answer to DO carries the signatures and the proofs of what is not there")
{
    zone_key key;
    const auto zs = one(signed_example(key));
    auto a = ask(zs, query_do("mail.example.com.", type::A));
    REQUIRE(a.r.an == 2);
    CHECK(a.r.section(0)[1].type == type_sec::RRSIG);
    CHECK((a.r.rrs.back().ttl & 0x8000) != 0);   // DO echoed in the OPT
    a = ask(zs, query("mail.example.com.", type::A));
    CHECK(a.r.an == 1);
    CHECK_FALSE(has_type(a.r.rrs, type_sec::RRSIG));

    a = ask(zs, query_do("nothing.example.com.", type::A));
    CHECK(a.r.rcode() == rcode::NXDOMAIN);
    CHECK(has_type(a.r.section(1), type_sec::NSEC));
    CHECK(has_type(a.r.section(1), type_sec::RRSIG));

    a = ask(zs, query_do("mail.example.com.", type::AAAA));
    CHECK(a.r.an == 0);
    const auto auth = a.r.section(1);
    CHECK(std::any_of(auth.begin(), auth.end(), [](const rr_out& r) { return r.type == type_sec::NSEC && r.owner == wire("mail.example.com."); }));

    // A wildcard's answer, signed with its labels, and the proof that the name asked is not there itself.
    a = ask(zs, query_do("x.apps.example.com.", type::A));
    REQUIRE(a.r.an == 2);
    CHECK(static_cast<uint8_t>(a.r.section(0)[1].rdata[3]) == 3);
    CHECK(has_type(a.r.section(1), type_sec::NSEC));

    // A delegation without a DS says so with the cut's NSEC.
    a = ask(zs, query_do("www.sub.example.com.", type::A));
    CHECK_FALSE(a.r.aa());
    const auto ref = a.r.section(1);
    CHECK(std::any_of(ref.begin(), ref.end(), [](const rr_out& r) { return r.type == type_sec::NSEC && r.owner == wire("sub.example.com."); }));

    a = ask(zs, query_do("example.com.", type_sec::DNSKEY));
    REQUIRE(a.r.an == 2);
    CHECK(a.r.section(0)[0].rdata == key.dnskey);
}
