// Fuzz target: the dns runtime's two readers of what it is given, a query off port 53 and a zone file
// (socketley/runtime/dns/).
//
// A query is what anybody on the internet can send, so the answerer is the one place a byte from outside meets this
// runtime's memory; a zone file is what an operator, or whoever can write the file, gives it, read again whenever it
// changes.
//
// The first byte chooses: even, the rest is a query answered from a fixed zone over UDP and over TCP; odd, the rest
// is a zone file, and when it is one, every name in it is asked for.
//
// Properties checked, beyond "did it crash":
//   * a reply is a response (QR) with the query's ID, and never larger than its transport allows: 512 bytes without
//     EDNS and 1232 with it over UDP, 64 KiB over TCP;
//   * a reply is well formed: its question and every record parse back, names within 255 bytes and no pointer
//     forward, and its counts are the records it holds;
//   * a reply's question is the query's, byte for byte;
//   * answering is deterministic: the same query, the same bytes;
//   * a zone accepted holds only names at or below its apex, and parsing it again gives the same zone.
#include "fuzz_common.h"
#include "runtime/dns/dns_answer.h"
#include "runtime/dns/dns_wire.h"
#include "runtime/dns/dns_zone.h"

#include <memory>
#include <string>
#include <vector>

namespace dn = socketley::dns;

namespace {

const dn::zone_set& fixed()
{
    static const dn::zone_set zs = []
    {
        dn::zone_set s;
        auto z = std::make_shared<dn::zone>();
        std::string why;
        const std::string text = "$ORIGIN example.com.\n$TTL 300\n@ SOA ns1 h 1 1h 15m 1w 60\n@ NS ns1\n@ MX 10 mail\n"
                           "@ A 192.0.2.1\nns1 A 192.0.2.53\nmail A 192.0.2.25\nwww CNAME @\nloop CNAME loop2\n"
                           "loop2 CNAME loop\n*.w A 192.0.2.9\nsub NS ns.sub\nns.sub A 192.0.2.99\n_s._tcp SRV 1 2 3 mail\n"
                           "t TXT \"" + std::string(400, 't') + "\"\n";
        if (!dn::parse_zone(text, {}, *z, why))
            abort();
        s.zones.push_back(std::move(z));
        return s;
    }();
    return zs;
}

// Walks a reply as a resolver would; false at the first thing that is not DNS.
bool well_formed(const uint8_t* m, size_t n, size_t& question_end)
{
    if (n < dn::header_len)
        return false;
    const uint16_t qd = dn::rd16(m + 4);
    const uint32_t rrs = uint32_t(dn::rd16(m + 6)) + dn::rd16(m + 8) + dn::rd16(m + 10);
    size_t off = dn::header_len;
    uint8_t name[256];
    for (uint16_t i = 0; i < qd; ++i)
    {
        size_t next = 0;
        if (!dn::read_name(m, n, off, name, next) || next + 4 > n)
            return false;
        off = next + 4;
    }
    question_end = off;
    for (uint32_t i = 0; i < rrs; ++i)
    {
        size_t next = 0;
        if (!dn::read_name(m, n, off, name, next) || next + 10 > n)
            return false;
        const uint16_t t = dn::rd16(m + next);
        const uint16_t len = dn::rd16(m + next + 8);
        if (next + 10 + len > n)
            return false;
        // The names inside the types that carry them parse too.
        const size_t rd = next + 10;
        size_t inner = 0;
        if ((t == dn::type::NS || t == dn::type::CNAME || t == dn::type::PTR) &&
            (!dn::read_name(m, n, rd, name, inner) || inner != rd + len))
            return false;
        if (t == dn::type::MX && (len < 3 || !dn::read_name(m, n, rd + 2, name, inner) || inner != rd + len))
            return false;
        off = rd + len;
    }
    return off == n;
}

void check_query(const uint8_t* q, size_t len)
{
    static uint8_t out[65535], again[65535];
    for (const bool tcp : {false, true})
    {
        dn::answer_meta m;
        const size_t n = dn::answer(fixed(), q, len, out, sizeof out, tcp, /*xfr_allowed=*/true, m);
        if (n == 0)
            continue;
        FUZZ_CHECK(n >= dn::header_len, "a reply shorter than a header");
        FUZZ_CHECK((out[2] & 0x80) != 0, "a reply that is not a response");
        FUZZ_CHECK(dn::rd16(out) == dn::rd16(q), "a reply with another ID");
        if (!tcp)
            FUZZ_CHECK(n <= (m.edns ? 1232u : 512u), "a UDP reply past the size it may have");
        size_t qend = 0;
        FUZZ_CHECK(well_formed(out, n, qend), "a reply that does not parse");
        if (dn::rd16(out + 4) == 1)
        {
            FUZZ_CHECK(qend == m.question_end && qend <= len, "a question of another length");
            FUZZ_CHECK(std::memcmp(out + dn::header_len, q + dn::header_len, qend - dn::header_len) == 0,
                       "a question that is not the query's");
        }
        dn::answer_meta m2;
        const size_t n2 = dn::answer(fixed(), q, len, again, sizeof again, tcp, true, m2);
        FUZZ_CHECK(n2 == n && std::memcmp(out, again, n) == 0, "the same query answered twice differently");
    }
}

void check_zone(const uint8_t* data, size_t len)
{
    const std::string text(reinterpret_cast<const char*>(data), len);
    dn::zone z;
    std::string why;
    if (!dn::parse_zone(text, "fuzz.test.", z, why))
    {
        FUZZ_CHECK(!why.empty(), "a refusal without a reason");
        return;
    }
    dn::zone z2;
    std::string why2;
    FUZZ_CHECK(dn::parse_zone(text, "fuzz.test.", z2, why2), "a zone accepted once and refused the second time");
    FUZZ_CHECK(z2.records == z.records && z2.serial == z.serial && z2.names.size() == z.names.size(),
               "the same zone parsed twice differently");
    dn::zone_set zs;
    zs.zones.push_back(std::make_shared<dn::zone>(std::move(z)));
    static uint8_t out[65535];
    int asked = 0;
    for (const auto& [name, nd] : zs.zones[0]->names)
    {
        FUZZ_CHECK(dn::is_subdomain(name, zs.zones[0]->origin), "a name outside the apex");
        if (++asked > 64)
            break;
        std::string q("\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12);
        q += name;
        q += std::string("\x00\xff\x00\x01", 4);
        for (const uint16_t t : {dn::type::A, dn::type::TXT, dn::type::MX})
        {
            q[q.size() - 4] = static_cast<char>(t >> 8);
            q[q.size() - 3] = static_cast<char>(t);
            dn::answer_meta m;
            const size_t n = dn::answer(zs, reinterpret_cast<const uint8_t*>(q.data()), q.size(), out, sizeof out, true,
                                        true, m);
            size_t qend = 0;
            FUZZ_CHECK(n > 0 && well_formed(out, n, qend), "an answer from a parsed zone that does not parse");
        }
    }
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    if (data[0] & 1)
        check_zone(data + 1, size - 1);
    else
        check_query(data + 1, size - 1);
    return 0;
}
