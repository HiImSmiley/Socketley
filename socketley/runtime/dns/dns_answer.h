#pragma once
// What an authoritative server answers to one query, as RFC 1034 section 4.3.2 sets it out, written straight into the
// buffer the reply leaves from.
//
// It never asks anybody else: a name in no zone it holds is REFUSED, which is what keeps it from being an open
// resolver an attacker could aim at a victim. ANY gets the one small record RFC 8482 allows, for the same reason.
#include <cstddef>
#include <cstdint>

#include "dns_wire.h"
#include "dns_zone.h"

namespace socketley::dns
{

struct answer_meta
{
    uint8_t  rcode{0};
    uint16_t qtype{0};
    bool     dropped{false};    // nothing to send: a response, or too short to be a query
    bool     truncated{false};
    bool     referral{false};
    bool     edns{false};
    // The query's DO bit (RFC 3225): it takes the signatures of a signed zone.
    bool     dnssec{false};
    // A query for a whole zone, which only TCP carries and only allowed peers get; the caller streams it.
    const zone* xfr{nullptr};
    // A response to a NOTIFY this server sent, by its ID, so the caller stops sending it again.
    bool     notify_ack{false};
    uint16_t id{0};
    // The query's name in wire form, lower case, for the logs and the rate limit's key.
    // Where the question ends in the query and in the reply, which copies it.
    size_t   question_end{0};
    uint8_t  qname[max_name + 1];
    size_t   qname_len{0};

    // Every field back to its start but the name, which answer() writes before anything reads it: a whole
    // value-initialised copy zeroed and copied 270 bytes a query.
    void reset()
    {
        rcode = 0;
        qtype = 0;
        dropped = truncated = referral = edns = dnssec = notify_ack = false;
        xfr = nullptr;
        id = 0;
        question_end = 0;
        qname_len = 0;
    }
};

// The reply to the query in `q` written to `out` (`cap` bytes, at least 512), its length returned; 0 when nothing
// should be sent. `tcp` lifts the size an answer may have from what UDP carries to 64 KiB; `xfr_allowed` is
// whether the peer may have a whole zone.
size_t answer(const zone_set& zones, const uint8_t* q, size_t qlen, uint8_t* out, size_t cap, bool tcp,
              bool xfr_allowed, answer_meta& meta);

// A whole zone as AXFR sends it (RFC 5936): the SOA, every other record, the SOA again, across as many messages of at
// most 64 KiB as it takes, each handed to `emit` in turn. The first message carries the question of the query `q`.
template <typename Emit>
void transfer(const zone& z, const uint8_t* q, size_t question_end, Emit&& emit);

// A NOTIFY for zone `z` (RFC 1996), with `id`, into `out`; its length.
size_t make_notify(const zone& z, uint16_t id, uint8_t* out, size_t cap);

// One record written with its owner, compressing names in its data the way RFC 3597 allows for the types RFC 1035
// defined, and SRV's target never.
void write_rr(writer& w, std::string_view owner, uint16_t type, uint32_t ttl, std::string_view rdata);

template <typename Emit>
void transfer(const zone& z, const uint8_t* q, size_t question_end, Emit&& emit)
{
    static thread_local uint8_t buf[max_message];
    const rrset* soa = z.soa();
    if (!soa || soa->rdata.empty())
        return;
    bool first = true;
    uint16_t count = 0;
    writer w(buf, max_message);
    const auto begin = [&]()
    {
        w = writer(buf, max_message);
        // A response, authoritative, opcode QUERY.
        w.put16(rd16(q));
        w.put16(0x8400);
        w.put16(first ? 1 : 0);
        w.put16(0);
        w.put16(0);
        w.put16(0);
        if (first)
            w.put(q + header_len, question_end - header_len);
        count = 0;
    };
    const auto flush = [&]()
    {
        w.patch16(6, count);
        emit(static_cast<const uint8_t*>(buf), w.size());
        first = false;
    };
    const auto add = [&](std::string_view owner, uint16_t t, uint32_t ttl, std::string_view rd)
    {
        auto m = w.save();
        write_rr(w, owner, t, ttl, rd);
        if (w.overflowed() || count == 0xFFFF)
        {
            w.restore(m);
            flush();
            begin();
            const auto fresh = w.save();
            write_rr(w, owner, t, ttl, rd);
            // A record no message can hold is left out rather than sent as a message cut inside it.
            if (w.overflowed())
            {
                w.restore(fresh);
                return;
            }
        }
        ++count;
    };
    begin();
    add(z.origin, soa->type, soa->ttl, soa->rdata[0]);
    for (const auto& [name, nd] : z.names)
    {
        for (const auto& s : nd.sets)
        {
            if (s.type == 6 && name == z.origin)
                continue;
            for (const auto& rd : s.rdata)
                add(name, s.type, s.ttl, rd);
        }
        // A signed zone's RRSIGs go with it, each a record of type 46.
        for (const auto& s : nd.sigs)
            for (const auto& rd : s.rdata)
                add(name, 46, s.ttl, rd);
    }
    add(z.origin, soa->type, soa->ttl, soa->rdata[0]);
    flush();
}

}   // namespace socketley::dns
