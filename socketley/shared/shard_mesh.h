#pragma once
// A crossing between two shards of one runtime, without the daemon in the
// middle.
//
// ─── WHAT THIS CHANGES, AND WHAT IT DELIBERATELY DOES NOT ───────────────────
//
// It changes WHO a crossing goes to.  It does not change what one looks like.
//
// A shard posts to `name#j` through its own request_channel exactly as before;
// the ticket, the chan_request/chan_reply codec, the parked-request bookkeeping
// and the framing cache_instance puts inside the payload are all untouched.
// The only difference is that `name#j` now resolves in this process's own sink
// table to a mesh_sink, instead of missing it and falling through to the sink
// that writes to the daemon.
//
// cache_instance does not change by one line for this.  That is the test of
// whether the seam was in the right place.
//
// ─── WHY, WITH THE NUMBER THAT DECIDED IT ───────────────────────────────────
//
// The daemon relay is two round trips instead of one, and that was the cost
// that was expected.  The cost that was measured is different and worse: every
// shard's foreign traffic funnels through ONE process, so the relay is a
// serialisation point, and a serialisation point does not care how fast one hop
// is.  Throughput at depth 1, four arms, one client:
//
//     N = 1   103,270      N = 2   101,010      N = 4   93,167      N = 8   83,333
//
// Losses of 2%, 10% and 19% against crossing fractions of 50%, 75% and 87.5%.
// If the cost were per-crossing latency the losses would be about 4%, 6% and 7%
// -- proportional to the fraction.  They grow faster than it, which is
// contention rather than latency.
//
// The same reasoning does NOT apply to a sharded server, where routing is rare
// and `--lua` measures 2.46x at eight shards: there the funnel is never hot.
// This is a cache, where routing is the normal case.
//
// ─── THE RELAY IS NOT REMOVED.  IT IS THE FLOOR. ────────────────────────────
//
// A mesh_sink with no usable link delegates to the sink it was given, which is
// the daemon.  Four things follow, and the design rests on all four:
//
//   * correctness never depends on the mesh existing;
//   * a shard posting to a sibling that has not finished starting is a relay,
//     not an error;
//   * a link that dies degrades this runtime to slower, not to broken;
//   * and the two routes are one binary apart, so the measurement that decides
//     whether any of this was worth it is an A/B on the same build.
//
// The cost of that safety is that a mesh which never works looks exactly like a
// mesh that made no difference.  So every crossing is counted by ROUTE, and the
// counters are reported -- see stat_direct()/stat_relayed().  "The mesh made no
// difference" and "the mesh was never used" have to be distinguishable or the
// benchmark means nothing.
//
// ─── LIFETIME ───────────────────────────────────────────────────────────────
//
// Written down before the code was, because N**2 links is the shape this tree
// has paid the most for -- the half-close hold was fixed four times.
//
// N**2 is the number of LINKS, not the number of PATHS.  Each process holds
// N-1 of them, every one identical, with ONE way to die and one function that
// does it.  The number that has ever hurt here is how many places can tear
// something down, and for a link it is one: die().
//
//   WHO NOTICES A DEAD PEER.  The reader, and nothing else.  One one-shot
//   poll_add per link, re-armed after each drain -- the same arrangement the
//   worker's control socket uses, and for the same reason: a link drained on a
//   timer instead of a completion inherits that timer's latency, which cost a
//   cross-process `cache set` a measured 20.00 ms before the control socket was
//   armed.
//
//   WHAT A HALF-OPEN LINK DOES.  Nothing legitimate, and this is an invariant
//   rather than an observation.  Both directions carry traffic for the whole
//   life of a link, so this protocol has no graceful half-close: ANY end of
//   input is the peer going away.  That deletes the "is this a tidy shutdown or
//   a failure" question outright -- the question that produced four fixes for
//   one hold -- and it is stated at the point the end of input is read so that
//   nobody reintroduces it by being careful.
//
//   A CROSSING IN FLIGHT WHEN A SHARD DIES.  The moment a link is marked dead
//   it sweeps its OWN parked tickets and completes each `no_target`.  The
//   channel then delivers on_request_reply to the asking runtime, which already
//   knows how to render that into the reply it owes its client.  No timer, no
//   deadline, no hang.  A ticket is parked on exactly one link and only that
//   link can complete it, so the sweep is bounded by what that link owed.
//
//   WHO CLOSES THE DESCRIPTOR.  die(), after the sweep, through the loop --
//   which holds the number until the armed poll has reported.  A completion
//   that lands afterwards finds the link dead and drops, the same "retire, then
//   let the completion land" the supervisor uses for a worker it is replacing.
//
// ─── WHAT IS NOT HERE, NAMED RATHER THAN LEFT TO BE FOUND ───────────────────
//
// TLS is not here, and does not belong here.  The links are socketpair ends
// between sibling processes of one runtime on one host under one uid -- there
// is no network path to encrypt and no second party to authenticate.  Note
// that runtime_instance::get_mesh_tls_paths() is NOT about this file: it is
// the PROXY's backend leg (--client-ca / --client-cert / --client-key), a
// different feature that happens to share the word "mesh".  Reading that
// virtual as coverage this file lacks is the mistake this paragraph exists to
// prevent.
//
// A link cannot be re-established.  The descriptors are socketpair ends placed
// at fork, and a socketpair cannot be re-attached to a process that did not
// inherit it -- so a shard that dies and is restarted by its supervisor comes
// back with no links, and its crossings relay through the daemon until the
// whole runtime restarts.  Correct, slower for one shard's share of the
// traffic, and visible in the route counters rather than silent.
//
// The eventual answer is passing new ends over the control socket, for which
// shared/conn_transfer.h is already the mechanism.  It is a separate step with
// its own tests, and it is only worth buying if the measurement says the mesh
// earns its keep.
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "event_loop.h"
#include "event_loop_definitions.h"
#include "frame_writer.h"
#include "logging.h"
#include "request_channel.h"
#include "worker_protocol.h"

// What a link hands a request to once it has arrived from a sibling.  The
// worker supplies this; the link knows nothing about runtimes.
using shard_mesh_server = bool (*)(void* ctx, std::string_view target,
                                   std::string_view payload, std::string& reply);

// One link, to one sibling.
class shard_link : public io_handler
{
public:
    shard_link(int fd, uint32_t peer_index, request_channel* channel,
               shard_mesh_server server, void* server_ctx)
        : m_writer(fd), m_fd(fd), m_peer(peer_index),
          m_channel(channel), m_server(server), m_ctx(server_ctx)
    {
        // Non-blocking, because every write goes through frame_writer's backlog
        // and every read happens on a poll completion.  A blocking descriptor
        // here would stall this shard's event loop on a sibling's scheduling.
        const int fl = ::fcntl(m_fd, F_GETFL, 0);
        if (fl >= 0)
            if (::fcntl(m_fd, F_SETFL, fl | O_NONBLOCK) < 0) {}
    }

    ~shard_link() override
    {
        if (m_fd >= 0 && !m_loop)
            ::close(m_fd);
    }

    shard_link(const shard_link&)            = delete;
    shard_link& operator=(const shard_link&) = delete;

    bool attach(event_loop& loop)
    {
        m_loop = &loop;
        loop.register_owner(this);
        arm();
        return m_armed;
    }

    bool alive() const { return !m_dead && m_fd >= 0 && !m_writer.dead(); }
    uint32_t peer() const { return m_peer; }

    // Send one request to the sibling.  False means it did not go — the caller
    // relays it instead, which is why this returns a fact rather than logging
    // one.
    bool send_request(uint64_t ticket, std::string_view target,
                      std::string_view payload)
    {
        if (!alive())
            return false;

        if (!m_writer.write(worker_proto::frame(
                worker_proto::frame_type::chan_req,
                worker_proto::encode_chan_request(ticket, target, payload))))
        {
            // The backlog is full or the socket is gone.  Either way this link
            // is not carrying anything more; the relay is still there.
            die("the backlog to a sibling filled or its socket went");
            return false;
        }

        if (m_writer.dead())
        {
            die("writing to a sibling failed");
            return false;
        }

        m_owed.insert(ticket);
        return true;
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        m_armed = false;
        if (m_dead)
            return;

        // A cancelled poll is the loop withdrawing it, not the peer.
        if (cqe->res < 0 && cqe->res != -EAGAIN)
        {
            die("the poll on a sibling link reported an error");
            return;
        }

        if (!drain())
            return;                    // drain() called die() itself

        m_writer.flush();
        if (m_writer.dead())
        {
            die("flushing to a sibling failed");
            return;
        }
        arm();
    }

    // Give up this link and answer everything it owed.
    //
    // The one function that ends a link.  Everything below is ordered so that
    // no step can be reached twice: the flag first, then the tickets, then the
    // descriptor.
    void die(const char* why)
    {
        if (m_dead)
            return;
        m_dead = true;
        m_writer.mark_dead();

        // Every crossing this link was carrying, answered now rather than left
        // for a deadline that does not exist.  The channel delivers each one to
        // the runtime that asked, which renders it as the error it owes its
        // client.
        if (m_channel)
            for (const uint64_t t : m_owed)
                m_channel->complete_deferred(t, request_status::no_target, {});
        const size_t swept = m_owed.size();
        m_owed.clear();

        if (m_fd >= 0)
        {
            // Through the loop, which holds the number until the armed poll has
            // reported: a plain close() here would free it for the next accept
            // while a completion still names it.
            if (m_loop)
            {
                if (m_armed)
                    if (!m_loop->submit_poll_remove(&m_req)) {}
                m_loop->close_fd(m_fd);
            }
            else
            {
                ::close(m_fd);
            }
            m_fd = -1;
        }

        LOG_WARN(("shard mesh: the link to shard " + std::to_string(m_peer)
                  + " is down (" + why + "); " + std::to_string(swept)
                  + " crossing(s) answered, the rest relay through the daemon")
                 .c_str());
    }

    size_t owed() const { return m_owed.size(); }

private:
    void arm()
    {
        if (m_dead || !m_loop || m_armed || m_fd < 0)
            return;
        // The request carries its own owner: the loop dispatches a completion
        // by the handler named in it, and one left empty matches no live
        // registration, so the completion is dropped.  Measured before this
        // line existed: the mesh built its links, sent its requests, and every
        // crossing hung — the poll never came back because nothing was waiting
        // for it.
        m_req   = { this, nullptr, m_fd, 0, op_poll };
        m_armed = m_loop->submit_poll_add(m_fd, POLLIN, &m_req);
        if (!m_armed)
        {
            // Nothing will wake this link again, and a link nothing wakes is a
            // link whose crossings never come back.  Better dead and relaying.
            die("a poll on a sibling link could not be armed");
        }
    }

    // Read what is there and act on every whole frame.  False means the link
    // has been given up on.
    bool drain()
    {
        char buf[4096];
        for (;;)
        {
            const ssize_t n = ::read(m_fd, buf, sizeof(buf));
            if (n > 0)
            {
                m_in.append(buf, static_cast<size_t>(n));
                continue;
            }

            // ─── ANY END OF INPUT IS THE PEER GOING AWAY ────────────────────
            //
            // Not "is this a tidy half-close or a failure".  That question does
            // not exist on this link and must not be invented here: both
            // directions carry traffic for the whole life of a link, so a peer
            // that has stopped writing has stopped, and there is nothing a
            // half-open mesh link could still be for.
            //
            // Written here rather than in the header alone because this is the
            // line somebody would otherwise "fix" into a graceful-shutdown
            // path, and that is the shape that cost this tree four fixes for
            // one hold.
            if (n == 0)
            {
                die("a sibling closed its end");
                return false;
            }
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            die("reading from a sibling failed");
            return false;
        }

        worker_proto::frame_type type{};
        uint16_t                 ver = 0;
        std::string              payload;
        bool                     fatal = false;

        while (worker_proto::take_frame(m_in, type, ver, payload, fatal))
            handle(type, payload);

        if (fatal)
        {
            die("a sibling sent a frame this build cannot read");
            return false;
        }
        return true;
    }

    void handle(worker_proto::frame_type type, const std::string& payload)
    {
        // Two frame types and no others.  The ticket in a chan_req belongs to
        // the SIBLING and goes back with the answer; the ticket in a chan_rep
        // belongs to this process.  The two spaces never meet, which is the
        // same arrangement the worker and the daemon already rely on and the
        // reason neither needs a tag.
        if (type == worker_proto::frame_type::chan_req)
        {
            worker_proto::chan_request_wire q;
            if (!worker_proto::decode_chan_request(payload, q))
                return;

            std::string reply;
            const bool ok = m_server && m_server(m_ctx, q.target, q.payload, reply);

            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::chan_rep,
                    worker_proto::encode_chan_reply(
                        q.ticket,
                        static_cast<uint8_t>(ok ? request_status::ok
                                                : request_status::no_target),
                        reply))))
                die("could not answer a sibling: the backlog is full");
            return;
        }

        if (type == worker_proto::frame_type::chan_rep)
        {
            worker_proto::chan_reply_wire p;
            if (!worker_proto::decode_chan_reply(payload, p))
                return;

            m_owed.erase(p.ticket);
            if (m_channel)
                m_channel->complete_deferred(
                    p.ticket, static_cast<request_status>(p.status), p.payload);
        }
        // Anything else travels the daemon's wire, not this one, and is skipped
        // rather than fatal — the length in the header is what makes that safe.
    }

    frame_writer m_writer;
    int          m_fd{-1};
    uint32_t     m_peer{0};

    request_channel*  m_channel{nullptr};
    shard_mesh_server m_server{nullptr};
    void*             m_ctx{nullptr};

    event_loop* m_loop{nullptr};
    io_request  m_req{};
    bool        m_armed{false};
    bool        m_dead{false};

    std::string                 m_in;
    std::unordered_set<uint64_t> m_owed;
};

// What `name#j` resolves to in a shard's own sink table.
//
// Registered under the qualified name shared/shard_target.h defines, so the
// lookup that used to miss and fall through to the daemon now hits here first.
// Everything about the request is the same on both routes.
class mesh_sink : public request_sink
{
public:
    mesh_sink(shard_link* link, request_sink* relay)
        : m_link(link), m_relay(relay) {}

    void serve_request(std::string_view, std::string& out) override
    {
        out.clear();          // unreachable: serves_inline() is false
    }

    bool serves_inline() const override { return false; }

    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override
    {
        if (m_link && m_link->send_request(ticket, target, payload))
        {
            ++m_direct;
            return true;
        }

        // No link, or a link that has just given up.  The relay is the route
        // that always exists; a crossing is slower here, never lost.
        if (m_relay && m_relay->serve_deferred(ticket, target, payload))
        {
            ++m_relayed;
            return true;
        }
        return false;
    }

    uint64_t stat_direct()  const { return m_direct; }
    uint64_t stat_relayed() const { return m_relayed; }

private:
    shard_link*   m_link{nullptr};
    request_sink* m_relay{nullptr};
    uint64_t      m_direct{0};
    uint64_t      m_relayed{0};
};
