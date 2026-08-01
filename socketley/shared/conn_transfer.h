#pragma once
// Moving a connection between runtimes that are no longer in the same process.
//
// ─── TWO MECHANISMS, AND WHY NOT ONE ────────────────────────────────────────
//
// The obvious design is one channel that everything goes down, and it is the
// wrong one.  What a runtime does to a connection falls into two shapes and
// they want opposite things:
//
//   HANDOVER.  The far runtime is going to *be* the endpoint — TCP routing, a
//   sub-server that owns the client from here on.  Nothing in the middle reads
//   the bytes, rewrites them, or needs to see them again.  Relaying those bytes
//   through the middle is pure loss: every byte is copied out of one socket and
//   into another for no reason but that the middle happens to hold the
//   descriptor.  So the descriptor goes instead, once, with SCM_RIGHTS, and
//   after that the two ends talk directly and the middle is not in the path at
//   all.  That is strictly less work than the in-process version, which still
//   copies through the parent.
//
//   RELAY.  The middle is rewriting headers, pooling backend connections, or
//   otherwise has to keep seeing the traffic.  It cannot hand the descriptor
//   away because it needs it.  Here the bytes travel, tagged with the conn_ref
//   they belong to, over a UNIX socket — never TCP loopback.  Loopback would
//   mean an IP header, a checksum, a port lookup and a second socket buffer for
//   traffic that never leaves the machine; AF_UNIX is a copy into the peer's
//   buffer and nothing else.  The middle was already paying a memcpy in this
//   case, so what changes is where the copy lands, not that there is one.
//
// The split is exactly the line where the middle's presence is load-bearing.
// Collapsing the two into one mechanism means either paying the relay for
// connections nobody in the middle is reading — the case that is most of the
// traffic — or trying to hand away a descriptor the middle still needs.
//
// ─── THE PART THAT IS EASY TO GET WRONG ─────────────────────────────────────
//
// SCM_RIGHTS duplicates.  After a successful send both processes hold a working
// descriptor for the same socket, and if the sender keeps writing, the two
// interleave and the receiver's protocol desynchronises.  A handover is
// therefore not complete when the send returns; it is complete when the sender
// has *relinquished*, which is three things in this order:
//
//   1. stop submitting anything that names the descriptor,
//   2. wait until the ring owes it nothing for that descriptor,
//   3. close.
//
// Step 2 is not optional and is the reason this is a two-call interface rather
// than one.  An SQE carries a descriptor NUMBER that the kernel resolves when
// it consumes the SQE, which under SQPOLL is on another thread at a moment
// nothing here controls.  Closing between the submission and the consumption
// does not cancel the operation, it redirects it onto whatever inherits the
// number — the hazard event_loop's fd_inflight() exists to answer.  This
// project has paid for that lesson more than once and the handover is a new
// place to pay it.
//
// worker_protocol.h says no descriptors cross the daemon-worker control socket.
// That remains true of the control socket and its frames.  This is a different
// channel with a different rule, and the rule it does not get to break is the
// one above.
#include <cstdint>
#include <string>
#include <string_view>

#include "conn_identity.h"

class event_loop;

namespace conn_transfer
{

// ── Handover: the descriptor itself ─────────────────────────────────────────

// One connection being given away.  `backlog` is what the sender had already
// read off the socket and not yet acted on — a handover after the first read is
// the normal case, not the exception, because routing decisions are made *from*
// the first bytes.  Without it those bytes are simply lost, and the receiver
// sees a stream that starts in the middle of a message.
struct handover
{
    conn_ref    ref;
    std::string origin;      // runtime name that is giving it up, for the log
    std::string backlog;     // already-read bytes, in wire order, may be empty
};

// Send `payload_fd` and `h` down `channel_fd` (an AF_UNIX stream socket).
//
// On success the descriptor exists in both processes.  The sender has NOT given
// it up yet — see relinquish() below, which is the other half and is not
// optional.  Returns false and touches nothing on failure.
bool send_handover(int channel_fd, const handover& h, int payload_fd);

// Take one handover off `channel_fd`.  On success `out_fd` is a descriptor in
// this process, owned by this process, and `h` describes it.
//
// Returns false when there is not a complete handover to take, which for a
// blocking channel means the peer is gone.  `out_fd` is -1 unless true is
// returned; a partial read never leaves a descriptor stranded, because the
// kernel delivers the SCM_RIGHTS control message with the first byte of the
// message it was attached to and this sends the whole thing in one sendmsg.
bool recv_handover(int channel_fd, handover& h, int& out_fd);

// The sender's half of the handover, and the thing that makes the receiver the
// owner rather than a second writer.  Two calls, and they are two because the
// answer to "is the ring finished with this descriptor" arrives on a later turn
// of the loop than the question.
//
// withdraw() asks for everything armed on `fd` back.  Call it ONCE.  Every call
// costs an SQE and, worse, a caller that calls it every turn never makes
// progress: the cancel it just submitted is the completion the next drain
// consumes, so the operation being cancelled never gets a turn to report.  A
// handover decided from inside a read completion has nothing armed and does not
// need this at all, which is the ordinary case — the routing decision is made
// from the first bytes, and at that moment the read that carried them has
// already reported.
void withdraw(event_loop* loop, int fd);

// relinquish() closes.  Returns true once the descriptor is gone from this
// process, false while the ring still owes something for it — in which case the
// caller tries again on a later turn and must not write to the descriptor in
// the meantime.  Never write to it after send_handover() succeeds, whatever
// this answers: the receiver is already on the other end of it.
//
// `loop` may be null for a caller with no ring, which closes immediately.
bool relinquish(event_loop* loop, int fd);

// ── Relay: the bytes, tagged ────────────────────────────────────────────────
//
// A frame is [u32 payload_len][u8 opcode][conn_ref][payload].  The length
// prefix is what lets a receiver skip an opcode it does not know instead of
// desynchronising, the same rule worker_protocol.h keeps and for the same
// reason: the two ends are separate processes with independent lifetimes and an
// upgrade can replace the binary under one of them.

enum class relay_op : uint8_t
{
    open  = 1,   // a connection now exists under this ref; payload is its origin name
    data  = 2,   // payload is bytes from that connection
    close = 3,   // it is gone; payload is empty
};

inline constexpr size_t relay_header_size = 4 + 1 + conn_ref_wire_size;

// Refuse rather than allocate.  A relay payload is one read off a socket, which
// this project caps at 16 KB, plus room for a rewritten header.
inline constexpr uint32_t relay_max_payload = 1u * 1024u * 1024u;

std::string relay_frame(relay_op op, const conn_ref& ref, std::string_view payload);

// Pulls one whole frame off the front of `buf`.  False with `fatal` clear means
// "not yet, keep reading" and leaves `buf` alone.  False with `fatal` set means
// the stream is not a relay stream and there is no resynchronisation point.
bool take_relay_frame(std::string& buf, relay_op& op, conn_ref& ref,
                      std::string& payload, bool& fatal);

}   // namespace conn_transfer
