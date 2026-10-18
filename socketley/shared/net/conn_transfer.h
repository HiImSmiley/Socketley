#pragma once
// HANDOVER gives the descriptor away with SCM_RIGHTS; RELAY tags the bytes
// with a conn_ref for a middle that must keep seeing them.
#include <cstdint>
#include <string>
#include <string_view>

#include "conn_identity.h"

class event_loop;

namespace conn_transfer
{

// ── Handover: the descriptor itself ─────────────────────────────────────────

// `backlog` is what the sender already read; routing is decided from the first
// bytes, so a handover after a read is the normal case.
struct handover
{
    conn_ref    ref;
    std::string origin;      // runtime name that is giving it up, for the log
    std::string backlog;     // already-read bytes, in wire order, may be empty
};

// On success the descriptor exists in BOTH processes; relinquish() is the
// other half and is not optional.
bool send_handover(int channel_fd, const handover& h, int payload_fd);

// False means no complete handover, which on a blocking channel means the peer
// is gone; a partial read cannot strand a descriptor, this is one sendmsg.
bool recv_handover(int channel_fd, handover& h, int& out_fd);

// Asks back everything armed on `fd`, exactly once, because the cancel is the
// completion the next drain eats.
void withdraw(event_loop* loop, int fd);

// True once the descriptor is gone, false means retry later, and never write
// to it after send_handover() succeeds whatever this answers.
bool relinquish(event_loop* loop, int fd);

// [u32 len][u8 op][conn_ref][payload]; the prefix lets a receiver skip an
// opcode it does not know instead of desynchronising.

enum class relay_op : uint8_t
{
    open  = 1,   // a connection now exists under this ref; payload is its origin name
    data  = 2,   // payload is bytes from that connection
    close = 3,   // it is gone; payload is empty
};

inline constexpr size_t relay_header_size = 4 + 1 + conn_ref_wire_size;

// Refuse rather than allocate: far above the 16 KB one socket read this
// project caps at, far below anything that would hurt to reject.
inline constexpr uint32_t relay_max_payload = 1u * 1024u * 1024u;

std::string relay_frame(relay_op op, const conn_ref& ref, std::string_view payload);

// Pulls one whole frame off the front of `buf`; `fatal` clear means not yet
// and leaves `buf` alone, `fatal` set means the stream is not a relay stream.
bool take_relay_frame(std::string& buf, relay_op& op, conn_ref& ref,
                      std::string& payload, bool& fatal);

}   // namespace conn_transfer
