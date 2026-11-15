#pragma once
// A shell's `socketley send` straight to the worker holding the runtime: the daemon hands one end of a SEQPACKET pair
// to the builtin with its answer to a `send-link` and the other to the worker, and from then on each line is one
// message and its answer one byte, with no third process woken for it.
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace socketley::send_link
{

// What the grant channel carries beside the end of a link; '@' is outside runtime_manager::valid_name(), as for
// peer_link::interactive_marker.
inline constexpr std::string_view marker = "@s";

// The longest line a link carries, which is also each link's buffer in the worker; a longer one goes through the daemon.
inline constexpr size_t max_message = 4096;

// The answer byte: the line was handed to the runtime as a `deliver` frame is, or none of it was and the daemon is
// asked instead, which is what makes a refusal safe to retry.
inline constexpr uint8_t delivered = 0;
inline constexpr uint8_t not_taken = 1;

// The most links one worker serves, a megabyte of buffers; a grant past it is closed, and the shell that asked goes on
// through the daemon.
inline constexpr size_t max_links = 256;

}   // namespace socketley::send_link
