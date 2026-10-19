#pragma once
// What the CLI, a script, a storage notification or a topic rule asks of an mqtt runtime, as the request channel
// carries it: the marker, a verb and its fields in byte_codec form. Answered in text for the CLI and "ok" for a
// publish.
#include <cstdint>
#include <string>
#include <string_view>

#include "../../shared/util/byte_codec.h"

namespace socketley::mqtt
{

inline constexpr std::string_view command_prefix = "\x02skl-mqtt\n";
// One shard's word to another, which no command starts with.
inline constexpr std::string_view shard_prefix = "\x02skl-mqtt-shard\n";

enum class verb : uint8_t
{
    publish   = 1,
    sessions  = 2,
    kick      = 3,
    retained  = 4,
    clear     = 5,
    tap_open  = 6,
    tap_poll  = 7,
    tap_close = 8,
};

inline std::string command_publish(std::string_view topic, std::string_view payload, uint8_t qos, bool retain)
{
    socketley::bytes::writer w(command_prefix);
    w.u8(static_cast<uint8_t>(verb::publish));
    w.bytes(topic);
    w.bytes(payload);
    w.u8(qos);
    w.flag(retain);
    return w.take();
}

// A verb with one text argument, or none: sessions, kick, retained, clear, tap_open, tap_poll, tap_close.
inline std::string command_text(verb v, std::string_view arg = {}, bool flag = false)
{
    socketley::bytes::writer w(command_prefix);
    w.u8(static_cast<uint8_t>(v));
    w.bytes(arg);
    w.flag(flag);
    return w.take();
}

}   // namespace socketley::mqtt
