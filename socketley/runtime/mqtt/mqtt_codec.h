#pragma once
// MQTT 3.1, 3.1.1 and 5.0 packets read from and written to bytes, with every rule of the specification a receiver
// must enforce checked here, so the broker above it only ever sees a well-formed packet.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::mqtt
{

// The protocol levels a CONNECT names: 3 is MQTT 3.1 ("MQIsdp"), 4 is 3.1.1 and 5 is 5.0.
inline constexpr uint8_t level_31  = 3;
inline constexpr uint8_t level_311 = 4;
inline constexpr uint8_t level_5   = 5;

// The largest Remaining Length four bytes of variable length integer carry.
inline constexpr uint32_t max_remaining = 268'435'455;

enum class packet_type : uint8_t
{
    connect = 1, connack, publish, puback, pubrec, pubrel, pubcomp,
    subscribe, suback, unsubscribe, unsuback, pingreq, pingresp, disconnect, auth
};

const char* packet_name(packet_type t);

// The reason codes of 5.0, which 3.1.1 answers are mapped from where it has an equivalent.
namespace reason
{
inline constexpr uint8_t success                   = 0x00;
inline constexpr uint8_t granted_qos1              = 0x01;
inline constexpr uint8_t granted_qos2              = 0x02;
inline constexpr uint8_t disconnect_with_will      = 0x04;
inline constexpr uint8_t no_matching_subscribers   = 0x10;
inline constexpr uint8_t no_subscription_existed   = 0x11;
inline constexpr uint8_t continue_authentication   = 0x18;
inline constexpr uint8_t unspecified               = 0x80;
inline constexpr uint8_t malformed                 = 0x81;
inline constexpr uint8_t protocol_error            = 0x82;
inline constexpr uint8_t implementation_specific   = 0x83;
inline constexpr uint8_t unsupported_version       = 0x84;
inline constexpr uint8_t client_id_invalid         = 0x85;
inline constexpr uint8_t bad_user_or_password      = 0x86;
inline constexpr uint8_t not_authorized            = 0x87;
inline constexpr uint8_t server_unavailable        = 0x88;
inline constexpr uint8_t server_busy               = 0x89;
inline constexpr uint8_t bad_auth_method           = 0x8C;
inline constexpr uint8_t keepalive_timeout         = 0x8D;
inline constexpr uint8_t session_taken_over        = 0x8E;
inline constexpr uint8_t topic_filter_invalid      = 0x8F;
inline constexpr uint8_t topic_name_invalid        = 0x90;
inline constexpr uint8_t packet_id_in_use          = 0x91;
inline constexpr uint8_t packet_id_not_found       = 0x92;
inline constexpr uint8_t receive_max_exceeded      = 0x93;
inline constexpr uint8_t topic_alias_invalid       = 0x94;
inline constexpr uint8_t packet_too_large          = 0x95;
inline constexpr uint8_t message_rate_too_high     = 0x96;
inline constexpr uint8_t quota_exceeded            = 0x97;
inline constexpr uint8_t administrative_action     = 0x98;
inline constexpr uint8_t payload_format_invalid    = 0x99;
inline constexpr uint8_t qos_not_supported         = 0x9B;
inline constexpr uint8_t shared_not_supported      = 0x9E;
inline constexpr uint8_t sub_ids_not_supported     = 0xA1;
inline constexpr uint8_t wildcards_not_supported   = 0xA2;
}   // namespace reason

const char* reason_text(uint8_t code);

// The properties of a 5.0 packet; which of them a packet may carry is checked when it is read.
struct properties
{
    std::optional<uint8_t>     payload_format;
    std::optional<uint32_t>    message_expiry;
    std::optional<std::string> content_type;
    std::optional<std::string> response_topic;
    std::optional<std::string> correlation_data;
    std::vector<uint32_t>      subscription_ids;
    std::optional<uint32_t>    session_expiry;
    std::optional<std::string> assigned_client_id;
    std::optional<uint16_t>    server_keepalive;
    std::optional<std::string> auth_method;
    std::optional<std::string> auth_data;
    std::optional<uint8_t>     request_problem_info;
    std::optional<uint32_t>    will_delay;
    std::optional<uint8_t>     request_response_info;
    std::optional<std::string> response_info;
    std::optional<std::string> server_reference;
    std::optional<std::string> reason_string;
    std::optional<uint16_t>    receive_maximum;
    std::optional<uint16_t>    topic_alias_maximum;
    std::optional<uint16_t>    topic_alias;
    std::optional<uint8_t>     maximum_qos;
    std::optional<uint8_t>     retain_available;
    std::vector<std::pair<std::string, std::string>> user;
    std::optional<uint32_t>    maximum_packet_size;
    std::optional<uint8_t>     wildcard_available;
    std::optional<uint8_t>     sub_ids_available;
    std::optional<uint8_t>     shared_available;

    bool empty() const;
};

struct will_message
{
    std::string topic;
    std::string payload;
    uint8_t     qos{0};
    bool        retain{false};
    properties  props;
};

struct connect_packet
{
    uint8_t     level{level_311};
    bool        clean_start{true};
    uint16_t    keepalive{0};
    std::string client_id;
    std::optional<will_message> will;
    std::optional<std::string>  username;
    std::optional<std::string>  password;
    properties  props;
};

struct connack_packet
{
    bool       session_present{false};
    uint8_t    reason{reason::success};
    properties props;
};

struct publish_packet
{
    bool        dup{false};
    uint8_t     qos{0};
    bool        retain{false};
    std::string topic;
    uint16_t    packet_id{0};
    properties  props;
    std::string payload;
};

// PUBACK, PUBREC, PUBREL and PUBCOMP, which differ only in their type.
struct ack_packet
{
    packet_type type{packet_type::puback};
    uint16_t    packet_id{0};
    uint8_t     reason{reason::success};
    properties  props;
};

struct subscription
{
    std::string filter;
    uint8_t     qos{0};
    bool        no_local{false};
    bool        retain_as_published{false};
    uint8_t     retain_handling{0};
};

struct subscribe_packet
{
    uint16_t                  packet_id{0};
    properties                props;
    std::vector<subscription> entries;
};

struct suback_packet
{
    packet_type          type{packet_type::suback};
    uint16_t             packet_id{0};
    properties           props;
    std::vector<uint8_t> reasons;
};

struct unsubscribe_packet
{
    uint16_t                 packet_id{0};
    properties               props;
    std::vector<std::string> filters;
};

struct disconnect_packet
{
    uint8_t    reason{reason::success};
    properties props;
};

struct auth_packet
{
    uint8_t    reason{reason::success};
    properties props;
};

// Why a packet could not be read: the reason code a 5.0 DISCONNECT names, and words for the log.
struct refusal
{
    uint8_t     code{reason::malformed};
    std::string why;
};

// ── Framing ─────────────────────────────────────────────────────────────────

enum class frame_status : uint8_t { ok, incomplete, malformed, too_large };

struct frame
{
    uint8_t          first{0};
    packet_type      type{packet_type::connect};
    uint8_t          flags{0};
    std::string_view body;
    size_t           size{0};
};

// The packet at the front of `in`: ok with `out` set, incomplete when more bytes are needed, malformed when the fixed
// header cannot be one, too_large when it says more than `max_size` bytes.
frame_status take_frame(std::string_view in, uint32_t max_size, frame& out);

// ── Reading ─────────────────────────────────────────────────────────────────

// Each takes the frame's body and flags and the protocol level the connection speaks.
bool read_connect(const frame& f, connect_packet& out, refusal& err);
bool read_publish(const frame& f, uint8_t level, publish_packet& out, refusal& err);
bool read_ack(const frame& f, uint8_t level, ack_packet& out, refusal& err);
bool read_subscribe(const frame& f, uint8_t level, subscribe_packet& out, refusal& err);
bool read_unsubscribe(const frame& f, uint8_t level, unsubscribe_packet& out, refusal& err);
bool read_disconnect(const frame& f, uint8_t level, disconnect_packet& out, refusal& err);
bool read_auth(const frame& f, uint8_t level, auth_packet& out, refusal& err);
bool read_empty(const frame& f, refusal& err);
// The answers a broker sends, read by clients and by the tests that play one.
bool read_connack(const frame& f, uint8_t level, connack_packet& out, refusal& err);
bool read_suback(const frame& f, uint8_t level, suback_packet& out, refusal& err);

// ── Writing ─────────────────────────────────────────────────────────────────

void write_connect(std::string& out, const connect_packet& p);
void write_connack(std::string& out, uint8_t level, const connack_packet& p);
void write_publish(std::string& out, uint8_t level, const publish_packet& p);
void write_ack(std::string& out, uint8_t level, const ack_packet& p);
void write_subscribe(std::string& out, uint8_t level, const subscribe_packet& p);
void write_suback(std::string& out, uint8_t level, const suback_packet& p);
void write_unsubscribe(std::string& out, uint8_t level, const unsubscribe_packet& p);
void write_pingreq(std::string& out);
void write_pingresp(std::string& out);
void write_disconnect(std::string& out, uint8_t level, const disconnect_packet& p);
void write_auth(std::string& out, const auth_packet& p);

// The bytes write_publish() would produce, so a sender can hold a packet to a peer's Maximum Packet Size first.
size_t publish_size(uint8_t level, const publish_packet& p);

// A PUBLISH as views of what it carries, which is how the broker writes one to each subscriber: a publish_packet
// copied the topic, the payload and every property once per subscriber.
struct publish_parts
{
    uint8_t          qos{0};
    bool             retain{false};
    bool             dup{false};
    uint16_t         packet_id{0};
    std::string_view topic;
    std::string_view payload;
    // 5.0's properties, written by the put_prop_* below without their length.
    std::string_view props;
};
size_t publish_parts_size(uint8_t level, const publish_parts& p);
void write_publish_parts(std::string& out, uint8_t level, const publish_parts& p);
void put_prop_byte(std::string& out, uint8_t id, uint8_t v);
void put_prop_u32(std::string& out, uint8_t id, uint32_t v);
void put_prop_varint(std::string& out, uint8_t id, uint32_t v);
void put_prop_str(std::string& out, uint8_t id, std::string_view v);
void put_prop_pair(std::string& out, uint8_t id, std::string_view k, std::string_view v);

// ── Names ───────────────────────────────────────────────────────────────────

// Well-formed UTF-8 without U+0000, which every string of the protocol must be.
bool valid_utf8(std::string_view s);
// A topic a PUBLISH may name: no wildcard, not empty.
bool valid_topic(std::string_view t);
// A filter a SUBSCRIBE may name, a shared one ($share/<group>/<filter>) included.
bool valid_filter(std::string_view f);

// A shared subscription's group and the filter it shares, false when `f` is not one.
bool split_shared(std::string_view f, std::string_view& group, std::string_view& filter);

}   // namespace socketley::mqtt
