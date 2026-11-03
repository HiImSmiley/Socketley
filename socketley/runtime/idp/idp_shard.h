#pragma once
// A sharded idp: shard 0 writes the accounts and every shard reads its journal, so N cores sign in and verify while
// one keeps the record. A code is kept by the shard that gave it and named by it, so whichever shard the exchange
// reaches asks that one for it; the frames here are what the shards ask each other.
#include <cstdint>
#include <string>
#include <string_view>

#include "idp_accounts.h"

namespace socketley::idp
{

// What marks a request channel payload as one shard's question to another.
inline constexpr std::string_view cross_marker = "\x02skl-idp-shard\n";

// An authorization code, good once for a minute.
struct code_entry
{
    std::string client_id;
    std::string redirect;
    std::string sub;
    std::string nonce;
    std::string scope;
    std::string challenge;
    int64_t auth_time{0};
    // When the code was given, in milliseconds, for a sign-out everywhere since.
    int64_t issued_ms{0};
    int64_t expires{0};
    // The resource server its access token is for, empty for the client itself.
    std::string resource;
};

// A device grant (RFC 8628) waiting for its person, kept by the shard its user code names.
struct device_entry
{
    enum state_t : uint8_t
    {
        pending  = 0,
        approved = 1,
        denied   = 2,
    };
    std::string client_id;
    std::string scope;
    std::string user_code;
    std::string sub;
    state_t state{pending};
    int64_t auth_time{0};
    // When the person decided, in milliseconds, for a sign-out everywhere since.
    int64_t issued_ms{0};
    int64_t expires{0};
    // When the device may ask again without being told to slow down.
    int64_t next_poll{0};
    // The address, or the IPv6 site, that asked for it, whose grants waiting are counted.
    std::string from;
};

// What a poll of a device code comes to.
enum class device_poll : uint8_t
{
    pending   = 0,
    slow_down = 1,
    approved  = 2,
    denied    = 3,
    gone      = 4,
};

struct shard_call
{
    enum op_t : uint8_t
    {
        redeem        = 1,   // the code `key`, taken from the shard that gave it
        update        = 2,   // the account `key`'s `fields`, set by shard 0
        miss          = 3,   // a sign-in from `key` failed at `at`, told to every other shard
        device_decide = 4,   // the user code `key` allowed or refused (`fields` allow, sub) at `at`
        device_ask    = 5,   // the device code `key` polled by the client `fields` client_id at `at`
        device_peek   = 6,   // the grant the user code `key` names, if it still waits at `at`
        hold          = 7,   // an attempt at `key` begun at `at` at another shard, counted here while it is checked
        let_go        = 8,   // and checked, no longer counted
    };
    op_t op{redeem};
    std::string key;
    field_list fields;
    int64_t at{0};
};

std::string encode_call(const shard_call& c);
// False when it is not one.
bool decode_call(std::string_view in, shard_call& out);

// A redeem's answer: the code's entry, or none when it is not known, was used or has gone.
std::string encode_code(const code_entry* e);
bool decode_code(std::string_view in, bool& found, code_entry& out);

// A device poll's answer: what it came to, and for an approved grant the account, its scope and when it signed in;
// a peek's, pending with the client and scope of a grant still waiting.
std::string encode_device(device_poll what, const device_entry* e);
bool decode_device(std::string_view in, device_poll& what, device_entry& out);

// An update's answer: done, or why not.
std::string encode_result(bool ok, std::string_view why);
bool decode_result(std::string_view in, bool& ok, std::string& why);

// The shard a code names, which gave it; false for a code of an unsharded provider or none of `shards`.
bool code_shard(std::string_view code, uint32_t shards, uint32_t& shard);

}   // namespace socketley::idp
