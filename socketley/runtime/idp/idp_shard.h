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
    int64_t expires{0};
};

struct shard_call
{
    enum op_t : uint8_t
    {
        redeem = 1,   // the code `key`, taken from the shard that gave it
        update = 2,   // the account `key`'s `fields`, set by shard 0
        miss   = 3,   // a sign-in from `key` failed at `at`, told to every other shard
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

// An update's answer: done, or why not.
std::string encode_result(bool ok, std::string_view why);
bool decode_result(std::string_view in, bool& ok, std::string& why);

// The shard a code names, which gave it; false for a code of an unsharded provider or none of `shards`.
bool code_shard(std::string_view code, uint32_t shards, uint32_t& shard);

}   // namespace socketley::idp
