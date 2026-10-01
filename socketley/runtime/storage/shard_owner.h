#pragma once
// Which shard of a sharded storage runtime owns an object, by a rule clients can compute.
//
// The slot is CRC16/XMODEM of "bucket/key" masked to 16384 slots, exactly the
// function a cache uses for its keys, and the owner of a slot is
// slot * shards / 16384, so the slot does not move when the shard count does.
#include <cstdint>
#include <string_view>

#include "../../shared/cache_shard_map.h"

namespace socketley::storage
{

// A bucket name cannot contain '/', so the joined string is unambiguous.
inline uint32_t object_slot(std::string_view bucket, std::string_view key)
{
    return cache_crc16_update(cache_crc16_update(cache_crc16_update(0, bucket), "/"), key) & (cache_slot_count - 1);
}

inline uint32_t object_owner(std::string_view bucket, std::string_view key, uint32_t shards)
{
    return cache_shard_of_slot(object_slot(bucket, key), shards);
}

}   // namespace socketley::storage
