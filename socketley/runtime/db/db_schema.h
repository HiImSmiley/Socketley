#pragma once
// What the --schema file declares of each collection -- who may read and write it, and which fields are indexed --
// and the service keys the --keys file holds. Both are a line each, `#` starting a comment.
//
//   # collection  access   index...          (an index: a field, or unique:field; ttl:field for when one goes)
//   characters    owner    level unique:name
//   scores        public   score
//   sessions      owner    ttl:expires_at
//
// A collection the file does not name is private: only a key reaches it.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::db
{

// Who reaches a collection beside a key, which reaches every one.
enum class access : uint8_t
{
    priv,      // nobody else
    owner,     // a signed-in user, the documents they own
    shared,    // a signed-in user reads every document and writes the ones they own
    open,      // anybody reads; a signed-in user writes the ones they own
    catalog,   // anybody reads; only a key writes
};

const char* access_name(access a);

struct index_def
{
    std::string field;
    bool unique{false};
};

struct collection_def
{
    std::string name;
    access acc{access::priv};
    std::vector<index_def> indexes;
    // The field whose number, in seconds since 1970, is when a document of the collection goes; empty for never.
    std::string ttl;
};

struct schema
{
    std::vector<collection_def> collections;
    const collection_def* find(std::string_view name) const;
};

// A collection's name: 1 to 64 of a-z 0-9 _ -, a letter first.
bool valid_collection(std::string_view name);
// A document's id: 1 to 128 of A-Z a-z 0-9 . _ : @ + -, not `_` first, which the API's own paths take.
bool valid_id(std::string_view id);

bool parse_schema(std::string_view text, schema& out, std::string& why);

struct service_key
{
    std::string name;
    std::string secret;
};

// `name secret` a line; a secret is at least 16 characters, since it is the whole of what a key proves.
bool parse_keys(std::string_view text, std::vector<service_key>& out, std::string& why);

}   // namespace socketley::db
