#pragma once
// A registered runtime type as the daemon learns it: a declarative manifest
// naming the type, the worker executable, and a schema of config keys -- read
// without executing anything, because the type's behaviour lives in the
// worker binary and never in this address space.
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "../shared/runtime_definitions.h"

class runtime_instance;
struct parsed_args;

namespace type_manifest
{

enum class key_kind : uint8_t { string_key, int_key, bool_key, enum_key };

struct schema_key
{
    std::string              name;
    key_kind                 kind{key_kind::string_key};
    bool                     required{false};
    bool                     has_default{false};
    std::string              default_value;
    std::vector<std::string> values;   // enum_key only
};

struct manifest
{
    std::string             type_name;
    std::string             exec;
    std::vector<schema_key> schema;
};

// Reads every *.toml in `dir` and registers each type it accepts, logging and
// skipping a file it refuses, so one bad manifest cannot keep the daemon down.
size_t load_dir(const std::filesystem::path& dir);

// The manifest for a registered id, nullptr for a built-in or unknown one;
// stable for the life of the process because manifests are loaded once.
const manifest* find(runtime_type t);

// The worker executable declared for `t`, empty for a built-in, which the
// supervisor reads as "exec myself".
std::string exec_path(runtime_type t);

// One `--<key>` flag against t's schema on the create and edit paths: 0 when
// consumed, 1 when refused with the reason printed, -1 when not a schema key.
int parse_registered_flag(runtime_instance* instance, const parsed_args& pa,
                          size_t& i);

// Asked once every flag has been seen, like the TLS set: names a missing
// required key, and fills declared defaults in on success.
std::string registered_create_refusal(runtime_instance* instance);

// A document's "extra" that replaces a registered runtime's fields whole and leaves out a required key with no
// default, which create refuses and an import therefore must too.
std::string missing_required_refusal(runtime_type t,
                                     const std::vector<std::pair<std::string, std::string>>& extra);

// The same schema check for a bag arriving as a document rather than as
// flags, so `import` refuses a misspelled key by name too.
std::string extra_refusal(runtime_type t,
                          const std::vector<std::pair<std::string, std::string>>& extra);

} // namespace type_manifest
