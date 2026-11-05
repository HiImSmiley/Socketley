#include "type_manifest.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>

#include "../cli/arg_parser.h"
#include "../shared/util/logging.h"
#include "../shared/util/text_list.h"
#include "../shared/runtime/runtime_instance.h"
#include "../shared/runtime/type_registry.h"

namespace fs = std::filesystem;

namespace
{

using extra_bag = std::vector<std::pair<std::string, std::string>>;

// The daemon's stand-in for a registered type, modelled on runtime_manager's
// replica_instance: the base class plus the bag of fields the manifest
// declared, because the behaviour lives in the worker binary.
class registered_instance final : public runtime_instance
{
public:
    registered_instance(runtime_type type, std::string_view name)
        : runtime_instance(type, name)
    {
    }

    void on_cqe(struct io_uring_cqe*) override {}
    bool setup(event_loop&) override { return false; }
    void teardown(event_loop&) override {}

    void capture_config(extra_bag& out) const override { out = m_extra; }
    void apply_config(const extra_bag& in) override { m_extra = in; }

    void set_field(std::string_view key, std::string_view value)
    {
        for (auto& [k, v] : m_extra)
        {
            if (k == key)
            {
                v = std::string(value);
                return;
            }
        }
        m_extra.emplace_back(std::string(key), std::string(value));
    }

    bool has_field(std::string_view key) const
    {
        for (const auto& [k, v] : m_extra)
            if (k == key)
                return true;
        return false;
    }

private:
    extra_bag m_extra;
};

// The names a schema key may not take: every key the state writer can emit,
// plus every flag spelling the common parsers consume first -- because a
// shadowed key would be parsed as something else and never refused.
constexpr std::string_view reserved_keys[] = {
    "name", "id", "type", "port", "listen", "was_running", "log_file",
    "write_file", "lua_script", "bash_output", "bash_prefix", "bash_timestamp",
    "max_connections", "rate_limit", "global_rate_limit", "idle_timeout", "congestion",
    "write_buffer", "write-buffer", "read_buffer", "read-buffer",
    "drain", "reconnect", "tls", "cert_path", "key_path", "ca_path", "target",
    "cache_name", "group", "owner", "child_policy", "shards", "shard_index",
    "cpus", "external_runtime", "managed", "exec_path", "pid",
    "mode", "send_to", "udp", "master_pw", "http_dir", "http_cache", "no_inject",
    "upstreams", "protocol", "strategy", "backends", "health_check",
    "health_interval", "health_path", "health_threshold", "circuit_threshold", "root", "fastcgi_root", "index", "fallback", "compress",
    "circuit_timeout", "backend_timeout", "retry_count", "retry_all",
    "mesh_client_ca", "mesh_client_cert", "mesh_client_key", "auth", "redirect_https", "persistent_path",
    "persistent_interval",
    "cache_mode", "resp_forced", "cluster", "no_cluster", "replicate_target", "cluster_replica", "max_memory",
    "eviction", "extra",
    "ca", "cert", "key", "global-rate-limit", "idle-timeout", "log", "lua",
    "max-conn", "max-connections", "rate-limit", "test",
    "write", "http", "cache", "retry", "client_ca", "client_cert",
    "client_key", "sidecar", "persistent", "maxmemory", "resp", "replicate",
    "config", "bash", "start", "daemon_process",
    "domain", "bind", "acme", "acme-email", "acme_email", "acme_domains", "upstream", "master-pw", "send-to",
    "http-cache", "tls_offloaded", "mesh_wired", "companion_path",
};

bool is_reserved(std::string_view key)
{
    for (std::string_view r : reserved_keys)
        if (r == key)
            return true;
    return false;
}

bool valid_key_name(std::string_view key)
{
    if (key.empty() || key.size() > 64 || key[0] == '-')
        return false;
    for (char c : key)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    return true;
}

// Whether `v` is a value the key's kind accepts, as the one sentence a
// refusal prints, asked by the flag parser, the create gate and `import`.
std::string value_refusal(const type_manifest::schema_key& k, std::string_view v)
{
    switch (k.kind)
    {
        case type_manifest::key_kind::string_key:
            return {};

        case type_manifest::key_kind::int_key:
        {
            long long n = 0;
            const char* first = v.data();
            const char* last  = v.data() + v.size();
            auto [p, ec] = std::from_chars(first, last, n);
            if (ec != std::errc{} || p != last)
                return "--" + k.name + " takes an integer, not \"" +
                       std::string(v) + "\"\n";
            return {};
        }

        case type_manifest::key_kind::bool_key:
            if (v != "true" && v != "false")
                return "--" + k.name + " takes true or false, not \"" +
                       std::string(v) + "\"\n";
            return {};

        case type_manifest::key_kind::enum_key:
        {
            for (const auto& allowed : k.values)
                if (allowed == v)
                    return {};
            std::string msg = "--" + k.name + " must be one of";
            for (const auto& allowed : k.values)
                msg += " " + allowed;
            msg += ", not \"" + std::string(v) + "\"\n";
            return msg;
        }
    }
    return {};
}

// ── Storage ─────────────────────────────────────────────────────────────────
// Keyed by the process-local id and loaded once at startup, so find() may
// hand out pointers.

std::map<uint8_t, type_manifest::manifest>& manifests()
{
    static std::map<uint8_t, type_manifest::manifest> m;
    return m;
}

std::shared_mutex& manifest_mutex()
{
    static std::shared_mutex m;
    return m;
}

// ── The manifest file ───────────────────────────────────────────────────────
// A TOML subset read line by line -- assignments, [config.<key>] sections,
// quoted strings, integers, booleans and string arrays -- refusing anything it
// does not know by name, which is the same rule the flags follow.

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// A scalar: the quoted body, or the bare token for integers and booleans.
bool scalar_value(std::string_view raw, std::string& out)
{
    raw = trim(raw);
    if (raw.empty())
        return false;
    if (raw.front() == '"')
    {
        if (raw.size() < 2 || raw.back() != '"')
            return false;
        raw = raw.substr(1, raw.size() - 2);
        if (raw.find('"') != std::string_view::npos)
            return false;
        out = std::string(raw);
        return true;
    }
    if (raw.find(' ') != std::string_view::npos ||
        raw.find('\t') != std::string_view::npos)
        return false;
    out = std::string(raw);
    return true;
}

bool array_value(std::string_view raw, std::vector<std::string>& out)
{
    raw = trim(raw);
    if (raw.size() < 2 || raw.front() != '[' || raw.back() != ']')
        return false;
    raw = raw.substr(1, raw.size() - 2);
    out.clear();

    while (true)
    {
        raw = trim(raw);
        if (raw.empty())
            return !out.empty();
        std::string  item;
        if (!scalar_value(socketley::take_item(raw), item))
            return false;
        out.push_back(std::move(item));
    }
}

// One manifest file into `m`, with the refusal naming the line and the key,
// because a manifest is edited by hand and "invalid" locates nothing.
std::string parse_manifest_file(const fs::path& path, type_manifest::manifest& m)
{
    std::ifstream in(path);
    if (!in)
        return "could not be read";

    bool        have_version = false;
    long long   version      = 0;
    bool        in_section   = false;
    type_manifest::schema_key section;

    // Section keys are validated when the next section or the file ends,
    // because `kind` may be declared after `default`.
    auto commit_section = [&]() -> std::string {
        if (!in_section)
            return {};
        if (section.kind == type_manifest::key_kind::enum_key && section.values.empty())
            return "config." + section.name + " is an enum with no values";
        if (section.kind != type_manifest::key_kind::enum_key && !section.values.empty())
            return "config." + section.name + " has values but is not an enum";
        if (section.required && section.has_default)
            return "config." + section.name + " is required and has a default, "
                   "which contradict";
        if (section.has_default)
            if (const std::string why = value_refusal(section, section.default_value);
                !why.empty())
                return "config." + section.name + "'s default does not fit its kind";
        m.schema.push_back(std::move(section));
        section = {};
        in_section = false;
        return {};
    };

    std::string line_s;
    int         lineno = 0;
    while (std::getline(in, line_s))
    {
        ++lineno;
        std::string_view line = trim(line_s);
        if (line.empty() || line.front() == '#')
            continue;

        const std::string at = " (line " + std::to_string(lineno) + ")";

        if (line.front() == '[')
        {
            if (const std::string why = commit_section(); !why.empty())
                return why;
            if (line.back() != ']')
                return "unterminated section header" + at;
            std::string_view header = trim(line.substr(1, line.size() - 2));
            if (header.rfind("config.", 0) != 0)
                return "unknown section [" + std::string(header) + "]" + at;
            std::string_view key = header.substr(7);
            if (!valid_key_name(key))
                return "\"" + std::string(key) + "\" is not a usable key name" + at;
            if (is_reserved(key))
                return "\"" + std::string(key) + "\" is reserved: a built-in "
                       "flag or state field already has that name" + at;
            for (const auto& sk : m.schema)
                if (sk.name == key)
                    return "config." + std::string(key) + " is declared twice" + at;
            section      = {};
            section.name = std::string(key);
            in_section   = true;
            continue;
        }

        const size_t eq = line.find('=');
        if (eq == std::string_view::npos)
            return "not an assignment: \"" + std::string(line) + "\"" + at;
        const std::string_view key = trim(line.substr(0, eq));
        const std::string_view raw = trim(line.substr(eq + 1));

        if (!in_section)
        {
            std::string v;
            if (key == "name")
            {
                if (!scalar_value(raw, m.type_name))
                    return "name takes a quoted string" + at;
            }
            else if (key == "exec")
            {
                if (!scalar_value(raw, m.exec))
                    return "exec takes a quoted string" + at;
            }
            else if (key == "manifest_version")
            {
                if (!scalar_value(raw, v))
                    return "manifest_version takes an integer" + at;
                auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), version);
                if (ec != std::errc{} || p != v.data() + v.size())
                    return "manifest_version takes an integer" + at;
                have_version = true;
            }
            else
            {
                return "unknown key \"" + std::string(key) + "\"" + at;
            }
            continue;
        }

        std::string v;
        if (key == "kind")
        {
            if (!scalar_value(raw, v))
                return "kind takes a quoted string" + at;
            if (v == "string")    section.kind = type_manifest::key_kind::string_key;
            else if (v == "int")  section.kind = type_manifest::key_kind::int_key;
            else if (v == "bool") section.kind = type_manifest::key_kind::bool_key;
            else if (v == "enum") section.kind = type_manifest::key_kind::enum_key;
            else return "kind must be string, int, bool or enum, not \"" + v + "\"" + at;
        }
        else if (key == "required")
        {
            if (!scalar_value(raw, v) || (v != "true" && v != "false"))
                return "required takes true or false" + at;
            section.required = (v == "true");
        }
        else if (key == "default")
        {
            if (!scalar_value(raw, section.default_value))
                return "default takes a scalar" + at;
            section.has_default = true;
        }
        else if (key == "values")
        {
            if (!array_value(raw, section.values))
                return "values takes an array of quoted strings" + at;
        }
        else
        {
            return "unknown key \"" + std::string(key) + "\" in config." +
                   section.name + at;
        }
    }

    if (const std::string why = commit_section(); !why.empty())
        return why;

    if (m.type_name.empty())
        return "no name";
    if (m.exec.empty())
        return "no exec";
    if (m.exec.front() != '/')
        return "exec must be an absolute path";
    if (!have_version)
        return "no manifest_version";
    if (version != 1)
        return "manifest_version " + std::to_string(version) +
               " is not one this build reads";

    return {};
}

const type_manifest::manifest* find_locked(runtime_type t)
{
    auto& m  = manifests();
    auto  it = m.find(static_cast<uint8_t>(t));
    return it == m.end() ? nullptr : &it->second;
}

} // namespace

namespace type_manifest
{

size_t load_dir(const fs::path& dir)
{
    std::error_code ec;
    if (!fs::is_directory(dir, ec))
        return 0;

    // Sorted so two daemons over one directory assign ids in one order --
    // a courtesy only, since no id ever leaves the process.
    std::vector<fs::path> files;
    for (const auto& e : fs::directory_iterator(dir, ec))
        if (e.path().extension() == ".toml")
            files.push_back(e.path());
    std::sort(files.begin(), files.end());

    size_t loaded = 0;
    for (const auto& path : files)
    {
        manifest m;
        if (const std::string why = parse_manifest_file(path, m); !why.empty())
        {
            LOG_WARN(("type manifest " + path.string() + " refused: " + why).c_str());
            continue;
        }

        runtime_type id;
        const std::string tn = m.type_name;

        // adopt() rather than register_type(), because the daemon may be the
        // same binary that registered this type for its worker role: the
        // daemon holds a placeholder and must build registered_instance, or
        // `show` reports whatever base the caller's class derives from.  The
        // worker's own registry is a different process and keeps its factory.
        if (!type_registry::adopt(
                tn,
                [tn](std::string_view name) -> std::unique_ptr<runtime_instance>
                {
                    runtime_type t;
                    if (!type_registry::lookup(tn, t))
                        return nullptr;
                    return std::make_unique<registered_instance>(t, name);
                },
                id))
        {
            LOG_WARN(("type manifest " + path.string() + " refused: \"" + tn +
                      "\" is a built-in type name, is not a valid type name, or finds no free type id").c_str());
            continue;
        }

        // Two manifests for one name is still two answers to one question.
        {
            std::shared_lock lock(manifest_mutex());
            if (manifests().count(static_cast<uint8_t>(id)))
            {
                LOG_WARN(("type manifest " + path.string() + " refused: \"" +
                          tn + "\" is already declared").c_str());
                continue;
            }
        }

        {
            std::unique_lock lock(manifest_mutex());
            manifests().emplace(static_cast<uint8_t>(id), std::move(m));
        }
        ++loaded;
    }
    return loaded;
}

const manifest* find(runtime_type t)
{
    std::shared_lock lock(manifest_mutex());
    return find_locked(t);
}

std::string exec_path(runtime_type t)
{
    std::shared_lock lock(manifest_mutex());
    const manifest* m = find_locked(t);
    return m ? m->exec : std::string{};
}

int parse_registered_flag(runtime_instance* instance, const parsed_args& pa,
                          size_t& i)
{
    const manifest* m = find(instance->get_type());
    if (!m)
        return -1;

    const std::string_view arg = pa.args[i];
    if (arg.size() < 3 || arg.substr(0, 2) != "--")
        return -1;
    const std::string_view key = arg.substr(2);

    for (const auto& sk : m->schema)
    {
        if (sk.name != key)
            continue;

        // Every instance carrying a registered id was built by this file's
        // factory, which is what makes the cast the truth.
        auto* inst = static_cast<registered_instance*>(instance);

        // A bool key is a plain flag, with an explicit true or false consumed
        // when the operator spelled one.
        if (sk.kind == key_kind::bool_key)
        {
            std::string_view v = "true";
            if (i + 1 < pa.count &&
                (pa.args[i + 1] == "true" || pa.args[i + 1] == "false"))
                v = pa.args[++i];
            inst->set_field(sk.name, v);
            return 0;
        }

        if (i + 1 >= pa.count)
        {
            std::cout << "--" << sk.name << " requires a value\n";
            return 1;
        }
        const std::string_view v = pa.args[++i];
        if (const std::string why = value_refusal(sk, v); !why.empty())
        {
            std::cout << why;
            return 1;
        }
        inst->set_field(sk.name, v);
        return 0;
    }

    return -1;
}

std::string registered_create_refusal(runtime_instance* instance)
{
    const manifest* m = find(instance->get_type());
    if (!m)
        return {};

    auto* inst = static_cast<registered_instance*>(instance);
    for (const auto& sk : m->schema)
    {
        if (inst->has_field(sk.name))
            continue;
        if (sk.required)
            return "--" + sk.name + " is required for a " + m->type_name + "\n";
        if (sk.has_default)
            inst->set_field(sk.name, sk.default_value);
    }
    return {};
}

std::string missing_required_refusal(runtime_type t,
                                     const std::vector<std::pair<std::string, std::string>>& extra)
{
    const manifest* m = find(t);
    if (!m)
        return {};
    for (const auto& sk : m->schema)
        if (sk.required && !sk.has_default &&
            std::none_of(extra.begin(), extra.end(), [&](const auto& kv) { return kv.first == sk.name; }))
            return "\"extra\" leaves out " + sk.name + ", which a " + m->type_name + " requires\n";
    return {};
}

std::string extra_refusal(runtime_type t,
                          const std::vector<std::pair<std::string, std::string>>& extra)
{
    const manifest* m = find(t);
    if (!m)
    {
        if (extra.empty())
            return {};
        return "\"extra\": a " + std::string(type_to_string(t)) +
               " has no manifest and no extra fields\n";
    }

    for (const auto& [k, v] : extra)
    {
        const schema_key* found = nullptr;
        for (const auto& sk : m->schema)
            if (sk.name == k)
            {
                found = &sk;
                break;
            }
        if (!found)
            return "\"" + k + "\" is not a key " + m->type_name +
                   "'s manifest declares\n";
        if (const std::string why = value_refusal(*found, v); !why.empty())
            return why;
    }
    return {};
}

} // namespace type_manifest
