// Fuzz target: `import`'s merge of a document into a runtime (socketley/daemon/import_apply.cpp and
// state_persistence::import_refusal), the path cmd_import and edit's rollback take, driven against a valid runtime.
//
// Reachable by whoever can reach the control socket (the operator, group socketley): no privilege boundary, so what is
// at stake is that the daemon, its state file and the next start agree on what a runtime is.
//
// An input is: one byte naming the runtime's type, the document the runtime is made from (as the daemon restores it
// from its state file), a NUL, and the document imported into it.
//
// What must hold, beside no report from the sanitizers:
//
//   * A document import_refusal() takes is applied whole: import_apply() does not refuse it half way.
//   * What the runtime then is reads back: its state file parses, and written again is the same file.
//   * A second load yields the same: a runtime restored from that file, as the next start restores it, is written as
//     the same file.
//   * Applying the same document again changes nothing.
//   * Every field the document names is what the runtime holds afterwards (`show` says what the import said).
//   * Putting a runtime's own fields back, as edit's rollback does, changes nothing.
//   * The document `show` prints for a runtime is one import takes.

#include <cctype>
#include <optional>
#include <string>
#include <string_view>

#include "fuzz_common.h"

#include "../../socketley/daemon/flag_handlers.h"
#include "../../socketley/daemon/import_apply.h"
#include "../../socketley/daemon/type_manifest.h"
#include "../../socketley/runtime/server/server_instance.h"
#include "../../socketley/shared/persist/state_persistence.h"
#include "../../socketley/shared/runtime/runtime_config_apply.h"
#include "../../socketley/shared/runtime/runtime_factory.h"
#include "../../socketley/shared/runtime/runtime_instance.h"

namespace
{

const state_persistence& sp()
{
    // An empty directory makes the object a parser and nothing else: no writer thread, no file.
    static const state_persistence p{std::filesystem::path{}};
    return p;
}

// The runtime the daemon restores from a state file: the same calls daemon.cpp's restore makes, without the script.
std::unique_ptr<runtime_instance> restored(runtime_type type, const runtime_config& cfg)
{
    auto rt = create_runtime(type, "fz");
    if (!rt)
        return nullptr;
    rt->set_id("f00d01");
    apply_common_config(*rt, cfg);
    if (cfg.reconnect >= 0)
        rt->set_reconnect(cfg.reconnect);
    apply_typed_config(*rt, cfg);
    return rt;
}

std::string state_of(const runtime_instance& rt)
{
    return sp().format_json_pretty(sp().read_from_instance(&rt));
}

void differ(const char* a_label, const std::string& a, const char* b_label, const std::string& b)
{
    size_t at = 0;
    while (at < a.size() && at < b.size() && a[at] == b[at])
        ++at;
    const size_t from = at > 80 ? at - 80 : 0;
    fuzz::dump(a_label, reinterpret_cast<const uint8_t*>(a.data()) + from, std::min<size_t>(a.size() - from, 240));
    fuzz::dump(b_label, reinterpret_cast<const uint8_t*>(b.data()) + from, std::min<size_t>(b.size() - from, 240));
}

// What cmd_import judges before it applies anything, besides import_refusal(): a type's extra fields, the ACME names
// and a server's upstreams.
bool cmd_import_would_refuse(runtime_type type, const runtime_config& cfg)
{
    if (!type_manifest::extra_refusal(type, cfg.extra).empty())
        return true;
    if (cfg.has("acme_domains") && !cfg.acme_domains.empty() && !acme_refusal(type, cfg.acme_domains, false).empty())
        return true;
    if (cfg.has("acme_email") && !cfg.acme_email.empty() && !acme_refusal(type, cfg.acme_email, true).empty())
        return true;
    if (type == runtime_server && cfg.has("upstreams"))
        for (const auto& u : cfg.upstreams)
            if (!server_instance::upstream_ok(u))
                return true;
    return false;
}

// Keys an import names that are not settings it applies: the runtime's identity, the daemon's own bookkeeping, and
// what cmd_import itself handles (the name, the script).
bool not_applied(std::string_view key)
{
    for (const std::string_view k : {"name", "id", "type", "was_running", "owner", "child_policy", "shard_index",
                                     "mesh_wired", "companion_path", "cpus", "external_runtime", "managed",
                                     "exec_path", "pid", "lua_script", "master_forward", "master_pw"})
        if (key == k)
            return true;
    return false;
}

// A field's value as format_json_pretty() writes it, one field a line, the whole of an array; empty when not written.
std::string written_value(const std::string& doc, std::string_view key)
{
    const std::string head = "\n    \"" + std::string(key) + "\": ";
    const size_t at = doc.find(head);
    if (at == std::string::npos)
        return {};
    const size_t from = at + head.size();
    size_t end = doc.find('\n', from);
    if (end == std::string::npos)
        end = doc.size();
    std::string v = doc.substr(from, end - from);
    if (!v.empty() && v.back() == ',')
        v.pop_back();
    return v;
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 2 || size > (64u << 10))
        return 0;
    const auto type = static_cast<runtime_type>(data[0] % 15);
    const std::string_view rest(reinterpret_cast<const char*>(data) + 1, size - 1);
    const size_t nul = rest.find('\0');
    if (nul == std::string_view::npos)
        return 0;
    const std::string base_doc(rest.substr(0, nul));
    const std::string doc(rest.substr(nul + 1));

    runtime_config base;
    if (!sp().parse_json_string(base_doc, base, type))
        base.name = "fz";
    auto rt = restored(type, base);
    if (!rt)
        return 0;

    // What `show` prints for any runtime is a document import takes.
    const std::string before = state_of(*rt);
    {
        const std::string why = sp().import_refusal(before, type);
        if (!why.empty())
        {
            fuzz::dump("show", reinterpret_cast<const uint8_t*>(before.data()), before.size());
            fuzz::dump("refusal", reinterpret_cast<const uint8_t*>(why.data()), why.size());
        }
        FUZZ_CHECK(why.empty(), "import refuses the document show printed for the runtime");
    }

    // Edit's rollback: the runtime's own fields put back over it change nothing.
    {
        runtime_config own, scratch;
        FUZZ_CHECK(sp().parse_json_string(before, own, type), "the state of a runtime does not read back");
        runtime_config back = sp().read_from_instance(rt.get());
        back.present = own.present;
        for (const char* fixed : {"name", "id", "type", "was_running"})
            back.present.erase(fixed);
        std::string why;
        FUZZ_CHECK(import_apply(*rt, back, why, /*restore=*/true), "putting a runtime's own fields back over it was refused");
        const std::string again = state_of(*rt);
        if (again != before)
            differ("before", before, "its own fields put back", again);
        FUZZ_CHECK(again == before, "putting a runtime's own fields back over it changed it");
    }

    // The import: judged, then applied whole.  cmd_import takes an object and nothing else ("invalid JSON").
    {
        std::string_view d = doc;
        while (!d.empty() && std::isspace(static_cast<unsigned char>(d.front()))) d.remove_prefix(1);
        while (!d.empty() && std::isspace(static_cast<unsigned char>(d.back()))) d.remove_suffix(1);
        if (!d.starts_with('{') || !d.ends_with('}'))
            return 0;
    }
    runtime_config cfg;
    const bool named = sp().parse_json_string(doc, cfg, type);
    if (!named && cfg.has("name"))
        return 0;
    if (!sp().import_refusal(doc, type).empty() || cmd_import_would_refuse(type, cfg))
        return 0;
    std::string why;
    FUZZ_CHECK(import_apply(*rt, cfg, why), "a document import judged good was refused half way through its apply");
    const std::string after = state_of(*rt);

    // It reads back, and is written the same.
    runtime_config read_back;
    FUZZ_CHECK(sp().parse_json_string(after, read_back, type), "the state file after an import does not read back");
    FUZZ_CHECK(sp().format_json_pretty(read_back) == after, "the state file after an import is not written as read");

    // The next start makes the same runtime of it.
    {
        auto again = restored(type, read_back);
        FUZZ_CHECK(again != nullptr, "the type made a runtime once and not twice");
        const std::string reloaded = state_of(*again);
        if (reloaded != after)
            differ("after the import", after, "restored from that state", reloaded);
        FUZZ_CHECK(reloaded == after, "a runtime restored from its state file is not the runtime that wrote it");
    }

    // The same import again changes nothing.
    {
        FUZZ_CHECK(import_apply(*rt, cfg, why), "a document applied once was refused the second time");
        const std::string twice = state_of(*rt);
        if (twice != after)
            differ("imported once", after, "imported twice", twice);
        FUZZ_CHECK(twice == after, "importing the same document twice is not importing it once");
    }

    // Every field the document names is the runtime's afterwards, as it says it.
    {
        const std::string said = sp().format_json_pretty(cfg);
        const bool acme = cfg.has("acme_domains") && !cfg.acme_domains.empty();
        for (const auto& key : cfg.present)
        {
            if (not_applied(key))
                continue;
            // A certificate's names point TLS at the files the certificate is kept in, whatever the document says.
            if (acme && (key == "tls" || key == "cert_path" || key == "key_path"))
                continue;
            std::string want = written_value(said, key);
            const std::string got = written_value(after, key);
            // The certificate's names are a list, kept without its empty items.
            if (key == "acme_domains" && want.size() >= 2)
            {
                std::string items;
                for (std::string_view l = std::string_view(want).substr(1, want.size() - 2); !l.empty();)
                {
                    const size_t comma = l.find(',');
                    const std::string_view one = l.substr(0, comma);
                    if (!one.empty())
                        items += (items.empty() ? "" : ",") + std::string(one);
                    l = comma == std::string_view::npos ? std::string_view{} : l.substr(comma + 1);
                }
                want = "\"" + items + "\"";
            }
            // A web runtime's one backend, empty, is none.
            if (type == runtime_web && key == "backends" && want == "[\"\"]")
                want.clear();
            if (want != got)
            {
                fuzz::dump("field", reinterpret_cast<const uint8_t*>(key.data()), key.size());
                fuzz::dump("the document said", reinterpret_cast<const uint8_t*>(want.data()), want.size());
                fuzz::dump("the runtime holds", reinterpret_cast<const uint8_t*>(got.data()), got.size());
            }
            FUZZ_CHECK(want == got, "a field an import named is not what the runtime holds afterwards");
        }
    }
    return 0;
}
