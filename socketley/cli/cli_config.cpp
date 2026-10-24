#include "cli.h"
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sol/sol.hpp>

#include "runtime_type_parser.h"
#include "../daemon/ipc_client.h"
#include "../daemon/lua_setup.h"
#include "../daemon/type_manifest.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/json/json_doc.h"
#include "../shared/persist/paths.h"
#include "../shared/util/settings.h"

namespace {

using socketley::json::jvalue;

// A daemon setting the daemon reads at startup and cannot be told afterwards,
// refused by name rather than dropped, because a file that sets a log level
// nothing applies reads as if it did.
std::string refuse_startup_only_daemon_keys(const sol::table& daemon)
{
    for (std::string_view key : { "log_level", "metrics_port", "cpus" })
    {
        if (!daemon[key].valid())
            continue;

        return std::string(key) + " is read when the daemon starts and cannot be "
               "set on a running one: put it in the daemon's own configuration "
               "file and point SOCKETLEY_CONFIG at it\n";
    }

    return {};
}

// The file the daemon reads its own settings from, as it finds it.
std::string daemon_config_path()
{
    const char* env = socketley::settings::text("SOCKETLEY_CONFIG");
    return env && env[0] ? std::string(env) : socketley_paths::resolve().config_path.string();
}

bool same_file(const std::string& a, const std::string& b)
{
    std::error_code ec1, ec2;
    return std::filesystem::equivalent(a, b, ec1) && !ec1 && !ec2;
}

// A command's words as the daemon's line, each quoted where it has to be.
std::string line_of(const std::vector<std::string>& words, size_t from = 0)
{
    std::string line;
    for (size_t i = from; i < words.size(); ++i)
    {
        if (!line.empty())
            line += ' ';
        ipc_frame::append_arg(line, words[i]);
    }
    return line;
}

bool parse(const std::string& text, jvalue& out)
{
    std::string_view v = text;
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
        v.remove_suffix(1);
    return socketley::json::json_reader(v).document(out) && out.k == jvalue::kind::object;
}

std::string compact(const jvalue& v)
{
    std::string out;
    socketley::json::write_into(out, v);
    return out;
}

// The settings in which two states of a runtime differ, what is volatile aside, each with what `want` says of it --
// nothing, as zero of its kind, where it says nothing.
jvalue differences(const jvalue& want, const jvalue& have)
{
    jvalue doc;
    doc.k = jvalue::kind::object;
    for (const auto& [k, v] : want.members)
    {
        if (lua_setup::volatile_key(k))
            continue;
        const jvalue* h = socketley::json::member(have, k);
        if (!h || compact(*h) != compact(v))
            doc.members.emplace_back(k, v);
    }
    for (const auto& [k, v] : have.members)
    {
        if (lua_setup::volatile_key(k) || socketley::json::member(want, k))
            continue;
        jvalue zero;
        zero.k = v.k;
        if (v.k == jvalue::kind::number)
            zero.s = "0";
        if (zero.k == jvalue::kind::object || zero.k == jvalue::kind::null)
            continue;
        if (compact(zero) != compact(v))
            doc.members.emplace_back(k, std::move(zero));
    }
    return doc;
}

// The daemon's answer to one command; false, said under the runtime's name, where it refused.
bool ask(const std::string& name, const std::string& line, std::string& out, int& failure,
         const char* what = "create")
{
    const int rc = ipc_send(line, out);
    if (rc < 0)
    {
        failure = ipc_report_failure(rc);
        return false;
    }
    if (rc == 0)
        return true;
    std::cerr << "could not " << what << " " << name << ":\n";
    if (out.empty())
        std::cerr << "  the daemon refused it and said nothing (exit " << rc << ")\n";
    std::istringstream lines(out);
    for (std::string l; std::getline(lines, l);)
        std::cerr << "  " << l << "\n";
    return false;
}

} // namespace

// `socketley --lua <file>`: the daemon brought to what the file says -- each runtime made where it is missing, changed
// where it differs, left alone where it is as said, and started or stopped as its `start` says.
int cli_config(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: socketley --lua <lua path>\n";
        return 1;
    }

    // Registered types before any entry is read, because parse_runtime_type
    // resolves through the registry these fill.
    type_manifest::load_dir(socketley_paths::resolve().types_dir);

    std::error_code ec;
    const std::string top = std::filesystem::absolute(argv[2], ec).string();
    sol::state lua;
    lua_setup::open(lua, top);

    sol::load_result script = lua.load_file(top);

    if (!script.valid())
    {
        sol::error err = script;
        std::cerr << "failed to load config: " << err.what() << "\n";
        return 1;
    }

    // Deliberately not bounded by lua_deadline, because this chunk runs in the
    // CLI process, holds nothing anybody is waiting on, and can be ended with
    // a keystroke.
    sol::protected_function_result result = script();

    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "error executing config: " << err.what() << "\n";
        return 1;
    }

    // Apply daemon settings (name, cluster) before runtimes
    sol::optional<sol::table> daemon = lua["daemon"].get<sol::optional<sol::table>>();
    if (daemon)
    {
        // The daemon's own file says them for its next start, so they are no mistake in it.
        if (std::string why = refuse_startup_only_daemon_keys(*daemon); !why.empty() && !same_file(top, daemon_config_path()))
        {
            std::cerr << why;
            return 1;
        }

        for (const char* key : {"name", "cluster"})
        {
            sol::optional<std::string> v = (*daemon)[key].get<sol::optional<std::string>>();
            if (!v || v->empty())
                continue;
            std::string response;
            std::string line = std::string("daemon-") + key + " ";
            ipc_frame::append_arg(line, *v);
            int rc = ipc_send(line, response);
            if (rc < 0) { return ipc_report_failure(rc); }
            if (rc != 0) { if (!response.empty()) std::cerr << response; return rc; }
        }
    }

    std::string why;
    std::vector<lua_setup::runtime_entry> entries = lua_setup::runtimes(lua, top, why);
    if (!why.empty())
    {
        std::cerr << why;
        return 1;
    }

    // The daemon's exit code and sentence are read rather than only whether
    // the socket answered, because a config file whose every runtime failed
    // reported success and printed nothing -- collected rather than returned
    // at the first failure.
    int failed = 0;

    for (lua_setup::runtime_entry& e : entries)
    {
        if (!e.refused.empty())
        {
            std::cerr << "could not create " << (e.name.empty() ? std::string("an entry") : e.name) << ":\n  " << e.refused;
            ++failed;
            continue;
        }

        // What create would keep, the flags judged as create judges them.
        int failure = 0;
        std::vector<std::string> plan_words = e.create;
        plan_words[0] = "plan";
        std::string planned, shown;
        if (!ask(e.name, line_of(plan_words), planned, failure))
        {
            if (failure)
                return failure;
            ++failed;
            continue;
        }

        std::string show_line = "show ";
        ipc_frame::append_arg(show_line, e.name);
        const int src = ipc_send(show_line, shown);
        if (src < 0)
            return ipc_report_failure(src);

        jvalue want, have;
        if (src != 0)
        {
            // Missing: made as the file says, and started where it says so.
            std::vector<std::string> words = e.create;
            if (e.start == 1)
                words.emplace_back("-s");
            std::string response;
            if (!ask(e.name, line_of(words), response, failure))
            {
                if (failure)
                    return failure;
                ++failed;
                continue;
            }
            // Success is silent, but a create that printed something while succeeding has something to say.
            if (!response.empty())
                std::cout << response;
            continue;
        }

        if (!parse(planned, want) || !parse(shown, have))
        {
            std::cerr << "could not create " << e.name << ":\n  the daemon's account of it was not JSON\n";
            ++failed;
            continue;
        }

        if (socketley::json::string_of(have, "type") != socketley::json::string_of(want, "type"))
        {
            std::cerr << "could not create " << e.name << ":\n  a runtime of that name is a "
                      << socketley::json::string_of(have, "type") << ", and the file says " << e.type << "\n";
            ++failed;
            continue;
        }

        const jvalue changes = differences(want, have);
        const bool running = [&] {
            const jvalue* r = socketley::json::member(have, "was_running");
            return r && r->k == jvalue::kind::boolean && r->b;
        }();
        if (!changes.members.empty())
        {
            // Across a restart where it runs, so what it reads at its start is read again.
            std::string line = "import ";
            ipc_frame::append_arg(line, e.name);
            if (running)
                line += " --restart";
            line += ' ' + compact(changes);
            std::string response;
            if (!ask(e.name, line, response, failure, "change"))
            {
                if (failure)
                    return failure;
                ++failed;
                continue;
            }
            // Asked again, since a document the runtime takes in part is a setup half made.
            std::string again;
            jvalue now;
            if (ipc_send(show_line, again) == 0 && parse(again, now))
                if (const jvalue left = differences(want, now); !left.members.empty())
                {
                    std::cerr << "could not change " << e.name << ":\n  it does not take what the file says of";
                    for (const auto& [k, v] : left.members)
                        std::cerr << " " << k;
                    std::cerr << "\n";
                    ++failed;
                    continue;
                }
        }

        if (e.start != -1 && (e.start == 1) != running)
        {
            std::string line = e.start == 1 ? "start " : "stop ";
            ipc_frame::append_arg(line, e.name);
            std::string response;
            if (!ask(e.name, line, response, failure, e.start == 1 ? "start" : "stop"))
            {
                if (failure)
                    return failure;
                ++failed;
            }
        }
    }

    if (failed > 0)
    {
        std::cerr << failed << " of " << entries.size()
                  << " runtimes in this configuration were not created\n";
        return 1;
    }

    return 0;
}

namespace
{

// A dns runtime's zone kept by name is a file of the state directory's, and one given by path is that file.
std::filesystem::path zone_file(const std::string& entry)
{
    if (entry.find('/') != std::string::npos)
        return entry;
    std::string n = entry;
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!n.empty() && n.back() == '.')
        n.pop_back();
    return socketley_paths::resolve().state_dir / "zones" / (n + ".zone");
}

bool copy_into(const std::filesystem::path& from, const std::filesystem::path& to, std::string& why)
{
    std::error_code ec;
    std::filesystem::create_directories(to.parent_path(), ec);
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec)
        why = from.string() + " could not be copied to " + to.string() + ": " + ec.message();
    return !ec;
}

// The order a setup makes runtimes in, a runtime before those that name it: names first, then accounts, storage and
// data, then what serves and routes, then what reads them.
int rank(std::string_view type)
{
    static constexpr std::string_view order[] = {"dns", "idp", "storage", "db", "cache", "mqtt", "server",
                                                 "client", "proxy", "mail", "sync"};
    const auto at = std::find(std::begin(order), std::end(order), type);
    return static_cast<int>(at - std::begin(order));
}

// The daemon's own settings, as its file says them, for the setup to say them as well.
std::string daemon_table()
{
    const std::string path = daemon_config_path();
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return {};
    sol::state lua;
    lua_setup::open(lua, path);
    if (!lua.safe_script_file(path, sol::script_pass_on_error).valid())
        return {};
    sol::object d = lua["daemon"];
    if (d.get_type() != sol::type::table)
        d = lua["config"];
    if (d.get_type() != sol::type::table)
        return {};
    // A value as Lua, a table of them in order where it is a list and by name where it is not.
    std::function<std::string(const sol::object&, int)> lit = [&](const sol::object& o, int depth) -> std::string {
        switch (o.get_type())
        {
            case sol::type::boolean: return o.as<bool>() ? "true" : "false";
            case sol::type::number:
            {
                char buf[32];
                std::snprintf(buf, sizeof buf, "%.10g", o.as<double>());
                return buf;
            }
            case sol::type::string:
            {
                jvalue s;
                s.k = jvalue::kind::string;
                s.s = o.as<std::string>();
                return lua_setup::lua_literal(s);
            }
            case sol::type::table:
            {
                if (depth > 8)
                    return "{}";
                std::map<std::string, std::string> fields;
                for (const auto& [k, v] : o.as<sol::table>())
                    if (k.get_type() == sol::type::string)
                        fields[k.as<std::string>()] = lit(v, depth + 1);
                std::string out = "{\n";
                const std::string pad(4 * static_cast<size_t>(depth + 1), ' ');
                for (const auto& [k, v] : fields)
                    out += pad + k + " = " + v + ",\n";
                return out + std::string(4 * static_cast<size_t>(depth), ' ') + "}";
            }
            default: return "nil";
        }
    };
    return "daemon = " + lit(d, 0) + "\n";
}

}   // namespace

// `socketley export <dir>`: this daemon's setup as Lua -- <dir>/config.lua, a file a runtime under runtimes/, its zones
// under zones/ and its scripts under lua/ -- which `socketley --lua`, or the daemon reading it as its own, makes again.
int cli_export(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: socketley export <dir>\n";
        return 1;
    }
    type_manifest::load_dir(socketley_paths::resolve().types_dir);
    const std::filesystem::path dir = argv[2];
    std::error_code ec;
    if (std::filesystem::exists(dir / "config.lua", ec))
    {
        std::cout << (dir / "config.lua").string() << " exists: export writes a setup into a directory that has none\n";
        return 1;
    }

    std::string listing;
    const int lrc = ipc_send("ls --json", listing);
    if (lrc < 0)
        return ipc_report_failure(lrc);
    jvalue all;
    socketley::json::json_policy any;
    any.object_root = false;
    std::string_view lv = listing;
    while (!lv.empty() && std::isspace(static_cast<unsigned char>(lv.back())))
        lv.remove_suffix(1);
    if (lrc != 0 || !socketley::json::json_reader(lv, any).document(all) || all.k != jvalue::kind::array)
    {
        std::cout << "the daemon's list of runtimes was not JSON: " << listing.substr(0, 200) << "\n";
        return 2;
    }

    struct one
    {
        std::string name, type, text;
    };
    std::vector<one> written;
    std::set<std::string> outside;
    for (const jvalue& r : all.items)
    {
        // One another runtime made is made again by it, and one the cluster placed by the cluster.
        const jvalue* placed = socketley::json::member(r, "cluster");
        if (!socketley::json::string_of(r, "owner").empty() || (placed && placed->k == jvalue::kind::boolean && placed->b))
            continue;
        const std::string name(socketley::json::string_of(r, "name"));
        std::string shown, line = "show ";
        ipc_frame::append_arg(line, name);
        jvalue state;
        if (ipc_send(line, shown) != 0 || !parse(shown, state))
        {
            std::cout << name << ": the daemon did not show it\n";
            return 2;
        }
        const std::string type(socketley::json::string_of(state, "type"));
        runtime_type rt;
        if (!parse_runtime_type(type.c_str(), rt))
        {
            std::cout << name << ": its type " << type << " is none this build knows\n";
            return 2;
        }
        std::vector<std::string> unmapped;
        auto settings = lua_setup::settings_of(state, rt, unmapped);
        if (!unmapped.empty())
        {
            std::cout << name << ": no flag sets";
            for (const auto& k : unmapped)
                std::cout << " " << k;
            std::cout << ", so a setup cannot say them\n";
            return 2;
        }
        // A mail runtime's certificate that is its entrance's is the one --tls with --dns takes without being told.
        if (rt == runtime_mail && !socketley::json::string_of(state, "dns").empty())
        {
            const std::string acme = (socketley_paths::resolve().state_dir / ".acme" / "entrance-").string();
            const auto entrance_file = [&](std::string_view key) {
                return std::string(socketley::json::string_of(state, key)).starts_with(acme);
            };
            if (entrance_file("cert_path") && entrance_file("key_path"))
                std::erase_if(settings, [](const auto& s) { return s.first == "cert" || s.first == "key"; });
        }
        std::string why;
        for (auto& [k, v] : settings)
        {
            // Its zones and its script go with it, beside the file; what else it reads is named above the setup.
            if (rt == runtime_dns && k == "zone")
                for (jvalue& z : v.items)
                {
                    const std::filesystem::path from = zone_file(z.s);
                    const std::string to = "zones/" + from.filename().string();
                    if (!copy_into(from, dir / to, why))
                    {
                        std::cout << why << "\n";
                        return 2;
                    }
                    z.s = to;
                }
            else if (k == "lua" && v.k == jvalue::kind::string)
            {
                const std::string to = "lua/" + name + ".lua";
                if (!copy_into(v.s, dir / to, why))
                {
                    std::cout << why << "\n";
                    return 2;
                }
                v.s = to;
            }
            // A runtime's data directory and what it writes are its own, made where they are missing.
            else if (v.k == jvalue::kind::string && v.s.starts_with("/") && k != "dir" && k != "backup_dir" && k != "log" &&
                     k != "write" && !v.s.starts_with(socketley_paths::resolve().state_dir.string()))
                outside.insert(v.s);
            else if (k == "auth" && v.k == jvalue::kind::string && v.s.find(":/") != std::string::npos)
                outside.insert(v.s.substr(v.s.find(':') + 1));
        }
        std::string text = "-- The " + type + " runtime " + name + ".\nreturn {\n    type = \"" + type + "\",\n    name = " +
                           lua_setup::lua_literal([&] { jvalue s; s.k = jvalue::kind::string; s.s = name; return s; }()) + ",\n";
        for (const auto& [k, v] : settings)
            text += "    " + k + " = " + lua_setup::lua_literal(v) + ",\n";
        const jvalue* running = socketley::json::member(state, "was_running");
        text += std::string("    start = ") + (running && running->b ? "true" : "false") + ",\n}\n";
        written.push_back({name, type, std::move(text)});
    }
    std::stable_sort(written.begin(), written.end(), [](const one& a, const one& b) { return rank(a.type) < rank(b.type); });

    std::filesystem::create_directories(dir / "runtimes", ec);
    for (const one& w : written)
    {
        std::ofstream f(dir / "runtimes" / (w.name + ".lua"));
        f << w.text;
        if (!f)
        {
            std::cout << (dir / "runtimes" / (w.name + ".lua")).string() << " could not be written\n";
            return 2;
        }
    }
    char date[32];
    const std::time_t now = std::time(nullptr);
    std::strftime(date, sizeof date, "%Y-%m-%d", std::localtime(&now));
    std::string top = std::string("-- This machine's socketley setup, written by `socketley export` on ") + date + ".\n"
                      "-- Its runtimes, made in this order by `socketley --lua config.lua`, or by the daemon at its start\n"
                      "-- where this is its own configuration file; their data is not in it.\n";
    if (!outside.empty())
    {
        top += "--\n-- What they read and the setup does not hold, to be on the machine as well:\n";
        for (const auto& p : outside)
            top += "--   " + p + "\n";
    }
    const std::string d = daemon_table();
    top += "\n" + d + (d.empty() ? "" : "\n") + "runtimes = {\n";
    for (const one& w : written)
        top += "    include \"runtimes/" + w.name + ".lua\",\n";
    top += "}\n";
    {
        std::ofstream f(dir / "config.lua");
        f << top;
        if (!f)
        {
            std::cout << (dir / "config.lua").string() << " could not be written\n";
            return 2;
        }
    }

    // Read back as `--lua` reads it, each runtime planned and held to what the daemon shows of it.
    const std::string written_top = std::filesystem::absolute(dir / "config.lua", ec).string();
    sol::state lua;
    lua_setup::open(lua, written_top);
    if (auto r = lua.safe_script_file(written_top, sol::script_pass_on_error); !r.valid())
    {
        const sol::error err = r;
        std::cout << "the setup written does not run: " << err.what() << "\n";
        return 2;
    }
    std::string why;
    int differing = 0;
    for (const lua_setup::runtime_entry& e : lua_setup::runtimes(lua, written_top, why))
    {
        std::string planned, shown, line = "show ";
        ipc_frame::append_arg(line, e.name);
        std::vector<std::string> words = e.create;
        int failure = 0;
        jvalue want, have;
        if (!e.refused.empty())
            planned = e.refused;
        else if (words[0] = "plan"; !ask(e.name, line_of(words), planned, failure, "plan"))
        {
            if (failure)
                return failure;
            ++differing;
            continue;
        }
        if (!e.refused.empty() || ipc_send(line, shown) != 0 || !parse(planned, want) || !parse(shown, have))
        {
            std::cout << e.name << ": the setup written does not make it: " << planned;
            ++differing;
            continue;
        }
        jvalue left = differences(want, have);
        // Its zones and its script are the copies beside the setup, which the runtime is not reading yet.
        std::erase_if(left.members, [](const auto& m) { return m.first == "zones" || m.first == "lua_script"; });
        if (!left.members.empty())
        {
            std::cout << e.name << ": the setup written makes it otherwise in";
            for (const auto& [k, v] : left.members)
                std::cout << " " << k;
            std::cout << "\n";
            ++differing;
        }
    }
    return differing ? 1 : 0;
}
