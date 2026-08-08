#include "cli.h"
#include <iostream>
#include <sstream>
#include <string>
#include <sol/sol.hpp>

#include "runtime_type_parser.h"
#include "ipc_client.h"
#include "command_hashing.h"

int cli_config(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: socketley --lua <lua path>\n";
        return 1;
    }

    sol::state lua;
    lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::table);

    sol::load_result script = lua.load_file(argv[2]);

    if (!script.valid())
    {
        sol::error err = script;
        std::cerr << "failed to load config: " << err.what() << "\n";
        return 1;
    }

    // Deliberately NOT bounded by lua_deadline, unlike every other chunk this
    // tree runs.  That bound exists because the daemon's event loop is one
    // thread serving every runtime, and a script that does not return takes all
    // of them down with it.  This chunk runs in the CLI process: it holds
    // nothing anybody else is waiting on, the operator started it in the
    // foreground and can end it with a keystroke, and a configuration file that
    // spends thirty seconds working out what to create is doing something
    // legitimate that a ten second bound would break for no gain.
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
        sol::optional<std::string> name = (*daemon)["name"].get<sol::optional<std::string>>();
        if (name && !name->empty())
        {
            std::string response;
            int rc = ipc_send("daemon-name " + *name, response);
            if (rc < 0) { std::cerr << "failed to connect to daemon\n"; return 2; }
            if (rc != 0) { if (!response.empty()) std::cerr << response; return rc; }
        }

        sol::optional<std::string> cluster = (*daemon)["cluster"].get<sol::optional<std::string>>();
        if (cluster && !cluster->empty())
        {
            std::string response;
            int rc = ipc_send("daemon-cluster " + *cluster, response);
            if (rc < 0) { std::cerr << "failed to connect to daemon\n"; return 2; }
            if (rc != 0) { if (!response.empty()) std::cerr << response; return rc; }
        }
    }

    sol::table runtimes = lua["runtimes"];

    if (!runtimes.valid())
        return 0;

    // ─── WHAT THE DAEMON SAID, AND WHETHER ANYBODY LISTENED ─────────────────
    //
    // Every create below used to be sent with `if (ipc_send(...) < 0)`, which
    // asks only whether the socket answered.  The exit code and the sentence
    // the daemon wrote were both dropped, the loop went on, and the function
    // ended with `return 0`.  A configuration file whose every runtime failed
    // reported success and printed nothing.  Measured, against a config naming
    // a script that does not exist:
    //
    //     $ socketley --lua badconf.lua ; echo $?
    //     0                                     <- silence
    //
    //     $ socketley create server conf_a -p 18703 --lua /nonexistent/x.lua -s
    //     could not load Lua script: /nonexistent/x.lua
    //     script error: cannot open /nonexistent/x.lua: No such file or directory
    //     1
    //
    // The daemon wrote the diagnosis both times.  Only one of the two callers
    // read it.
    //
    // Collected rather than returned at the first failure: a config file is a
    // set of runtimes, and the eleven that came up are worth having.  What is
    // not on offer is finishing quietly.
    int failed = 0;

    for (auto& pair : runtimes)
    {
        sol::table t = pair.second;

        // sol::optional, like every other field below.  Read as a plain
        // std::string these two throw on a table that has no such key — and
        // sol2's safety checks follow NDEBUG, so in Release they do not throw,
        // they convert whatever is there.  A config with a misspelled key got
        // undefined behaviour in the build everybody runs.
        sol::optional<std::string> type_opt = t["type"].get<sol::optional<std::string>>();
        sol::optional<std::string> name_opt = t["name"].get<sol::optional<std::string>>();

        if (!name_opt || name_opt->empty())
        {
            std::cerr << "runtime entry without a name: every entry in `runtimes` "
                         "needs name and type\n";
            ++failed;
            continue;
        }
        if (!type_opt || type_opt->empty())
        {
            std::cerr << "runtime \"" << *name_opt << "\" has no type "
                         "(server, client, proxy or cache)\n";
            ++failed;
            continue;
        }

        const std::string type_str = *type_opt;
        const std::string name     = *name_opt;

        runtime_type type;

        if (!parse_runtime_type(type_str.c_str(), type))
        {
            std::cerr << "unknown runtime type: " << type_str << "\n";
            ++failed;
            continue;
        }

        std::string command = "create " + type_str + " " + name;

        sol::optional<int> port = t["port"].get<sol::optional<int>>();
        if (port)
            command += " -p " + std::to_string(*port);

        sol::optional<std::string> target = t["target"].get<sol::optional<std::string>>();
        if (target)
            command += " -t " + *target;

        sol::optional<std::string> mode = t["mode"].get<sol::optional<std::string>>();
        if (mode)
            command += " --mode " + *mode;

        sol::optional<std::string> log = t["log"].get<sol::optional<std::string>>();
        if (log)
            command += " --log " + *log;

        sol::optional<std::string> write_file = t["write"].get<sol::optional<std::string>>();
        if (write_file)
            command += " -w " + *write_file;

        sol::optional<std::string> persistent = t["persistent"].get<sol::optional<std::string>>();
        if (persistent)
            command += " --persistent " + *persistent;

        sol::optional<std::string> protocol = t["protocol"].get<sol::optional<std::string>>();
        if (protocol)
            command += " --protocol " + *protocol;

        sol::optional<std::string> strategy = t["strategy"].get<sol::optional<std::string>>();
        if (strategy)
            command += " --strategy " + *strategy;

        sol::optional<sol::table> backends = t["backends"].get<sol::optional<sol::table>>();
        if (backends)
        {
            std::string joined;
            for (auto& p : *backends)
            {
                if (!joined.empty())
                    joined += ",";
                joined += p.second.as<std::string>();
            }
            command += " --backend " + joined;
        }

        sol::optional<std::string> lua_script = t["config"].get<sol::optional<std::string>>();
        if (!lua_script || lua_script->empty())
            lua_script = t["lua"].get<sol::optional<std::string>>();
        if (lua_script && !lua_script->empty())
            command += " --lua " + *lua_script;

        sol::optional<std::string> bash = t["bash"].get<sol::optional<std::string>>();
        if (bash)
        {
            switch (fnv1a(*bash))
            {
                case fnv1a("pt"):
                case fnv1a("tp"):
                case fnv1a("bpt"):
                case fnv1a("btp"):
                    command += " -bpt";
                    break;
                case fnv1a("p"):
                case fnv1a("bp"):
                    command += " -bp";
                    break;
                case fnv1a("t"):
                case fnv1a("bt"):
                    command += " -bt";
                    break;
                default:
                    command += " -b";
                    break;
            }
        }

        sol::optional<std::string> cache_name = t["cache"].get<sol::optional<std::string>>();
        if (cache_name)
            command += " --cache " + *cache_name;

        sol::optional<std::string> group = t["group"].get<sol::optional<std::string>>();
        if (group && !group->empty())
            command += " -g " + *group;

        sol::optional<std::string> master_pw = t["master_pw"].get<sol::optional<std::string>>();
        if (master_pw && !master_pw->empty())
            command += " --master-pw " + *master_pw;

        bool master_forward = t["master_forward"].get_or(false);
        if (master_forward)
            command += " --master-forward";

        sol::optional<std::string> http_dir = t["http"].get<sol::optional<std::string>>();
        if (http_dir && !http_dir->empty())
            command += " --http " + *http_dir;

        bool http_cache = t["http_cache"].get_or(false);
        if (http_cache)
            command += " --http-cache";

        bool udp = t["udp"].get_or(false);
        if (udp)
            command += " --udp";

        bool test = t["test"].get_or(false);
        if (test)
            command += " --test";

        // Where this runtime runs.  The one flag a configuration could not
        // reach, and the one it could least afford to miss.
        //
        // A runtime gets its own worker process unless it asks not to, and a
        // worker holds one runtime and no runtime map.  The cross-runtime Lua
        // API — socketley.create/.start/.stop/.remove/.send/.list/.get/.pipe,
        // everything under socketley.cluster, and self.route(), which names
        // another runtime — is exactly the part that needs the map, so in a
        // worker every one of those calls raises.
        //
        // Inside a callback that raise is caught and logged and the runtime
        // carries on, which is what made this worth adding rather than
        // documenting: the runtime comes up green, `ls` lists it, the port
        // accepts connections, and none of the work is done.  A configuration
        // that wanted such a runtime had no way to say so, and no way to find
        // out that it had not.
        //
        // Nor could it be repaired afterwards: `edit` refuses the flag, because
        // honouring it would mean moving a configured runtime between address
        // spaces underneath whatever already points at it.  A configuration
        // that omitted it had to be deleted and recreated by hand.
        //
        // Emitted wherever it lands in the string: create pre-scans its
        // arguments for this flag before parsing any of them, precisely so that
        // its position cannot change what --lua does.
        bool daemon_process = t["daemon_process"].get_or(false);
        if (daemon_process)
            command += " --daemon-process";

        bool start = t["start"].get_or(false);
        if (start)
            command += " -s";

        std::string response;
        const int rc = ipc_send(command, response);

        if (rc < 0)
        {
            // No daemon is a different thing from a runtime that would not
            // build: nothing after this can succeed either, so it stops here.
            std::cerr << "failed to connect to daemon\n";
            return 2;
        }

        if (rc != 0)
        {
            std::cerr << "could not create " << name << ":\n";
            if (!response.empty())
            {
                // The daemon's own sentence, indented so a multi-line refusal
                // reads as belonging to the runtime named above it.
                std::istringstream lines(response);
                std::string line;
                while (std::getline(lines, line))
                    std::cerr << "  " << line << "\n";
            }
            else
            {
                std::cerr << "  the daemon refused it and said nothing "
                             "(exit " << rc << ")\n";
            }
            ++failed;
            continue;
        }

        // Success is silent, per this project's convention — but a create that
        // printed something while succeeding has something to say (an on_start
        // that raised, for one), and dropping it here is what this whole change
        // is about.
        if (!response.empty())
            std::cout << response;
    }

    if (failed > 0)
    {
        std::cerr << failed << " of " << runtimes.size()
                  << " runtimes in this configuration were not created\n";
        return 1;
    }

    return 0;
}
