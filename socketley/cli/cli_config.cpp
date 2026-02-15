#include "cli.h"
#include <iostream>
#include <string>
#include <sol/sol.hpp>

#include "runtime_type_parser.h"
#include "ipc_client.h"
#include "command_hashing.h"

int cli_config(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cerr << "usage: socketley --config <lua path>\n";
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

    sol::protected_function_result result = script();

    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "error executing config: " << err.what() << "\n";
        return 1;
    }

    sol::table runtimes = lua["runtimes"];

    if (!runtimes.valid())
        return 0;

    for (auto& pair : runtimes)
    {
        sol::table t = pair.second;
        std::string type_str = t["type"];
        std::string name     = t["name"];

        runtime_type type;

        if (!parse_runtime_type(type_str.c_str(), type))
        {
            std::cerr << "unknown runtime type: " << type_str << "\n";
            continue;
        }

        std::string command = "create " + type_str + " " + name;

        sol::optional<int> port = t["port"];
        if (port)
            command += " -p " + std::to_string(*port);

        sol::optional<std::string> target = t["target"];
        if (target)
            command += " -t " + *target;

        sol::optional<std::string> mode = t["mode"];
        if (mode)
            command += " --mode " + *mode;

        sol::optional<std::string> log = t["log"];
        if (log)
            command += " --log " + *log;

        sol::optional<std::string> write_file = t["write"];
        if (write_file)
            command += " -w " + *write_file;

        sol::optional<std::string> persistent = t["persistent"];
        if (persistent)
            command += " --persistent " + *persistent;

        sol::optional<std::string> protocol = t["protocol"];
        if (protocol)
            command += " --protocol " + *protocol;

        sol::optional<std::string> strategy = t["strategy"];
        if (strategy)
            command += " --strategy " + *strategy;

        sol::optional<sol::table> backends = t["backends"];
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

        sol::optional<std::string> lua_script = t["config"];
        if (!lua_script || lua_script->empty())
            lua_script = t["lua"];
        if (lua_script && !lua_script->empty())
            command += " --config " + *lua_script;

        sol::optional<std::string> bash = t["bash"];
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

        sol::optional<std::string> cache_name = t["cache"];
        if (cache_name)
            command += " --cache " + *cache_name;

        sol::optional<std::string> master_pw = t["master_pw"];
        if (master_pw && !master_pw->empty())
            command += " --master-pw " + *master_pw;

        bool master_forward = t["master_forward"].get_or(false);
        if (master_forward)
            command += " --master-forward";

        bool udp = t["udp"].get_or(false);
        if (udp)
            command += " --udp";

        bool test = t["test"].get_or(false);
        if (test)
            command += " --test";

        bool autostart = t["autostart"].get_or(false);
        if (autostart)
            command += " -s";

        std::string response;
        if (ipc_send(command, response) < 0)
        {
            std::cerr << "failed to connect to daemon\n";
            return 1;
        }

    }

    return 0;
}
