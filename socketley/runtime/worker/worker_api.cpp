#include <socketley/worker.h>

#include <cstdio>
#include <cstring>

#include "worker_main.h"
#include "../../shared/type_registry.h"

namespace socketley {
namespace worker {

bool register_type(std::string_view type_name, factory make)
{
    runtime_type id;
    return type_registry::register_type(type_name, std::move(make), id);
}

int run(int argc, char** argv)
{
    // The daemon's spawn line and nothing else, because a worker started by
    // hand has no control socket on descriptor 3 and no daemon to answer to.
    if (argc < 2 || std::strcmp(argv[1], "proxy-worker") != 0)
    {
        std::printf("%s is a socketley worker binary: the daemon starts it "
                    "from a type manifest's exec path\n",
                    argc > 0 ? argv[0] : "this");
        return 1;
    }

    return worker_main(3);
}

} // namespace worker
} // namespace socketley
