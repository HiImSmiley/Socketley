#include <socketley/worker.h>

#include <cstdio>
#include <cstring>

#include "worker_main.h"
#include "../../shared/runtime/type_registry.h"
#include "../server/server_instance.h"

namespace socketley {
namespace worker {

bool register_type(std::string_view type_name, factory make)
{
    // The sniffer decides from the first four bytes and cannot know verbs the
    // daemon has never seen, so a store answering GET and PUT was read as HTTP
    // until it said otherwise -- a footgun documented in an example rather
    // than defaulted here.  A registered type that has not spoken gets lines.
    factory lines_by_default = [make = std::move(make)](std::string_view n)
    {
        auto inst = make(n);
        if (auto* srv = dynamic_cast<server_instance*>(inst.get()))
            if (!srv->wire_protocol_declared())
                srv->set_wire_protocol(proto_tcp);
        return inst;
    };

    runtime_type id;
    return type_registry::register_type(type_name, std::move(lines_by_default), id);
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
