// socketley/worker.h — the worker half of a registered runtime type
// (Tier 2, requires libsocketley_sdk.a)
//
// A registered type is a manifest the daemon reads plus a binary the daemon's
// supervisor forks and execs; this header is that binary's whole surface.
//
// Usage:
//   int main(int argc, char** argv) {
//       socketley::worker::register_type("greeter",
//           [](std::string_view name) { return std::make_unique<greeter>(name); });
//       return socketley::worker::run(argc, argv);
//   }
//
// The daemon spawns the binary as `<exec> proxy-worker` with the control
// socket on descriptor 3, and run() refuses any other invocation, because a
// worker started by hand has no daemon to answer to.
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include <functional>
#include <memory>
#include <string_view>

class runtime_instance;

namespace socketley {
namespace worker {

using factory = std::function<std::unique_ptr<runtime_instance>(std::string_view name)>;

// Registers the type this binary can build, before run(), returning false for
// a built-in name, a duplicate, or a name a manifest could not carry.
bool register_type(std::string_view type_name, factory make);

// Serves the daemon's control socket until it closes or a shutdown frame
// arrives, returning the process exit code.
int run(int argc, char** argv);

} // namespace worker
} // namespace socketley
