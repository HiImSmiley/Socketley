// Socketley SDK — daemon control example (header-only, no library needed)
//
// Build:
//   g++ -std=c++17 sdk/examples/basic/daemon_control.cpp \
//       -Iinclude/linux -o /tmp/daemon_control
//
// Run (requires a running socketley daemon):
//   /tmp/daemon_control

#include <socketley/control.h>
#include <cstdio>

int main()
{
    // Create and start a server
    auto r = socketley::ctl::create("server", "sdk-test", "-p 9000 -s");
    if (r.exit_code != 0)
    {
        fprintf(stderr, "create failed: %s\n", r.data.c_str());
        return 1;
    }

    // Query stats
    auto stats = socketley::ctl::stats("sdk-test");
    printf("%s\n", stats.data.c_str());

    // List runtimes
    auto list = socketley::ctl::ls();
    printf("%s", list.data.c_str());

    // Cleanup
    socketley::ctl::stop("sdk-test");
    socketley::ctl::remove("sdk-test");

    return 0;
}
