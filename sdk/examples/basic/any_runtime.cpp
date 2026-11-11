// Socketley SDK — any runtime type, by the flags `socketley create` takes
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/any_runtime.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /tmp/any_runtime
//
// Run:
//   /tmp/any_runtime web site "-p 8080 --root /srv/site --lua-pages"
//   /tmp/any_runtime storage files "-p 9000 --dir /srv/files --anonymous"
#include <socketley/any_runtime.h>

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cout << "usage: any_runtime <type> <name> [flags]\n";
        return 1;
    }
    socketley::any_runtime runtime(argv[1], argv[2], argc > 3 ? argv[3] : "");
    return runtime.start() ? 0 : 1;
}
