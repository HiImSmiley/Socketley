#include "cli.h"
#include "../daemon/daemon.h"
#include "../shared/runtime/runtime_manager.h"
#include "../shared/loop/event_loop.h"

int cli_daemon(int argc, char** argv)
{
    // Made here and not at namespace scope, because every process this binary becomes -- each CLI call and each
    // runtime's worker -- otherwise built and zeroed a daemon's whole loop and manager that it never used.
    // The loop is made first so it is destroyed last, because runtime destructors reach the ring and a teardown after
    // the loop's own destructor asks a destroyed object whether its ring is open.
    static event_loop      loop;
    static runtime_manager manager;
    return daemon_start(manager, loop, argc, argv);
}
