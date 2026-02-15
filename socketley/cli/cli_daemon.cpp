#include "cli.h"
#include "../daemon/daemon.h"
#include "../shared/runtime_manager.h"
#include "../shared/event_loop.h"

extern runtime_manager g_runtime_manager;
extern event_loop g_event_loop;

int cli_daemon()
{
    return daemon_start(g_runtime_manager, g_event_loop);
}
