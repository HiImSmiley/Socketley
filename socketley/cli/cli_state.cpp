#include "../shared/runtime/runtime_manager.h"
#include "../shared/loop/event_loop.h"

// The loop is declared first so it is destroyed last, because runtime
// destructors reach the ring and a teardown after the loop's own destructor
// asks a destroyed object whether its ring is open.
event_loop g_event_loop;
runtime_manager g_runtime_manager;
