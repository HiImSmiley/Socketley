#include "../shared/runtime_manager.h"
#include "../shared/event_loop.h"

// Order matters, and it is the loop first.
//
// Both live in this one translation unit, so their order is defined rather than
// merely likely: construction follows declaration order and destruction reverses
// it.  Declared the other way round — which is how it was — the loop was
// destroyed FIRST, and every runtime the manager still held was destroyed
// afterwards.  Those destructors reach the ring: ~lua_context withdraws the
// timeouts its Lua timers still have armed, and it is not the only one.  A
// teardown that runs after the loop's own destructor is asking a destroyed
// object whether its ring is open.
//
// Declaring the loop first makes it the last thing to go, which is the order the
// dependency already has: everything that submits names the loop, and nothing
// the loop holds names a runtime.  daemon_start() unmaps the ring long before
// either of these is destroyed, so this changes nothing about when I/O stops —
// only about which object is still alive to be asked.
event_loop g_event_loop;
runtime_manager g_runtime_manager;
