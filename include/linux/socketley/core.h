// ═══════════════════════════════════════════════════════════════════
//  socketley/core.h — Engine core (Tier 2, requires libsocketley_sdk.a)
//
//  Provides the event loop, runtime manager, and shared infrastructure.
//  Requires building from source: link with -lsocketley_sdk -luring -lssl -lcrypto
// ═══════════════════════════════════════════════════════════════════
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include "socketley/shared/runtime_definitions.h"
#include "socketley/shared/event_loop_definitions.h"
#include "socketley/shared/logging.h"
#include "socketley/shared/scoped_fd.h"
#include "socketley/shared/tls_context.h"
#include "socketley/shared/event_loop.h"
#ifndef SOCKETLEY_NO_LUA
#include "socketley/shared/lua_context.h"
#endif
#include "socketley/shared/runtime_instance.h"
#include "socketley/shared/runtime_manager.h"
#include "socketley/shared/runtime_factory.h"
