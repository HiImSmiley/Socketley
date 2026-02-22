#pragma once
// Socketley C++ SDK — umbrella header (Linux only, io_uring kernel 5.11+)
// Include this single header to access all Socketley SDK types.
//
// Required include paths (repo root must be in -I):
//   -I<repo_root>  -I<repo_root>/include/linux
//   -I<repo_root>/thirdparty/sol2  -I<repo_root>/thirdparty/luajit  (unless SOCKETLEY_NO_LUA)
//
// Required link libraries:
//   -luring -lssl -lcrypto -lluajit  (omit -lluajit when SOCKETLEY_NO_LUA)
#include "platform.h"
#include "types.h"
#include "event_loop.h"
#include "runtime.h"
#include "server.h"
#include "client.h"
#include "proxy.h"
#include "cache.h"
#include "daemon_client.h"
