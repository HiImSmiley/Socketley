// socketley/runtime/instance.h -- the base every runtime type shares
//
// Tier 3: the class you inherit from to give the daemon a runtime type it has
// never heard of, paired with <socketley/worker.h>.
//
//   class kvdb final : public runtime_instance {
//   public:
//       explicit kvdb(std::string_view n) : runtime_instance(n) { ... }
//   };
//
// The path below is relative to this header rather than to an include path,
// because the engine's own headers live in the source tree and a build that
// needed -I<repo-root> to see them could not be made from an installed copy.
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include "../../../../socketley/shared/runtime/runtime_instance.h"
