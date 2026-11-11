// socketley/ws_client.h -- the portable client tier, one copy
//
// This header is byte-identical on every platform, so it lives once under
// sdk/include/portable and is reached from here.  Two copies drifted apart in
// exactly the way a third would: they were 706 and 806 lines each, and a
// Linux program that wanted them had to put -Isdk/include/windows on its command
// line to compile.
#pragma once
#include "../../portable/socketley/ws_client.h"
