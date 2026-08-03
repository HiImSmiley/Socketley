#pragma once
// The macros only, for event_loop_definitions.h — which op_timing.h includes
// in turn, so it cannot include op_timing.h itself.
#ifdef SOCKETLEY_TIMING
#define SKL_TIMING_FIELD  uint64_t t_submit_ns{0};
#else
#define SKL_TIMING_FIELD
#endif
