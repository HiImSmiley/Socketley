#pragma once
// Submit-to-complete latency per op type, under -DSOCKETLEY_TIMING.
// A multishot row is NOT latency: the stamp resets per completion, so the
// second and later intervals are gaps between deliveries.

#ifdef SOCKETLEY_TIMING

#include <cstdint>
#include <cstdio>
#include <ctime>
#include "event_loop_definitions.h"

namespace skl_timing {

// vDSO CLOCK_MONOTONIC, ~20ns; rdtsc would need calibration this can do
// without, in a build that does not ship.
inline uint64_t now_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

// Log2 buckets, so one array spans a nanosecond to eleven seconds without
// deciding in advance where the interesting range is.
inline constexpr int BUCKETS = 34;

struct histogram
{
    uint64_t count[op_type_count][BUCKETS]{};
    uint64_t total_ns[op_type_count]{};
    uint64_t ops[op_type_count]{};
    uint64_t max_ns[op_type_count]{};

    // Time inside on_cqe, which unlike latency above does add up: summing
    // overlapping latencies exceeds the wall clock and means nothing.
    uint64_t handler_ns[op_type_count]{};

    void add_handler(uint8_t type, uint64_t ns)
    {
        if (type < op_type_count)
            handler_ns[type] += ns;
    }

    void add(uint8_t type, uint64_t ns)
    {
        if (type >= op_type_count)
            return;
        int b = 0;
        for (uint64_t v = ns; v > 1 && b < BUCKETS - 1; v >>= 1)
            ++b;
        ++count[type][b];
        total_ns[type] += ns;
        ++ops[type];
        if (ns > max_ns[type])
            max_ns[type] = ns;
    }

    // The low edge of the bucket, not interpolated: a log2 bucket is a factor
    // of two wide and interpolating invents precision.
    uint64_t percentile(uint8_t type, double p) const
    {
        const uint64_t want = static_cast<uint64_t>(ops[type] * p);
        uint64_t seen = 0;
        for (int b = 0; b < BUCKETS; ++b)
        {
            seen += count[type][b];
            if (seen >= want)
                return b == 0 ? 0 : (1ull << b);
        }
        return max_ns[type];
    }

    void dump(const char* label) const
    {
        bool any = false;
        for (uint8_t t = 0; t < op_type_count; ++t)
            if (ops[t]) { any = true; break; }
        if (!any)
            return;

        uint64_t handler_total = 0;
        for (uint8_t t = 0; t < op_type_count; ++t)
            handler_total += handler_ns[t];

        std::fprintf(stderr,
            "\n=== op timing: %s ===\n"
            "latency = submit to complete, and it OVERLAPS: summing it across\n"
            "operations can exceed the wall clock and is not a cost.  handler_ms\n"
            "is time inside on_cqe on this thread, and that one does add up.\n\n"
            "%-22s %10s %10s %10s %10s %12s %8s\n",
            label, "op", "count", "mean_us", "p50_us", "p99_us",
            "handler_ms", "share");
        for (uint8_t t = 0; t < op_type_count; ++t)
        {
            if (!ops[t])
                continue;
            std::fprintf(stderr, "%-22s %10llu %10.2f %10.2f %10.2f %12.1f %7.1f%%\n",
                         io_op_name(t),
                         (unsigned long long)ops[t],
                         double(total_ns[t]) / double(ops[t]) / 1000.0,
                         double(percentile(t, 0.50)) / 1000.0,
                         double(percentile(t, 0.99)) / 1000.0,
                         double(handler_ns[t]) / 1e6,
                         handler_total ? double(handler_ns[t]) * 100.0 / double(handler_total) : 0.0);
        }
        std::fprintf(stderr,
            "handler total %.1f ms across all op types\n"
            "(multishot rows are gaps between deliveries, not latencies — "
            "see shared/op_timing.h)\n", double(handler_total) / 1e6);
    }
};

}   // namespace skl_timing

#define SKL_TIMING_STAMP(req)  ((req)->t_submit_ns = ::skl_timing::now_ns())
#define SKL_TIMING_COMPLETE(hist, req)                                        \
    do {                                                                      \
        const uint64_t _n = ::skl_timing::now_ns();                           \
        if ((req)->t_submit_ns)                                               \
            (hist).add((req)->type, _n - (req)->t_submit_ns);                  \
        (req)->t_submit_ns = _n;   /* multishot: next gap starts here */      \
    } while (0)
// Around the dispatch, so what it measures is this thread's own work rather
// than the kernel's.
#define SKL_TIMING_HANDLER_BEGIN(req) \
    const uint64_t _skl_h0 = ::skl_timing::now_ns(); \
    const uint8_t  _skl_ht = (req) ? (req)->type : 0
#define SKL_TIMING_HANDLER_END(hist) \
    (hist).add_handler(_skl_ht, ::skl_timing::now_ns() - _skl_h0)
#define SKL_TIMING_MEMBER  ::skl_timing::histogram m_op_timing;
#define SKL_TIMING_DUMP(hist, label)  (hist).dump(label)

#else   // !SOCKETLEY_TIMING

#define SKL_TIMING_STAMP(req)          ((void)0)
#define SKL_TIMING_HANDLER_BEGIN(req)  ((void)0)
#define SKL_TIMING_HANDLER_END(hist)   ((void)0)
#define SKL_TIMING_COMPLETE(hist, req) ((void)0)
#define SKL_TIMING_MEMBER
#define SKL_TIMING_DUMP(hist, label)   ((void)0)

#endif
