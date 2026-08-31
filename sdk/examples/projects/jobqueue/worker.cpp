// jobqueue — a worker draining the queue jobd serves.
//
// Deliberately built on the CROSS-PLATFORM header: cache_client.h is the same
// file on Linux, Windows and macOS, so this worker compiles unchanged on all
// three and needs nothing from the repo but that one header.  A worker fleet
// on a different OS than the queue is the normal case, not the exotic one.
//
// It polls with lpop.  The text protocol has no blocking pop, so an idle
// worker sleeps between empty polls — the interval is the latency floor for
// a queued job, and 200ms is a demo value, not a recommendation.
//
// Build (Linux):
//   g++ -std=c++17 sdk/examples/projects/jobqueue/worker.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /tmp/jobworker
// (On Windows: cl /std:c++17 /EHsc /I include\windows worker.cpp
//  On macOS:   clang++ -std=c++17 -I include/darwin worker.cpp)
//
// Run:  /tmp/jobworker [host] — drains until Ctrl-C.

#include <socketley/cache_client.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    // Line-buffered even when stdout is a file or a pipe: a worker's output is
    // a progress log, and a job that was processed but never flushed looks
    // exactly like a job that was lost.
    setvbuf(stdout, nullptr, _IOLBF, 0);

    const std::string host = argc > 1 ? argv[1] : "127.0.0.1";

    socketley::cache_client q;
    if (!q.connect(host, 6380))
    {
        fprintf(stderr, "cannot reach the queue at %s:6380 -- is jobd up?\n",
                host.c_str());
        return 1;
    }
    printf("worker: connected to %s:6380, polling '%s'\n", host.c_str(), "queue");

    uint64_t done = 0;
    for (;;)
    {
        auto job = q.lpop("queue");
        if (!job.ok)
        {
            // A failed command is a broken connection, not an empty queue.
            fprintf(stderr, "worker: connection lost, reconnecting\n");
            while (!q.reconnect())
                std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        if (job.is_nil())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        // "process" the job — this is where real work goes.
        ++done;
        printf("worker: job %llu: %s\n",
               static_cast<unsigned long long>(done), job.value.c_str());

        // Completed jobs are counted in the same store, so `status` tooling
        // can read progress from anywhere that can reach port 6380.
        q.incr("jobs_done");
    }
}
