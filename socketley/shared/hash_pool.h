#pragma once
// A few helper threads that run the digests of a body, so a loop that moves
// bytes is not also the one core that hashes them.
//
// A caller submits work under a lane: the work of one lane runs in order on one
// thread, so a digest that is fed piece by piece is only ever touched by one
// thread at a time.  When a piece of work is done its completion is queued for
// the loop, and an eventfd says so: the loop reads that descriptor through its
// ring and calls drain(), which runs the completions on the loop's own thread.
// Nothing here touches the loop from a helper thread but the eventfd write.
//
// The threads are started by the first submission, so a runtime that never
// receives a large body has none, and they end in stop().
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <sys/eventfd.h>
#include <unistd.h>

#include "file_io.h"

namespace socketley
{

class hash_pool
{
public:
    using work       = std::function<void()>;
    using completion = std::function<void()>;

    // Zero threads means nothing is ever queued: enabled() is false and the
    // caller hashes in line.
    explicit hash_pool(unsigned threads) : m_lanes(threads)
    {
        if (threads)
            m_wake = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (m_wake < 0)
            m_lanes.clear();
    }

    ~hash_pool()
    {
        stop();
        if (m_wake >= 0)
            ::close(m_wake);
    }

    hash_pool(const hash_pool&)            = delete;
    hash_pool& operator=(const hash_pool&) = delete;

    bool     enabled() const { return !m_lanes.empty() && !m_stopped; }
    unsigned threads() const { return static_cast<unsigned>(m_lanes.size()); }

    // Waits for the eventfd on the loop's ring, through `io`, and drains the
    // completions when it fires.  False means the read could not be queued and
    // the pool must not be used.
    bool attach(file_io& io)
    {
        m_io = &io;
        if (!enabled())
            return true;
        return arm();
    }

    // The descriptor that becomes readable when completions are waiting.
    int wake_fd() const { return m_wake; }

    // Hands the descriptor to a caller that closes it through its loop, which
    // is how an outstanding read on it is cancelled; call after stop().
    int release_wake_fd()
    {
        const int fd = m_wake;
        m_wake = -1;
        return fd;
    }

    // How many pieces of work have been handed over, for a test to tell that the pool was used.
    uint64_t submitted() const { return m_submitted; }

    // A lane number for a new stream, spread over the threads.
    uint32_t next_lane() { return m_next_lane++; }

    // Runs `w` on the lane's thread after the work submitted before it, then
    // queues `done` for drain().  Called from the loop's thread only.
    void submit(uint32_t lane_no, work w, completion done)
    {
        if (!enabled())
            return;
        if (!m_started)
            start();
        // A re-arm that found the ring full is tried again here.
        if (m_need_arm && m_io)
            arm();
        ++m_submitted;
        lane& l = m_lanes[lane_no % m_lanes.size()];
        {
            std::lock_guard<std::mutex> g(l.mu);
            l.q.push_back({std::move(w), std::move(done)});
        }
        l.cv.notify_one();
    }

    // Runs the completions that are waiting, on the calling thread.
    void drain()
    {
        // Before the swap, so a completion queued after it writes the
        // descriptor again and is not left waiting for a wake-up that never comes.
        m_wake_pending.store(false, std::memory_order_seq_cst);
        std::vector<completion> ready;
        {
            std::lock_guard<std::mutex> g(m_done_mu);
            ready.swap(m_done);
        }
        for (completion& c : ready)
            c();
    }

    // Ends the threads, discarding whatever was queued; completions that had
    // not been drained never run.  Idempotent.
    void stop()
    {
        if (m_stopped)
            return;
        m_stopped = true;
        for (lane& l : m_lanes)
        {
            {
                std::lock_guard<std::mutex> g(l.mu);
                l.quit = true;
            }
            l.cv.notify_all();
        }
        for (lane& l : m_lanes)
            if (l.th.joinable())
                l.th.join();
        for (lane& l : m_lanes)
            l.q.clear();
        std::lock_guard<std::mutex> g(m_done_mu);
        m_done.clear();
    }

private:
    struct item
    {
        work       w;
        completion done;
    };

    struct lane
    {
        std::mutex              mu;
        std::condition_variable cv;
        std::deque<item>        q;
        std::thread             th;
        bool                    quit{false};
    };

    bool arm()
    {
        m_need_arm = false;
        const bool queued = m_io->pread(m_wake, reinterpret_cast<char*>(&m_wake_buf), sizeof m_wake_buf, 0,
            [this](int64_t r)
            {
                if (r < 0 || m_stopped)
                    return;
                drain();
                if (!arm())
                    m_need_arm = true;
            });
        if (!queued)
            m_need_arm = true;
        return queued;
    }

    void start()
    {
        m_started = true;
        for (lane& l : m_lanes)
            l.th = std::thread([this, &l] { run(l); });
    }

    void run(lane& l)
    {
        for (;;)
        {
            item it;
            {
                std::unique_lock<std::mutex> g(l.mu);
                l.cv.wait(g, [&] { return l.quit || !l.q.empty(); });
                if (l.quit)
                    return;
                it = std::move(l.q.front());
                l.q.pop_front();
            }
            it.w();
            {
                std::lock_guard<std::mutex> g(m_done_mu);
                m_done.push_back(std::move(it.done));
            }
            if (!m_wake_pending.exchange(true, std::memory_order_seq_cst))
            {
                const uint64_t one = 1;
                if (::write(m_wake, &one, sizeof one) < 0) {}
            }
        }
    }

    std::vector<lane>       m_lanes;
    int                     m_wake{-1};
    bool                    m_started{false};
    bool                    m_stopped{false};
    uint32_t                m_next_lane{0};
    uint64_t                m_submitted{0};
    std::mutex              m_done_mu;
    std::vector<completion> m_done;
    std::atomic<bool>       m_wake_pending{false};
    file_io*                m_io{nullptr};
    uint64_t                m_wake_buf{0};
    bool                    m_need_arm{false};
};

}   // namespace socketley
