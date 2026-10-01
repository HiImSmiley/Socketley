#pragma once
// Disk operations one after another on a runtime's ring.
#include <cerrno>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "../../shared/file_io.h"

namespace socketley::storage
{

// Disk operations one after another, each started when the one before it has
// reported, ending at the first that failed.
class disk_chain : public std::enable_shared_from_this<disk_chain>
{
public:
    using launch = std::function<bool(file_io::done)>;

    explicit disk_chain(std::shared_ptr<bool> alive) : m_alive(std::move(alive)) {}

    // A result of `tolerate` is counted as success, for a directory that may already be there.
    disk_chain& then(launch fn, int64_t tolerate = 0)
    {
        m_steps.push_back({std::move(fn), tolerate});
        return *this;
    }

    // `finished` gets 0, or the first negative errno; it does not run at all
    // when the store has gone.
    void run(std::function<void(int64_t)> finished)
    {
        m_finished = std::move(finished);
        next();
    }

private:
    struct step
    {
        launch  fn;
        int64_t tolerate;
    };

    void next()
    {
        auto self = shared_from_this();
        if (m_i == m_steps.size())
        {
            finish(0);
            return;
        }
        step& s = m_steps[m_i++];
        const int64_t tolerate = s.tolerate;
        // A launched step's captures go with it, or one that holds what holds this chain is a cycle.
        const launch fn = std::move(s.fn);
        const bool queued = fn([self, tolerate](int64_t r)
        {
            if (!*self->m_alive)
                return;
            if (r < 0 && r != tolerate)
            {
                self->finish(r);
                return;
            }
            self->next();
        });
        if (!queued)
            finish(-EIO);
    }

    void finish(int64_t r)
    {
        auto f = std::move(m_finished);
        m_finished = nullptr;
        if (f)
            f(r);
    }

    std::shared_ptr<bool> m_alive;
    std::vector<step>     m_steps;
    size_t                m_i{0};
    std::function<void(int64_t)> m_finished;
};

}   // namespace socketley::storage
