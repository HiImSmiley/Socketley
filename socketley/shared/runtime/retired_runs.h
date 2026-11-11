#pragma once

#include <memory>
#include <vector>

namespace socketley
{

// Runs stopped but still owed completions by the ring, each freed on the first turn it is drained().
template <class Run>
class retired_runs
{
public:
    // Stops the run here, so no caller can keep one that still starts new work.
    void retire(std::unique_ptr<Run> run)
    {
        if (!run)
            return;
        run->stop();
        m_runs.push_back(std::move(run));
    }

    // True once every retired run has been freed.
    bool drain()
    {
        reap();
        return m_runs.empty();
    }

    void reap()
    {
        if (!m_runs.empty())
            std::erase_if(m_runs, [](const std::unique_ptr<Run>& r) { return r->drained(); });
    }

private:
    std::vector<std::unique_ptr<Run>> m_runs;
};

} // namespace socketley
