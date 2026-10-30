#pragma once
// A metrics runtime's blocks copied to S3 (--archive), each once it is a day or more of data, or two days old, so the
// archive holds every sample after the local retention has let it go. Copied back into blocks/, they read again:
// a block inside a bigger one of its kind is dropped at open, so the pieces a merge replaced do no harm.
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <string_view>

#include "../../shared/http/outbound_http.h"

namespace socketley::metrics
{

struct archive_figures
{
    uint64_t blocks{0};
    uint64_t bytes{0};
    uint64_t failures{0};
};

class archiver
{
public:
    // How often the blocks are looked at, and a failed copy tried again.
    static constexpr int64_t every_ms = 60'000;

    archiver(event_loop& loop, file_io& io, hash_pool& resolver, std::string owner);
    ~archiver();

    // `url` an S3 bucket with a key prefix (http[s]://host[:port]/bucket[/prefix]), `credentials` the file sync reads,
    // `dir` the store's; false with `why` when the URL is not one.
    bool configure(std::string_view url, std::string credentials, std::string dir, std::string& why);
    bool enabled() const { return m_peer != nullptr; }
    // Starts the next copy when one is due; the time it wants to be asked again.
    int64_t tick(int64_t now);
    // A block was cut or merged, so the next tick looks at once rather than at the minute.
    void poke() { m_next = 0; }
    void stop();
    const archive_figures& figures() const { return m_f; }

private:
    void start(const std::string& name);
    void save() const;

    event_loop& m_loop;
    file_io& m_io;
    hash_pool& m_resolver;
    std::string m_owner;
    std::unique_ptr<socketley::http_peer> m_peer;
    std::string m_bucket, m_prefix, m_credentials, m_dir;
    // The blocks copied, by file name, kept in <dir>/archived.
    std::set<std::string> m_done;
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    bool m_running{false};
    bool m_said{false};
    int64_t m_next{0};
    archive_figures m_f;
};

}   // namespace socketley::metrics
