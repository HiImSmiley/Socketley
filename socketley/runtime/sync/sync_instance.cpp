#include "sync_instance.h"
#include "sync_run.h"

#include <filesystem>
#include <sstream>
#include <sys/stat.h>

#include "../../shared/logging.h"

namespace
{

// A target is `runtime/bucket` or `scheme://host[:port]/bucket`, with the bucket last in both.
bool target_bucket(std::string_view t, std::string_view& bucket)
{
    const size_t slash = t.rfind('/');
    if (slash == std::string_view::npos || slash + 1 >= t.size())
        return false;
    bucket = t.substr(slash + 1);
    return !bucket.empty() && bucket.find("://") == std::string_view::npos;
}

}   // namespace

bool parse_sync_runtime_mode(std::string_view s, sync_mode& out)
{
    if (s == "out")
        out = sync_mode_out;
    else if (s == "in")
        out = sync_mode_in;
    else if (s == "inout")
        out = sync_mode_inout;
    else
        return false;
    return true;
}

const char* sync_mode_name(sync_mode m)
{
    switch (m)
    {
        case sync_mode_out:   return "out";
        case sync_mode_in:    return "in";
        case sync_mode_inout: return "inout";
    }
    return "out";
}

sync_instance::sync_instance(std::string_view name) : runtime_instance(runtime_sync, name) {}

sync_instance::~sync_instance() = default;

std::vector<std::string> sync_instance::storage_targets() const
{
    std::vector<std::string> out;
    for (size_t p = 0; p <= m_storage.size();)
    {
        const size_t comma = std::min(m_storage.find(',', p), m_storage.size());
        std::string one(m_storage.substr(p, comma - p));
        while (!one.empty() && (one.front() == ' ' || one.front() == '\t'))
            one.erase(one.begin());
        while (!one.empty() && (one.back() == ' ' || one.back() == '\t'))
            one.pop_back();
        if (!one.empty())
            out.push_back(std::move(one));
        p = comma + 1;
    }
    return out;
}

uint16_t sync_instance::effective_port() const
{
    // It listens on nothing: `ls` and the dashboard show a dash rather than a port nobody can reach.
    return 0;
}

size_t sync_instance::get_connection_count() const
{
    return m_run ? m_run->open_connections() : 0;
}

std::string sync_instance::config_refusal() const
{
    if (m_dir.empty())
        return "sync: --dir is required: the directory whose files are carried\n";
    if (m_dir.front() != '/')
        return "sync: --dir takes an absolute path, not '" + m_dir + "'\n";
    struct stat st{};
    if (::stat(m_dir.c_str(), &st) != 0)
        return "sync: --dir " + m_dir + " does not exist\n";
    if (!S_ISDIR(st.st_mode))
        return "sync: --dir " + m_dir + " is not a directory\n";
    const auto targets = storage_targets();
    if (targets.empty())
        return "sync: --storage is required: a storage runtime's name and a bucket (ui/photos), or a URL with one\n";
    for (const auto& t : targets)
    {
        std::string_view bucket;
        if (!target_bucket(t, bucket))
            return "sync: --storage takes a bucket after the runtime or the URL, as in ui/photos or "
                   "https://storage.example/photos, not '" + t + "'\n";
    }
    // Two sources writing one directory cannot say which of them a file came from, so only the carrying out of one
    // directory may name more than one target.
    if (targets.size() > 1 && m_mode != sync_mode_out)
        return "sync: --storage takes one target unless --mode is out: carrying two of them into one directory "
               "cannot say which a file came from when they differ\n";
    if (m_credentials.empty())
        return "sync: --token or --credentials is required: a sync signs every request it makes\n";
    if (::access(m_credentials.c_str(), R_OK) != 0)
        return "sync: the credentials file " + m_credentials + " cannot be read\n";
    if (m_mode != sync_mode_out)
        return "sync: --mode " + std::string(sync_mode_name(m_mode)) +
               " is not carried yet; only out is, which sends --dir to --storage\n";
    if (!get_listen_path().empty())
        return "sync: --listen unix: is not served; a sync listens on nothing\n";
    if (get_port() != 0)
        return "sync: -p is not taken; a sync listens on nothing and dials out\n";
    return {};
}

void sync_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool sync_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::sync::sync_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("sync: " + why).c_str());
        return false;
    }
    m_run = std::move(run);
    return true;
}

void sync_instance::teardown(event_loop&)
{
    if (m_run)
        m_run->stop();
    m_run.reset();
}

void sync_instance::on_loop_turn()
{
    if (m_run)
        m_run->on_loop_turn();
}

std::string sync_instance::stats_lines() const
{
    std::ostringstream out;
    out << "mode:" << sync_mode_name(m_mode) << "\n";
    out << "dir:" << m_dir << "\n";
    if (!m_run)
        return out.str();
    const auto& s = m_run->stats();
    out << "indexed:" << s.indexed << "\n"
        << "carried:" << s.carried << "\n"
        << "removed:" << s.removed << "\n"
        << "bytes_carried:" << s.bytes_carried << "\n"
        << "waiting:" << s.waiting << "\n"
        << "failures:" << s.failures << "\n"
        << "last_run_secs:" << s.last_run_secs << "\n"
        << "last_error:" << s.last_error << "\n";
    return out.str();
}
