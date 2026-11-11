#include "sync_instance.h"
#include "sync_repos.h"
#include "sync_run.h"

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <sys/stat.h>

#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/persist/paths.h"
#include "../../shared/runtime/runtime_name.h"
#include "../../shared/http/outbound_http.h"
#include "../storage/s3_names.h"

std::string sync_index_path(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "sync" / (std::string(runtime_name) + ".index")).string();
}

bool parse_sync_target(std::string_view entry, sync_target_spec& out, std::string& why)
{
    out = sync_target_spec{};
    out.name.assign(entry);
    const size_t slash = entry.rfind('/');
    const std::string_view where = slash == std::string_view::npos ? std::string_view{} : entry.substr(0, slash);
    const std::string_view bucket = slash == std::string_view::npos ? std::string_view{} : entry.substr(slash + 1);
    const std::string example = " -- as in ui/photos, 10.0.0.5:9000/photos or https://files.example/photos";
    if (where.empty() || bucket.empty() || where.ends_with(":/") || where.ends_with("://"))
    {
        why = "'" + out.name + "' names no bucket" + example;
        return false;
    }
    if (!socketley::storage::valid_bucket_name(bucket))
    {
        why = "'" + std::string(bucket) + "' is not a bucket name: 3 to 63 of a-z, 0-9, '.' and '-'";
        return false;
    }
    out.bucket.assign(bucket);
    if (where.find("://") != std::string_view::npos || where.find(':') != std::string_view::npos)
    {
        out.url = where.find("://") == std::string_view::npos ? "http://" + std::string(where) : std::string(where);
        socketley::http_target t;
        if (!socketley::parse_http_url(out.url, t, why))
        {
            why = "'" + out.name + "': " + why;
            return false;
        }
        // The bucket is the whole of the path: a host serving its buckets below a path of its own signs another one.
        if (!t.path.empty() && t.path != "/")
        {
            why = "'" + out.name + "' has a path between the host and the bucket, which is not taken" + example;
            return false;
        }
        return true;
    }
    if (!socketley::valid_runtime_name(where))
    {
        why = "'" + std::string(where) + "' is neither a runtime's name nor an address" + example;
        return false;
    }
    out.runtime.assign(where);
    return true;
}

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

void sync_instance::set_dir(std::string_view path)
{
    // One spelling per directory: a trailing slash or a `.` would shift every path cut from it and change the scope
    // its index is kept for.
    std::string d = std::filesystem::path(path).lexically_normal().string();
    while (d.size() > 1 && d.back() == '/')
        d.pop_back();
    m_dir = std::move(d);
}

std::vector<std::string> sync_instance::storage_targets() const
{
    std::vector<std::string> out;
    for (std::string_view rest = m_storage; !rest.empty();)
    {
        std::string one(socketley::take_item(rest));
        while (!one.empty() && (one.front() == ' ' || one.front() == '\t'))
            one.erase(one.begin());
        while (!one.empty() && (one.back() == ' ' || one.back() == '\t'))
            one.pop_back();
        if (!one.empty())
            out.push_back(std::move(one));
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
    // A user's sync runtime a storage made: its file says everything else.
    if (!m_repositories.empty())
    {
        if (m_repositories.front() != '/')
            return "sync: --repositories takes an absolute path, not '" + m_repositories + "'\n";
        if (!m_dir.empty() || !m_storage.empty())
            return "sync: --repositories is a job of its own, with no --dir or --storage\n";
        if (!get_listen_path().empty() || get_port() != 0)
            return "sync: a sync listens on nothing\n";
        return {};
    }
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
        sync_target_spec spec;
        std::string why;
        if (!parse_sync_target(t, spec, why))
            return "sync: --storage " + why + "\n";
        if (std::count(targets.begin(), targets.end(), t) > 1)
            return "sync: --storage names " + t + " twice\n";
    }
    // Two sources writing one directory cannot say which of them a file came from, so only the carrying out of one
    // directory may name more than one target.
    if (targets.size() > 1 && m_mode != sync_mode_out)
        return "sync: --storage takes one target unless --mode is out: carrying two of them into one directory "
               "cannot say which a file came from when they differ\n";
    if (m_credentials.empty())
        return "sync: --credentials is required: a sync signs every request it makes\n";
    if (::access(m_credentials.c_str(), R_OK) != 0)
        return "sync: the credentials file " + m_credentials + " cannot be read\n";
    // Refused as the SSE key file is, since the secret in it signs as the storage user to anyone who reads it.
    if (struct stat cst{}; ::stat(m_credentials.c_str(), &cst) != 0 || !S_ISREG(cst.st_mode))
        return "sync: the credentials file " + m_credentials + " is not a regular file\n";
    else if ((cst.st_mode & 0077) != 0)
        return "sync: the credentials file " + m_credentials + " may be read by other users; chmod 600 it\n";
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
    if (!m_repositories.empty())
    {
        auto repos = std::make_unique<socketley::sync::repo_runner>(*this, loop);
        std::string why;
        if (!repos->start(why))
        {
            LOG_ERROR(("sync: " + why).c_str());
            m_repo_graveyard.retire(std::move(repos));
            return false;
        }
        m_repos = std::move(repos);
        return true;
    }
    auto run = std::make_unique<socketley::sync::sync_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("sync: " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void sync_instance::teardown(event_loop&)
{
    m_repo_graveyard.retire(std::move(m_repos));
    m_graveyard.retire(std::move(m_run));
}

bool sync_instance::runs_drained()
{
    return m_graveyard.drain() & m_repo_graveyard.drain();
}

void sync_instance::on_loop_turn()
{
    m_graveyard.reap();
    m_repo_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
    if (m_repos)
        m_repos->on_loop_turn();
}

std::string sync_instance::stats_lines() const
{
    std::ostringstream out;
    if (m_repos)
        return m_repos->stats_lines();
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
        << "failing:" << s.failing << "\n"
        << "watched:" << s.watched << "\n"
        << "brought:" << s.brought << "\n"
        << "removed_here:" << s.removed_here << "\n"
        << "conflicts:" << s.conflicts << "\n"
        << "last_run_secs:" << s.last_run_secs << "\n"
        << "last_error:" << s.last_error << "\n";
    return out.str();
}
