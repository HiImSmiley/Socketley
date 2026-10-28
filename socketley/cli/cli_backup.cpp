// `socketley export --full <file>` and `socketley restore <file>`: this machine's socketley whole, its setup and its
// data, in one tar archive, and put back from one on a machine whose daemon is stopped.
#include "cli.h"

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "../daemon/ipc_client.h"
#include "../shared/json/json_doc.h"
#include "../shared/persist/paths.h"
#include "../shared/persist/read_file.h"
#include "../shared/persist/tar_archive.h"

namespace fs = std::filesystem;
using socketley::json::jvalue;

namespace
{

// Where an archive's own files are, apart from the paths it puts back.
constexpr std::string_view meta_dir = "socketley-backup/";

std::string mib(uint64_t bytes)
{
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.1f MiB", static_cast<double>(bytes) / (1u << 20));
    return buf;
}

// The name a path has in the archive: itself without its leading slash.
std::string member_of(const fs::path& p)
{
    std::string s = p.lexically_normal().string();
    while (!s.empty() && s.front() == '/')
        s.erase(0, 1);
    while (!s.empty() && s.back() == '/')
        s.pop_back();
    return s;
}

bool under(const fs::path& p, const fs::path& root)
{
    const std::string a = p.lexically_normal().string(), b = root.lexically_normal().string();
    return a == b || (a.size() > b.size() && a.compare(0, b.size(), b) == 0 && (b.back() == '/' || a[b.size()] == '/'));
}

// A directory no runtime's data is, which an archive never takes whole.
bool too_broad(const fs::path& p)
{
    static const std::set<std::string> system = {"/", "/etc", "/usr", "/var", "/home", "/root", "/bin", "/sbin", "/lib",
                                                 "/lib64", "/opt", "/srv", "/tmp", "/var/lib", "/var/tmp", "/boot",
                                                 "/dev", "/proc", "/sys", "/run", "/mnt", "/media"};
    return system.count(p.lexically_normal().string()) > 0;
}

// `p` normal and without a trailing slash, so "/etc/" is compared as "/etc".
fs::path clean(const fs::path& p)
{
    std::string s = p.lexically_normal().string();
    while (s.size() > 1 && s.back() == '/')
        s.pop_back();
    return s;
}

// The places restore leaves to the system where an archive names them outside this machine's state and config: an
// archive may say any path, and what it says is no authority over the system's files nor over a user's own setup.
struct system_files
{
    std::vector<fs::path> homes;

    system_files()
    {
        if (const char* h = std::getenv("HOME"); h && h[0] == '/')
            homes.push_back(clean(h));
        ::setpwent();
        while (const passwd* pw = ::getpwent())
            if (pw->pw_dir && pw->pw_dir[0] == '/')
                homes.push_back(clean(pw->pw_dir));
        ::endpwent();
        std::erase_if(homes, [](const fs::path& h) { return too_broad(h); });
    }

    // Why `named` is one of them, or empty; asked of the path as named and, with `resolve`, as its links resolve.
    std::string why(const fs::path& named, bool resolve) const
    {
        static constexpr std::string_view system[] = {
            "/etc",    "/usr",       "/bin",          "/sbin",        "/lib",         "/lib32",           "/lib64",
            "/libx32", "/boot",      "/root",         "/dev",         "/proc",        "/sys",             "/run",
            "/var/run", "/var/spool", "/var/lib/dpkg", "/var/lib/rpm", "/var/lib/apt", "/var/lib/systemd", "/var/lib/polkit-1"};
        std::error_code ec;
        const fs::path real = resolve ? fs::weakly_canonical(named, ec) : named;
        for (const fs::path& p : {clean(named), ec ? clean(named) : clean(real)})
        {
            if (too_broad(p))
                return "a system directory";
            for (const std::string_view s : system)
                if (under(p, fs::path(s)))
                    return "under " + std::string(s);
            // A home's hidden files are its user's shell, ssh and desktop setup, not a runtime's data.
            const std::vector<fs::path> parts(p.begin(), p.end());
            if (parts.size() > 3 && parts[1] == "home" && parts[3].string().starts_with("."))
                return "a hidden file of a home";
            for (const fs::path& h : homes)
                if (p != h && under(p, h) && p.lexically_relative(h).begin()->string().starts_with("."))
                    return "a hidden file of a home";
        }
        return {};
    }
};

struct runtime_file
{
    std::string name, type;
    jvalue state;
};

// Every runtime the state directory keeps, read from its own file, which holds what `show` shows.
std::vector<runtime_file> runtimes_of(const fs::path& state)
{
    std::vector<runtime_file> out;
    std::error_code ec;
    for (const auto& f : fs::directory_iterator(state, ec))
    {
        if (!f.is_regular_file(ec) || f.path().extension() != ".json")
            continue;
        std::string text;
        runtime_file r;
        if (!socketley::read_file(f.path().string(), text) || !socketley::json::json_reader(text).document(r.state))
            continue;
        r.type = std::string(socketley::json::string_of(r.state, "type"));
        r.name = std::string(socketley::json::string_of(r.state, "name"));
        if (r.name.empty())
            r.name = f.path().stem().string();
        if (!r.type.empty())
            out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(), [](const runtime_file& a, const runtime_file& b) { return a.name < b.name; });
    return out;
}

// What a runtime reads and writes outside the state directory, from the paths its settings name: a storage's
// buckets, a cache's file and its journal, a script, a zone, a certificate, a file of tokens. Not its log, what it
// writes as output, its backups' directory, nor the files a sync runtime carries, which are the user's own.
void outside_paths(const runtime_file& r, std::set<std::string>& take, std::set<std::string>& leave)
{
    for (const auto& [key, v] : r.state.members)
    {
        if (v.k != jvalue::kind::string)
            continue;
        const bool skipped = key.find("log") != std::string::npos || key.find("write") != std::string::npos ||
                             key == "backup_dir" || (r.type == "sync" && key == "dir");
        for (std::string_view rest = v.s; !rest.empty();)
        {
            const size_t comma = rest.find(',');
            std::string_view one = rest.substr(0, comma);
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            if (one.find("://") != std::string_view::npos)
                continue;
            // A user and a file of passwords, "name:/path".
            if (const size_t at = one.find(":/"); at != std::string_view::npos && !one.starts_with("/"))
                one = one.substr(at + 1);
            if (!one.starts_with("/"))
                continue;
            std::error_code ec;
            const fs::path p = fs::path(one).lexically_normal();
            // The files beside it that share its name, as a cache's journal and its shards' files do, there even
            // before the file itself is first written.
            std::vector<std::string> beside;
            if (!fs::is_directory(p, ec))
                for (const auto& f : fs::directory_iterator(p.parent_path(), ec))
                    if (f.path().filename().string().starts_with(p.filename().string() + "."))
                        beside.push_back(f.path().string());
            if (!fs::exists(p, ec) && beside.empty())
                continue;
            if (skipped || too_broad(p))
            {
                leave.insert(p.string() + " (" + r.name + "'s " + key + ")");
                continue;
            }
            if (fs::exists(p, ec))
                take.insert(p.string());
            take.insert(beside.begin(), beside.end());
        }
    }
}

struct writer_job
{
    socketley::tar_writer tar;
    std::set<std::string> done;
    std::string why;
};

// `p` and, for a directory, what it holds, into the archive, but what `skip` says to pass over.
bool add_tree(writer_job& j, const fs::path& p, const std::function<bool(const fs::path&)>& skip)
{
    std::error_code ec;
    const auto one = [&](const fs::path& f) -> bool {
        const std::string name = member_of(f);
        if (name.empty() || !j.done.insert(name).second || skip(f))
            return true;
        struct stat st{};
        if (::lstat(f.c_str(), &st) != 0)
            return true;
        if (S_ISDIR(st.st_mode))
            return j.tar.add_dir(name, st, j.why);
        if (S_ISLNK(st.st_mode))
        {
            std::error_code lec;
            const fs::path target = fs::read_symlink(f, lec);
            return lec ? true : j.tar.add_link(name, target.string(), st, j.why);
        }
        // Sockets, pipes and devices are no data.
        if (!S_ISREG(st.st_mode))
            return true;
        return j.tar.add_file(name, f.string(), j.why);
    };
    if (!one(p))
        return false;
    if (!fs::is_directory(p, ec))
        return true;
    for (auto it = fs::recursive_directory_iterator(p, fs::directory_options::none, ec); !ec && it != fs::end(it);
         it.increment(ec))
    {
        if (skip(it->path()))
        {
            if (it->is_directory(ec) && !it->is_symlink(ec))
                it.disable_recursion_pending();
            continue;
        }
        if (!one(it->path()))
            return false;
    }
    if (ec)
    {
        j.why = p.string() + " could not be read whole: " + ec.message();
        return false;
    }
    return true;
}

bool daemon_running()
{
    std::string out;
    return ipc_send("ping", out) >= 0;
}

// The runtimes the daemon is running now, by name.
std::set<std::string> running_runtimes()
{
    std::set<std::string> out;
    std::string listing;
    if (ipc_send("ls --json", listing) != 0)
        return out;
    socketley::json::json_policy any;
    any.object_root = false;
    while (!listing.empty() && std::isspace(static_cast<unsigned char>(listing.back())))
        listing.pop_back();
    jvalue all;
    if (!socketley::json::json_reader(listing, any).document(all))
        return out;
    for (const auto& r : all.items)
        if (socketley::json::string_of(r, "status") == "running")
            out.insert(std::string(socketley::json::string_of(r, "name")));
    return out;
}

}   // namespace

// `socketley export --full <file> [--compress fast|best|none] [--threads N]`.
int cli_export_full(int argc, char** argv)
{
    std::string file;
    socketley::tar_writer::compression c = socketley::tar_writer::compression::fast;
    // As many compress as the CPUs this process may run on, up to 64, which hold 128 pieces of a MiB at once.
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    unsigned threads =
        ::sched_getaffinity(0, sizeof(cpus), &cpus) == 0 ? std::clamp(static_cast<unsigned>(CPU_COUNT(&cpus)), 1u, 64u) : 1;
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--threads" && i + 1 < argc)
        {
            const std::string_view v = argv[++i];
            unsigned n = 0;
            const auto [end, err] = std::from_chars(v.data(), v.data() + v.size(), n);
            if (err != std::errc() || end != v.data() + v.size() || n < 1 || n > 64)
            {
                std::cout << "--threads takes a number from 1 to 64\n";
                return 1;
            }
            threads = n;
        }
        else if (a == "--compress" && i + 1 < argc)
        {
            const std::string_view v = argv[++i];
            if (v == "fast")
                c = socketley::tar_writer::compression::fast;
            else if (v == "best")
                c = socketley::tar_writer::compression::best;
            else if (v == "none")
                c = socketley::tar_writer::compression::none;
            else
            {
                std::cout << "--compress takes fast, best or none\n";
                return 1;
            }
        }
        else if (file.empty() && !a.starts_with("--"))
            file = std::string(a);
        else
        {
            std::cerr << "usage: socketley export --full <file> [--compress fast|best|none] [--threads N]\n";
            return 1;
        }
    }
    if (file.empty())
    {
        std::cerr << "usage: socketley export --full <file> [--compress fast|best|none] [--threads N]\n";
        return 1;
    }
    std::error_code ec;
    const fs::path out = fs::absolute(file, ec);
    if (fs::exists(out, ec))
    {
        std::cout << out.string() << " exists: export writes a new archive\n";
        return 1;
    }
    const socketley_paths paths = socketley_paths::resolve();
    const fs::path state = paths.state_dir;
    if (::access(state.c_str(), R_OK | X_OK) != 0)
    {
        std::cout << "the state directory " << state.string() << " cannot be read: run as root or as the daemon's user\n";
        return 1;
    }
    if (under(out, state))
    {
        std::cout << "the archive is written outside the state directory it holds\n";
        return 1;
    }
    const bool running = daemon_running();
    const std::vector<runtime_file> runtimes = runtimes_of(state);

    // A scratch directory the daemon may write into, which the archive passes over and which goes after.
    const fs::path scratch = state / (".export-" + std::to_string(::getpid()));
    fs::create_directories(scratch, ec);
    struct stat sst{};
    if (::stat(state.c_str(), &sst) == 0 && ::geteuid() == 0 && ::chown(scratch.c_str(), sst.st_uid, sst.st_gid) != 0) {}
    const auto cleanup = [&] {
        std::error_code e;
        fs::remove_all(scratch, e);
    };

    // The setup as Lua, which the daemon shows, beside the data: for a reader, and for a machine laid out otherwise.
    bool setup = false;
    if (running)
    {
        std::string dir = (scratch / "setup").string();
        char prog[] = "socketley", verb[] = "export";
        std::vector<char> d(dir.begin(), dir.end());
        d.push_back('\0');
        char* av[] = {prog, verb, d.data(), nullptr};
        setup = cli_export(3, av) == 0;
        if (!setup)
            std::cout << "the Lua setup could not be written beside the data; the archive holds the state, which restore "
                         "puts back\n";
    }
    // A db runtime's documents as its backup writes them while it serves, which a copy of files being written is not.
    std::set<std::string> db_backed;
    const std::set<std::string> live = running ? running_runtimes() : std::set<std::string>{};
    for (const auto& r : runtimes)
    {
        if (r.type != "db" || !live.count(r.name))
            continue;
        const std::string to = (scratch / ("db-" + r.name + ".dbbackup")).string();
        std::vector<char> n(r.name.begin(), r.name.end()), t(to.begin(), to.end());
        n.push_back('\0');
        t.push_back('\0');
        char prog[] = "socketley", verb[] = "db-backup";
        char* av[] = {prog, verb, n.data(), t.data(), nullptr};
        if (cli_db_backup(4, av) == 0 && fs::exists(to, ec))
            db_backed.insert(r.name);
    }

    std::set<std::string> take, leave;
    for (const auto& r : runtimes)
        outside_paths(r, take, leave);
    const fs::path config_dir = paths.config_path.parent_path();
    const bool with_config = !config_dir.empty() && fs::is_directory(config_dir, ec) && !under(config_dir, state) &&
                             !too_broad(config_dir);
    // Roots inside others are theirs.
    std::vector<std::string> roots = {state.string()};
    if (with_config)
        roots.push_back(config_dir.string());
    for (const auto& p : take)
        if (std::none_of(roots.begin(), roots.end(), [&](const std::string& r) { return under(p, r); }))
            roots.push_back(p);

    jvalue manifest;
    manifest.k = jvalue::kind::object;
    const auto put = [&](const std::string& k, jvalue v) { manifest.members.emplace_back(k, std::move(v)); };
    const auto str = [](std::string s) {
        jvalue v;
        v.k = jvalue::kind::string;
        v.s = std::move(s);
        return v;
    };
    const auto list = [&](const auto& items) {
        jvalue v;
        v.k = jvalue::kind::array;
        for (const auto& i : items)
            v.items.push_back(str(i));
        return v;
    };
    char date[32];
    const std::time_t now = std::time(nullptr);
    std::strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
    char host[256] = {};
    ::gethostname(host, sizeof host - 1);
    jvalue fmt;
    fmt.k = jvalue::kind::number;
    fmt.s = "1";
    put("format", fmt);
    put("socketley", str(SOCKETLEY_VERSION));
    put("created", str(date));
    put("host", str(host));
    put("state_dir", str(state.string()));
    put("roots", list(roots));
    std::vector<std::string> names;
    for (const auto& r : runtimes)
        names.push_back(r.name + " (" + r.type + ")");
    put("runtimes", list(names));
    put("db_from_backup", list(db_backed));
    put("not_included", list(leave));
    jvalue s;
    s.k = jvalue::kind::boolean;
    s.b = setup;
    put("setup", s);

    const fs::path partial = out.string() + ".partial";
    writer_job j;
    bool ok = j.tar.open(partial.string(), c, j.why, threads) &&
              j.tar.add_bytes(std::string(meta_dir) + "manifest.json", socketley::json::written(manifest) + "\n", 0600, j.why);
    if (ok && setup)
    {
        const fs::path sdir = scratch / "setup";
        for (auto it = fs::recursive_directory_iterator(sdir, ec); ok && !ec && it != fs::end(it); it.increment(ec))
            if (it->is_regular_file(ec))
                ok = j.tar.add_file(std::string(meta_dir) + "setup/" + fs::relative(it->path(), sdir, ec).string(),
                                    it->path().string(), j.why);
    }
    // The state, but its command history, what export and restore leave behind, and the live files of a db whose
    // backup stands in for them.
    const auto skip_state = [&](const fs::path& p) {
        const std::string name = p.filename().string();
        if (p == partial || under(p, scratch) || name == ".history" || name.ends_with(".before-restore") || name.starts_with(".export-") ||
            name.ends_with(".restore-tmp"))
            return true;
        for (const auto& d : db_backed)
            if (under(p, state / "db" / d) && p != state / "db" / d)
                return true;
        return false;
    };
    for (const auto& root : roots)
        if (ok)
            ok = add_tree(j, root, skip_state);
    for (const auto& d : db_backed)
        if (ok)
            ok = j.tar.add_file(member_of(state / "db" / d / "seg-00000001.log"),
                                (scratch / ("db-" + d + ".dbbackup")).string(), j.why);
    ok = ok && j.tar.close(j.why);
    cleanup();
    if (!ok)
    {
        fs::remove(partial, ec);
        std::cout << "export: " << j.why << "\n";
        return 2;
    }
    fs::rename(partial, out, ec);
    if (ec)
    {
        std::cout << "export: " << out.string() << " could not be written: " << ec.message() << "\n";
        return 2;
    }
    std::cout << "exported " << j.tar.files() << " files of " << runtimes.size() << " runtimes, " << mib(j.tar.raw_bytes())
              << ", into " << out.string() << " (" << mib(j.tar.written_bytes()) << ")\n";
    if (!running)
        std::cout << "the daemon is not running: the archive holds what its files say, and no Lua setup\n";
    for (const auto& l : leave)
        std::cout << "not included: " << l << "\n";
    return 0;
}

// `socketley restore <file> [--force]`: what an archive holds put back where it was, owned as it was, while the daemon
// is stopped; started again, the daemon brings every runtime back from its state.
int cli_restore(int argc, char** argv)
{
    std::string file;
    bool force = false;
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--force")
            force = true;
        else if (file.empty() && !a.starts_with("--"))
            file = std::string(a);
        else
        {
            std::cerr << "usage: socketley restore <file> [--force]\n";
            return 1;
        }
    }
    if (file.empty())
    {
        std::cerr << "usage: socketley restore <file> [--force]\n";
        return 1;
    }
    if (daemon_running())
    {
        std::cout << "the daemon is running: stop it first (systemctl stop socketley), restore, then start it\n";
        return 1;
    }
    socketley::tar_reader tar;
    std::string why;
    if (!tar.open(file, why))
    {
        std::cout << "restore: " << why << "\n";
        return 1;
    }
    socketley::tar_reader::entry e;
    std::string text;
    if (tar.next(e, why) != socketley::tar_reader::status::entry || e.name != std::string(meta_dir) + "manifest.json" ||
        e.size > (1u << 20) || !tar.read(text, static_cast<size_t>(e.size), why))
    {
        std::cout << "restore: " << file << " is no archive socketley export --full wrote" << (why.empty() ? "" : ": " + why)
                  << "\n";
        return 1;
    }
    jvalue manifest;
    if (!socketley::json::json_reader(text).document(manifest))
    {
        std::cout << "restore: the archive's manifest does not read\n";
        return 1;
    }
    // This machine's state and config directories are restore's to write; what else the manifest names, only where it
    // is no system's.
    const socketley_paths here = socketley_paths::resolve();
    const fs::path state = clean(here.state_dir);
    const fs::path config_dir = here.config_path.empty() ? fs::path() : clean(here.config_path.parent_path());
    const auto local = [&](const fs::path& p) {
        return (!state.empty() && under(p, state)) ||
               (!config_dir.empty() && !too_broad(config_dir) && under(p, config_dir));
    };
    std::error_code ec;
    if (!force && !runtimes_of(state).empty())
    {
        std::cout << state.string() << " holds runtimes already: --force puts the archive's over them\n";
        return 1;
    }
    const system_files theirs;
    // A root is asked as its links resolve; what lies below one is held to no link by the walk further down.
    const auto left_to_system = [&](const fs::path& p, bool resolve) {
        return local(p) ? std::string() : theirs.why(p, resolve);
    };
    const auto say_left = [](const fs::path& p, const std::string& no) {
        std::cout << "not restored: " << p.string() << ", " << no << ", which restore leaves to the system; tar takes it "
                  << "out of the archive by hand\n";
    };
    std::vector<fs::path> roots, refused;
    if (const jvalue* r = socketley::json::member(manifest, "roots"); r && r->k == jvalue::kind::array)
        for (const auto& v : r->items)
        {
            if (v.k != jvalue::kind::string || !v.s.starts_with("/") || too_broad(clean(v.s)))
                continue;
            const fs::path p = clean(v.s);
            roots.push_back(p);
            if (const std::string no = left_to_system(p, true); !no.empty())
            {
                refused.push_back(p);
                say_left(p, no);
            }
        }
    const bool root_user = ::geteuid() == 0;
    // Outside the state and config, what the archive says root owns is written as the daemon's user's instead.
    struct stat state_owner{};
    if (::stat(state.c_str(), &state_owner) != 0) {}
    uint64_t files = 0, bytes = 0;
    // A directory takes its recorded mode once everything under it is written, deepest first.
    std::vector<std::pair<fs::path, mode_t>> dir_modes;
    const auto finish_dirs = [&]() {
        for (auto d = dir_modes.rbegin(); d != dir_modes.rend(); ++d)
            if (::chmod(d->first.c_str(), d->second) != 0) {}
    };
    for (;;)
    {
        const auto st = tar.next(e, why);
        if (st == socketley::tar_reader::status::end)
            break;
        if (st == socketley::tar_reader::status::bad)
        {
            std::cout << "restore: " << why << "; what came before is in place\n";
            return 2;
        }
        if (e.name.starts_with(meta_dir))
            continue;
        const fs::path target = fs::path("/") / e.name;
        const bool dotdot = std::any_of(target.begin(), target.end(), [](const fs::path& part) { return part == ".."; });
        if (dotdot || std::none_of(roots.begin(), roots.end(), [&](const fs::path& r) { return under(target, r); }))
        {
            std::cout << "restore: the archive names " << target.string() << ", outside what its manifest says it holds\n";
            return 2;
        }
        // Export passes this name over, and a link at it is what a later file of the same name would be written through.
        if (e.name.ends_with(".restore-tmp"))
        {
            std::cout << "restore: the archive names " << target.string() << ", which no archive export writes holds\n";
            return 2;
        }
        if (std::any_of(refused.begin(), refused.end(), [&](const fs::path& r) { return under(target, r); }))
            continue;
        if (const std::string no = left_to_system(target, false); !no.empty())
        {
            say_left(target, no);
            continue;
        }
        // A link made by this archive must not carry a later entry out of the root it is under.
        const fs::path& root_of = *std::find_if(roots.begin(), roots.end(), [&](const fs::path& r) { return under(target, r); });
        fs::path walked = root_of;
        bool through_link = false;
        const fs::path base = (e.type == '5' ? target : target.parent_path()).lexically_normal();
        const fs::path below = under(base, root_of) ? base.lexically_relative(root_of.lexically_normal()) : fs::path();
        for (const auto& part : below)
        {
            if (part == "." || part.empty())
                continue;
            walked /= part;
            struct stat ls{};
            if (::lstat(walked.c_str(), &ls) == 0 && S_ISLNK(ls.st_mode))
            {
                through_link = true;
                break;
            }
        }
        if (through_link)
        {
            std::cout << "restore: " << target.string() << " lies behind a symlink, which an archive may not write through\n";
            return 2;
        }
        uid_t uid = e.uid;
        gid_t gid = e.gid;
        if (const passwd* pw = e.uname.empty() ? nullptr : ::getpwnam(e.uname.c_str()))
            uid = pw->pw_uid;
        if (const group* gr = e.gname.empty() ? nullptr : ::getgrnam(e.gname.c_str()))
            gid = gr->gr_gid;
        if (root_user && !local(target))
        {
            if (uid == 0)
                uid = state_owner.st_uid;
            if (gid == 0)
                gid = state_owner.st_gid;
        }
        // No archive makes a file that runs as its owner or its group.
        const mode_t mode = static_cast<mode_t>(e.mode) & 01777;
        if (e.type == '5')
        {
            fs::create_directories(target, ec);
            if (::chmod(target.c_str(), mode | 0700) != 0) {}
            if (root_user && ::lchown(target.c_str(), uid, gid) != 0) {}
            dir_modes.emplace_back(target, mode);
            continue;
        }
        fs::create_directories(target.parent_path(), ec);
        if (e.type == '2')
        {
            fs::remove(target, ec);
            if (::symlink(e.link.c_str(), target.c_str()) != 0)
            {
                std::cout << "restore: " << target.string() << " could not be made: " << std::strerror(errno) << "\n";
                return 2;
            }
            if (root_user && ::lchown(target.c_str(), uid, gid) != 0) {}
            continue;
        }
        if (e.type != '0' && e.type != '7')
            continue;
        // Written beside it and moved over it whole, so a restore cut short leaves no file half written.
        const std::string tmp = target.string() + ".restore-tmp";
        // Made new, never through what a restore cut short or anyone else left at the name.
        if (::unlink(tmp.c_str()) != 0) {}
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0)
        {
            std::cout << "restore: " << target.string() << " could not be written: " << std::strerror(errno) << "\n";
            return 2;
        }
        bool written = true;
        while (written && tar.left() > 0)
        {
            std::string chunk;
            if (!tar.read(chunk, 1u << 20, why))
            {
                std::cout << "restore: " << why << "\n";
                ::close(fd);
                fs::remove(tmp, ec);
                return 2;
            }
            for (std::string_view rest = chunk; written && !rest.empty();)
            {
                const ssize_t w = ::write(fd, rest.data(), rest.size());
                if (w < 0 && errno == EINTR)
                    continue;
                written = w > 0;
                if (written)
                    rest.remove_prefix(static_cast<size_t>(w));
            }
        }
        if (::fchmod(fd, mode) != 0) {}
        if (root_user && ::fchown(fd, uid, gid) != 0) {}
        const timespec times[2] = {{e.mtime, 0}, {e.mtime, 0}};
        if (::futimens(fd, times) != 0) {}
        written = ::fsync(fd) == 0 && written;
        written = ::close(fd) == 0 && written;
        if (!written || ::rename(tmp.c_str(), target.c_str()) != 0)
        {
            std::cout << "restore: " << target.string() << " could not be written: " << std::strerror(errno) << "\n";
            fs::remove(tmp, ec);
            return 2;
        }
        ++files;
        bytes += e.size;
    }
    finish_dirs();
    std::cout << "restored " << files << " files, " << mib(bytes) << ", from " << socketley::json::string_of(manifest, "host")
              << " of " << socketley::json::string_of(manifest, "created")
              << "; start the daemon (systemctl start socketley) and its runtimes come back as they were\n";
    return 0;
}
