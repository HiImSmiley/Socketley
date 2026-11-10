// `socketley update`: the newest release from GitHub installed in place of this one, its .deb checked against the
// SHA-256 GitHub keeps of it, and the daemon restarted, which brings back every runtime that was running.
//
//   socketley update                 the newest release, when it is newer than this one
//   socketley update --check         what is installed and what the newest release is; nothing changes
//   socketley update --list          the releases, newest first
//   socketley update --to VERSION    that release, older or newer
//   socketley update --deb FILE      a package already here, for a machine that cannot reach GitHub
//
// GITHUB_TOKEN is sent when it is set, which reads a private repository's releases.
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "cli.h"
#include "../daemon/daemon_handler.h"
#include "../shared/http/https_client.h"
#include "../shared/ipc/daemon_client.h"
#include "../shared/ipc/daemon_request.h"
#include "../shared/json/json_doc.h"

extern char** environ;

namespace
{

constexpr std::string_view k_repo = "HiImSmiley/Socketley";
constexpr const char* k_unit = "socketley";

namespace js = socketley::json;

// `argv` run with this environment; its exit status, -1 when it could not be run. `out` takes its standard output
// when given, and then its complaints go nowhere, as the question's answer is all that is wanted of it.
int run(const std::vector<std::string>& argv, std::string* out = nullptr)
{
    std::vector<char*> args;
    for (const auto& a : argv)
        args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    int pipefd[2] = {-1, -1};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (out)
    {
        if (::pipe2(pipefd, O_CLOEXEC) != 0)
            return -1;
        posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    }
    pid_t pid = 0;
    const int rc = posix_spawnp(&pid, args[0], &fa, nullptr, args.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (out)
        ::close(pipefd[1]);
    if (rc != 0)
    {
        if (out)
            ::close(pipefd[0]);
        return -1;
    }
    if (out)
    {
        char buf[4096];
        ssize_t n;
        while ((n = ::read(pipefd[0], buf, sizeof buf)) > 0 || (n < 0 && errno == EINTR))
            if (n > 0)
                out->append(buf, static_cast<size_t>(n));
        ::close(pipefd[0]);
    }
    int st = 0;
    while (::waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

std::string trimmed(std::string s)
{
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ' || s.back() == '\r'))
        s.pop_back();
    return s;
}

// A version's numbers in order, a leading v dropped; what follows a '-' or '~' marks one before the same numbers.
struct version
{
    std::vector<long> parts;
    std::string suffix;
};

version parse_version(std::string_view v)
{
    if (!v.empty() && (v.front() == 'v' || v.front() == 'V'))
        v.remove_prefix(1);
    version out;
    const size_t cut = v.find_first_of("-~+");
    if (cut != std::string_view::npos)
    {
        out.suffix = std::string(v.substr(cut + 1));
        v = v.substr(0, cut);
    }
    for (size_t at = 0; at <= v.size();)
    {
        const size_t dot = std::min(v.find('.', at), v.size());
        out.parts.push_back(std::strtol(std::string(v.substr(at, dot - at)).c_str(), nullptr, 10));
        at = dot + 1;
    }
    return out;
}

// <0, 0 or >0 as `a` is older than, the same as or newer than `b`.
int compare_versions(std::string_view a, std::string_view b)
{
    const version x = parse_version(a), y = parse_version(b);
    for (size_t i = 0; i < std::max(x.parts.size(), y.parts.size()); ++i)
    {
        const long p = i < x.parts.size() ? x.parts[i] : 0, q = i < y.parts.size() ? y.parts[i] : 0;
        if (p != q)
            return p < q ? -1 : 1;
    }
    if (x.suffix == y.suffix)
        return 0;
    if (x.suffix.empty())
        return 1;
    if (y.suffix.empty())
        return -1;
    return x.suffix < y.suffix ? -1 : 1;
}

std::string bare(std::string_view tag)
{
    if (!tag.empty() && (tag.front() == 'v' || tag.front() == 'V'))
        tag.remove_prefix(1);
    return std::string(tag);
}

// GitHub's API: GET `path`, following a redirect, with the token when there is one; the reply's status, or 0 with
// `err` when no reply came.
struct github
{
    https_client::client http;
    std::string token;

    bool init(std::string& err)
    {
        if (const char* t = std::getenv("GITHUB_TOKEN"); t && *t)
            token = t;
        return http.init(err, {}, std::string("socketley/") + SOCKETLEY_VERSION);
    }

    int get(std::string url, std::string_view accept, std::string& body, std::string& err, size_t max_bytes)
    {
        for (int hop = 0; hop < 5; ++hop)
        {
            std::vector<std::pair<std::string, std::string>> h = {{"Accept", std::string(accept)},
                                                                  {"X-GitHub-Api-Version", "2022-11-28"}};
            // Only to GitHub's own API: a redirect leads to a signed address that a token must not reach.
            if (!token.empty() && url.starts_with("https://api.github.com/"))
                h.emplace_back("Authorization", "Bearer " + token);
            https_client::reply r;
            if (!http.request("GET", url, {}, {}, r, err, 300, max_bytes, h))
                return 0;
            if (r.status == 301 || r.status == 302 || r.status == 303 || r.status == 307 || r.status == 308)
            {
                url = r.header("location");
                if (url.empty())
                {
                    err = "a redirect named no address";
                    return 0;
                }
                continue;
            }
            body = std::move(r.body);
            return r.status;
        }
        err = "more than five redirects";
        return 0;
    }

    // A release as JSON: `which` is "latest", "tags/vX" or "" for the list; false having said why.
    bool releases(const std::string& which, js::jvalue& out)
    {
        std::string body, err;
        const std::string url = "https://api.github.com/repos/" + std::string(k_repo) + "/releases" +
                                (which.empty() ? "?per_page=30" : "/" + which);
        const int st = get(url, "application/vnd.github+json", body, err, 4u << 20);
        if (st == 0)
        {
            std::cout << "GitHub could not be asked for socketley's releases: " << err << "\n";
            return false;
        }
        if (st == 404)
        {
            if (which.starts_with("tags/") && !token.empty())
                std::cout << "there is no release " << which.substr(5) << "\n";
            else
                std::cout << "GitHub has no release of " << k_repo << " to read"
                          << (token.empty() ? "; a private repository's releases need GITHUB_TOKEN" : "") << "\n";
            return false;
        }
        if (st != 200)
        {
            std::cout << "GitHub answered " << st << " for socketley's releases"
                      << (st == 401 || st == 403 ? "; check GITHUB_TOKEN, or wait out GitHub's limit" : "") << "\n";
            return false;
        }
        js::json_policy policy;
        policy.object_root = false;
        policy.max_depth = 8;
        if (!js::json_reader(body, policy).document(out))
        {
            std::cout << "GitHub's answer about socketley's releases is not JSON\n";
            return false;
        }
        return true;
    }
};

// This machine's Debian architecture, as the package names it.
std::string architecture()
{
    std::string out;
    if (run({"dpkg", "--print-architecture"}, &out) == 0 && !trimmed(out).empty())
        return trimmed(out);
    struct utsname u{};
    ::uname(&u);
    const std::string_view m = u.machine;
    return m == "x86_64" ? "amd64" : m == "aarch64" ? "arm64" : std::string(m);
}

// ID and VERSION_ID of /etc/os-release, run together as a package built for one distribution may be named.
std::string distribution()
{
    std::ifstream f("/etc/os-release");
    std::string line, id, ver;
    while (std::getline(f, line))
    {
        const auto value = [&](std::string_view key) {
            std::string v = line.substr(key.size());
            if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
                v = v.substr(1, v.size() - 2);
            return v;
        };
        if (line.starts_with("ID="))
            id = value("ID=");
        else if (line.starts_with("VERSION_ID="))
            ver = value("VERSION_ID=");
    }
    return id + ver;
}

// The release's .deb for this machine: one named for its distribution first, as install.sh picks it.
const js::jvalue* pick_asset(const js::jvalue& release, std::string& why)
{
    const js::jvalue* assets = js::member(release, "assets");
    const std::string arch = "_" + architecture() + ".deb", distro = distribution();
    const js::jvalue* first = nullptr;
    if (assets)
        for (const auto& a : assets->items)
        {
            const std::string_view name = js::string_of(a, "name");
            if (!name.ends_with(arch))
                continue;
            if (!distro.empty() && name.find(distro) != std::string_view::npos)
                return &a;
            if (!first)
                first = &a;
        }
    if (!first)
        why = "release " + std::string(js::string_of(release, "tag_name")) + " has no .deb for " + architecture() +
              "; build from a clone with scripts/install-from-source.sh";
    return first;
}

// The SHA-256 of the file at `path`, in hex; empty when it cannot be read.
std::string sha256_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    char buf[65536];
    while (f.read(buf, sizeof buf) || f.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));
    unsigned char md[32];
    unsigned int n = 0;
    EVP_DigestFinal_ex(ctx, md, &n);
    EVP_MD_CTX_free(ctx);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < n; ++i)
    {
        out += hex[md[i] >> 4];
        out += hex[md[i] & 15];
    }
    return out;
}

// The package's version, as dpkg reads it from the file.
std::string deb_version(const std::string& path)
{
    std::string out;
    if (run({"dpkg-deb", "-f", path, "Version"}, &out) != 0)
        return {};
    return trimmed(out);
}

// The version dpkg has of socketley, empty when it was not installed from a package.
std::string installed_package()
{
    std::string out;
    if (run({"dpkg-query", "-W", "-f=${Status} ${Version}", "socketley"}, &out) != 0)
        return {};
    // Installed, or left half-configured by a postinst that failed: dpkg's either way, which apt finishes.
    const std::string s = trimmed(out);
    if (!s.starts_with("install ok "))
        return {};
    return s.substr(s.rfind(' ') + 1);
}

// The package installed, the service restarted when systemd runs it, and the daemon's runtimes said.
int install_and_restart(const std::string& path, const std::string& from, const std::string& to)
{
    // Asked before, as the package stops its own service while it is replaced.
    const bool service = run({"systemctl", "is-active", "--quiet", k_unit}) == 0;
    // apt installs the dependencies a newer package added, and takes an older one when it is asked for.
    ::setenv("DEBIAN_FRONTEND", "noninteractive", 1);
    const int rc = ::access("/usr/bin/apt-get", X_OK) == 0
                       ? run({"apt-get", "install", "-y", "-qq", "--allow-downgrades", path})
                       : run({"dpkg", "-i", path});
    if (rc != 0)
    {
        std::cout << "the package did not install (exit " << rc << "); socketley " << from << " is still in place\n";
        return 2;
    }
    if (service)
    {
        if (run({"systemctl", "restart", k_unit}) != 0)
        {
            std::cout << "socketley " << to << " is installed, and the restart of its service failed: "
                         "journalctl -u socketley says why\n";
            return 2;
        }
        std::cout << "socketley " << from << " -> " << to << "; the daemon was restarted\n";
        // The runtimes it brought back, once it answers.
        for (int i = 0; i < 100; ++i)
        {
            // A release from before `ping` answers as a daemon too old to name itself, and is one all the same.
            const auto who = socketley::daemon_probe(daemon_handler::socket_path.c_str(), nullptr, 300);
            if (who == socketley::daemon_identity::daemon || who == socketley::daemon_identity::predates_ping)
            {
                std::string data;
                if (socketley::daemon_request(daemon_handler::socket_path, "ls", data) == 0)
                    std::cout << data;
                return 0;
            }
            ::usleep(100000);
        }
        std::cout << "the daemon has not answered on " << daemon_handler::socket_path << " since its restart\n";
        return 2;
    }
    std::cout << "socketley " << from << " -> " << to << "\n";
    if (socketley::daemon_probe(daemon_handler::socket_path.c_str(), nullptr, 300) == socketley::daemon_identity::daemon)
        std::cout << "a daemon systemd does not run serves " << daemon_handler::socket_path << "; restart it to run "
                  << to << "\n";
    return 0;
}

int usage()
{
    std::cout << "usage: socketley update [--check | --list | --to VERSION | --deb FILE]\n";
    return 1;
}

}   // namespace

int cli_update(int argc, char** argv)
{
    bool check = false, list = false;
    std::string to, deb;
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--check")
            check = true;
        else if (a == "--list")
            list = true;
        else if (a == "--to" && i + 1 < argc)
            to = bare(argv[++i]);
        else if (a == "--deb" && i + 1 < argc)
            deb = argv[++i];
        else
            return usage();
    }
    if ((check || list) && (!to.empty() || !deb.empty()))
        return usage();

    const std::string current = SOCKETLEY_VERSION;
    if (!deb.empty())
    {
        const std::string v = deb_version(deb);
        if (v.empty())
        {
            std::cout << deb << " is not a .deb dpkg can read\n";
            return 1;
        }
        if (::geteuid() != 0)
        {
            std::cout << "installing a package takes root: sudo socketley update --deb " << deb << "\n";
            return 1;
        }
        const std::string package = installed_package();
        if (!package.empty() && compare_versions(package, v) == 0)
        {
            std::cout << "socketley " << v << " is installed already\n";
            return 0;
        }
        return install_and_restart(deb, package.empty() ? current : package, v);
    }

    // What dpkg has is what runs, and what is compared; a build from a clone has only its own version.
    const std::string package = installed_package();
    const std::string installed = package.empty() ? current : package;

    github gh;
    std::string err;
    if (!gh.init(err))
    {
        std::cout << "no TLS to reach GitHub with: " << err << "\n";
        return 2;
    }

    if (list)
    {
        js::jvalue all;
        if (!gh.releases("", all))
            return 2;
        std::string newest;
        for (const auto& r : all.items)
        {
            if (js::member(r, "draft") && js::member(r, "draft")->b)
                continue;
            const std::string tag = bare(js::string_of(r, "tag_name"));
            const bool pre = js::member(r, "prerelease") && js::member(r, "prerelease")->b;
            if (newest.empty() && !pre)
                newest = tag;
            std::cout << tag << "  " << js::string_of(r, "published_at").substr(0, 10)
                      << (pre ? "  pre-release" : "") << (compare_versions(tag, installed) == 0 ? "  installed" : "")
                      << (tag == newest && !pre ? "  newest" : "") << "\n";
        }
        return 0;
    }

    js::jvalue release;
    if (!gh.releases(to.empty() ? "latest" : "tags/v" + to, release))
        return 2;
    const std::string tag = bare(js::string_of(release, "tag_name"));
    const int cmp = compare_versions(tag, installed);

    if (check)
    {
        if (cmp > 0)
            std::cout << "socketley " << installed << " is installed; " << tag << " is the newest release: "
                      << "sudo socketley update\n";
        else
            std::cout << "socketley " << installed << " is installed; the newest release is " << tag << "\n";
        return 0;
    }
    if (to.empty() && cmp <= 0)
    {
        std::cout << "socketley " << installed << " is installed; the newest release is " << tag << ", nothing to do\n";
        return 0;
    }
    if (!to.empty() && cmp == 0)
    {
        std::cout << "socketley " << installed << " is installed already\n";
        return 0;
    }
    // A build from a clone is not dpkg's to replace: its files are not the package's.
    if (package.empty())
    {
        std::cout << "socketley " << current << " was not installed from a release package; update the clone it was "
                     "built from with bash scripts/update.sh\n";
        return 1;
    }
    if (::geteuid() != 0)
    {
        std::cout << "socketley " << tag << " is to be installed, which takes root: sudo"
                  << (gh.token.empty() ? "" : " -E") << " socketley update" << (to.empty() ? "" : " --to " + to)
                  << "\n";
        return 1;
    }

    const js::jvalue* asset = pick_asset(release, err);
    if (!asset)
    {
        std::cout << err << "\n";
        return 2;
    }
    // GitHub keeps each asset's SHA-256; a package without one is not installed by this command.
    const std::string_view digest = js::string_of(*asset, "digest");
    if (!digest.starts_with("sha256:"))
    {
        std::cout << "release " << tag << " says no SHA-256 of " << js::string_of(*asset, "name")
                  << "; download it and install it with socketley update --deb FILE\n";
        return 2;
    }

    char dir[] = "/tmp/socketley-update.XXXXXX";
    if (!::mkdtemp(dir))
    {
        std::cout << "no directory to download into: " << std::strerror(errno) << "\n";
        return 2;
    }
    const std::string path = std::string(dir) + "/" + std::string(js::string_of(*asset, "name"));
    struct cleanup
    {
        std::string dir, file;
        ~cleanup()
        {
            ::unlink(file.c_str());
            ::rmdir(dir.c_str());
        }
    } tidy{dir, path};

    std::string body;
    const int st = gh.get(std::string(js::string_of(*asset, "url")), "application/octet-stream", body, err, 512u << 20);
    if (st != 200)
    {
        std::cout << "the download of " << js::string_of(*asset, "name") << " failed: "
                  << (st ? "GitHub answered " + std::to_string(st) : err) << "\n";
        return 2;
    }
    {
        std::ofstream f(path, std::ios::binary);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!f)
        {
            std::cout << "the download could not be written to " << path << "\n";
            return 2;
        }
    }
    if (const int64_t want = js::int_of(*asset, "size", -1); want >= 0 && static_cast<int64_t>(body.size()) != want)
    {
        std::cout << "the download of " << js::string_of(*asset, "name") << " was " << body.size()
                  << " bytes, and release " << tag << " says " << want << "; nothing was installed\n";
        return 2;
    }
    if (sha256_file(path) != digest.substr(7))
    {
        std::cout << js::string_of(*asset, "name") << " is not the file release " << tag
                  << " published: its SHA-256 differs; nothing was installed\n";
        return 2;
    }
    if (const std::string v = deb_version(path); v.empty() || compare_versions(v, tag) != 0)
    {
        std::cout << js::string_of(*asset, "name") << " says it is version " << v << ", not " << tag
                  << "; nothing was installed\n";
        return 2;
    }
    return install_and_restart(path, package, tag);
}
