// `socketley ssh-cert`, a signed-in person's SSH key certified by their idp, and `socketley idp-ssh`, the idp's SSH
// authority asked by its own machine for its public key and for host certificates.
#include "cli.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <spawn.h>
#include <sys/wait.h>
#include <vector>

#include "../daemon/ipc_client.h"
#include "../shared/http/https_client.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/http/url.h"
#include "../shared/persist/read_file.h"

namespace fs = std::filesystem;

extern char** environ;

namespace
{

std::string issuer_of(std::string_view given)
{
    std::string s(given);
    while (!s.empty() && s.back() == '/')
        s.pop_back();
    if (!s.starts_with("https://") && !s.starts_with("http://"))
        s = "https://" + s;
    return s;
}

// The first line of a file, without its line ending; empty when it cannot be read.
std::string first_line(const std::string& path)
{
    std::string text;
    if (!socketley::read_file(path, text, {}, nullptr))
        return {};
    text = text.substr(0, text.find('\n'));
    if (!text.empty() && text.back() == '\r')
        text.pop_back();
    return text;
}

// `<key>-cert.pub` beside `<key>.pub`, where ssh looks for a key's certificate.
std::string cert_path_of(const std::string& pub)
{
    const std::string base = pub.ends_with(".pub") ? pub.substr(0, pub.size() - 4) : pub;
    return base + "-cert.pub";
}

bool write_text(const std::string& path, const std::string& text)
{
    const std::string tmp = path + ".new";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!(f << text))
            return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

// A new Ed25519 key at `path` made by ssh-keygen, which writes the private key in the form ssh reads.
bool make_key(const std::string& path)
{
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    const char* args[] = {"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "socketley", "-f", path.c_str(), nullptr};
    pid_t pid = 0;
    if (posix_spawnp(&pid, "ssh-keygen", nullptr, nullptr, const_cast<char**>(args), environ) != 0)
        return false;
    int status = 0;
    return ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}   // namespace

int cli_ssh_cert(int argc, char** argv)
{
    std::string given, key;
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--key" && i + 1 < argc)
            key = cli_caller_path("--key", argv[++i]);
        else if (given.empty() && !a.starts_with("--"))
            given = a;
        else
        {
            std::cout << "usage: socketley ssh-cert <idp address> [--key <public key file>]\n";
            return 1;
        }
    }
    if (given.empty())
    {
        std::cout << "usage: socketley ssh-cert <idp address> [--key <public key file>]\n";
        return 1;
    }
    // The person's Ed25519 key when they have one, or one made for socketley alone.
    if (key.empty())
    {
        const char* home = std::getenv("HOME");
        const fs::path ssh = fs::path(home ? home : ".") / ".ssh";
        key = fs::exists(ssh / "id_ed25519.pub") ? (ssh / "id_ed25519.pub").string()
                                                  : (ssh / "socketley_ed25519.pub").string();
        if (!fs::exists(key) && !make_key(key.substr(0, key.size() - 4)))
        {
            std::cout << "no key could be made at " << key.substr(0, key.size() - 4) << " (is ssh-keygen installed?)\n";
            return 2;
        }
    }
    const std::string line = first_line(key);
    if (line.empty())
    {
        std::cout << "no public key in " << key << "\n";
        return 1;
    }
    std::string token, err;
    if (!cli_access_token(given, token, err))
    {
        std::cout << err << "\n";
        return 1;
    }
    https_client::client h;
    https_client::reply r;
    if (!h.init(err) ||
        !h.request("POST", issuer_of(given) + "/ssh/user-cert", "application/x-www-form-urlencoded",
                   "public_key=" + socketley::http::url_encode(line, false), r, err, 30, 1 << 16,
                   {{"Authorization", "Bearer " + token}}))
    {
        std::cout << err << "\n";
        return 2;
    }
    if (r.status != 200)
    {
        std::cout << issuer_of(given) << " gave no certificate: " << r.body;
        return r.status == 401 || r.status == 403 || r.status == 400 ? 1 : 2;
    }
    const std::string out = cert_path_of(key);
    if (!write_text(out, r.body))
    {
        std::cout << "the certificate could not be written to " << out << "\n";
        return 2;
    }
    return 0;
}

int cli_idp_ssh(int argc, char** argv)
{
    const auto usage = [] {
        std::cout << "usage: socketley idp-ssh <idp> ca\n"
                     "       socketley idp-ssh <idp> host-sign <public key file> --names <host,...> [--days N]\n";
        return 1;
    };
    if (argc < 4)
        return usage();
    const std::string idp = argv[2], action = argv[3];
    std::vector<std::string> fwd{argv[0], "idp-user", idp};
    if (action == "ca" && argc == 4)
        fwd.emplace_back("ssh-ca");
    else if (action == "host-sign" && argc >= 5)
    {
        const std::string pub = cli_caller_path("host-sign", argv[4]);
        std::string names, days = "365";
        for (int i = 5; i < argc; ++i)
        {
            const std::string_view a = argv[i];
            if (a == "--names" && i + 1 < argc)
                names = argv[++i];
            else if (a == "--days" && i + 1 < argc)
                days = argv[++i];
            else
                return usage();
        }
        const std::string line = first_line(pub);
        if (line.empty() || names.empty())
        {
            if (line.empty())
                std::cout << "no public key in " << pub << "\n";
            return line.empty() ? 1 : usage();
        }
        fwd.insert(fwd.end(), {"ssh-host", line, names, days});
        // The certificate goes beside the key, where sshd's HostCertificate names it.
        std::string data;
        std::string cmd = "idp-user";
        for (size_t i = 2; i < fwd.size(); ++i)
            ipc_frame::append_arg(cmd += ' ', fwd[i]);
        const int rc = ipc_send(cmd, data);
        if (rc < 0)
            return ipc_report_failure(rc);
        if (rc != 0 || data.starts_with("error: "))
        {
            std::cout << data << (data.ends_with('\n') ? "" : "\n");
            return rc ? rc : 1;
        }
        const std::string out = cert_path_of(pub);
        if (!write_text(out, data))
        {
            std::cout << "the certificate could not be written to " << out << "\n";
            return 2;
        }
        return 0;
    }
    else
        return usage();
    std::vector<char*> ptrs;
    for (auto& a : fwd)
        ptrs.push_back(a.data());
    return cli_forward(static_cast<int>(ptrs.size()), ptrs.data());
}
