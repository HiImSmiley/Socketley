// `socketley login` and `socketley logout`: a person signed in at an idp runtime by the device grant (RFC 8628),
// and the tokens it gives kept for the commands that act as that person.
#include "cli.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

#include "../shared/http/https_client.h"
#include "../shared/http/url.h"
#include "../shared/json/json_doc.h"
#include "../shared/json/json_escape.h"
#include "../shared/loop/blocking_write.h"
#include "../shared/persist/read_file.h"
#include "../shared/util/ascii.h"
#include "../runtime/idp/idp_logic.h"

namespace fs = std::filesystem;
using socketley::json::json_reader;
using socketley::json::jvalue;
using socketley::json::string_of;
using socketley::json::int_of;

namespace
{

int64_t now_s()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// `auth.example.org` or a whole address, as the issuer the provider names itself by.
std::string issuer_of(std::string_view given)
{
    std::string s(given);
    while (!s.empty() && s.back() == '/')
        s.pop_back();
    if (!s.starts_with("https://") && !s.starts_with("http://"))
        s = "https://" + s;
    return s;
}

// Where a person's tokens at `issuer` are kept: one file per provider, readable by its owner alone.
fs::path token_path(const std::string& issuer)
{
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    const char* home = std::getenv("HOME");
    fs::path dir = xdg && *xdg ? fs::path(xdg) : fs::path(home ? home : ".") / ".config";
    std::string name;
    for (const char c : issuer.substr(issuer.find("://") + 3))
        name += std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' ? c : '_';
    return dir / "socketley" / "tokens" / (name + ".json");
}

struct kept
{
    std::string issuer;
    std::string client_id;
    std::string access_token;
    std::string refresh_token;
    int64_t expires{0};
};

bool write_kept(const kept& k, std::string& err)
{
    const fs::path p = token_path(k.issuer);
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    fs::permissions(p.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);
    const std::string text = "{\"issuer\":" + socketley::json::quote(k.issuer) + ",\"client_id\":" +
                             socketley::json::quote(k.client_id) + ",\"access_token\":" +
                             socketley::json::quote(k.access_token) + ",\"refresh_token\":" +
                             socketley::json::quote(k.refresh_token) + ",\"expires\":" + std::to_string(k.expires) +
                             "}\n";
    // Written beside and renamed over, so a reader never sees half of it.
    const std::string tmp = p.string() + ".new." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, text.data(), text.size()) && ::fsync(fd) == 0;
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), p.c_str()) != 0)
    {
        ::unlink(tmp.c_str());
        err = "the tokens could not be kept in " + p.string();
        return false;
    }
    return true;
}

bool read_kept(const std::string& issuer, kept& k)
{
    std::string text;
    if (!socketley::read_file(token_path(issuer).string(), text, {.missing_ok = true}, nullptr) || text.empty())
        return false;
    jvalue d;
    if (!json_reader(text).document(d))
        return false;
    k.issuer.assign(string_of(d, "issuer"));
    k.client_id.assign(string_of(d, "client_id"));
    k.access_token.assign(string_of(d, "access_token"));
    k.refresh_token.assign(string_of(d, "refresh_token"));
    k.expires = int_of(d, "expires");
    return k.issuer == issuer && !k.access_token.empty();
}

// A JSON answer from the provider: true for a document, whatever its status.
bool ask(https_client::client& h, const std::string& url, std::string_view form, int& status, jvalue& doc,
         std::string& err)
{
    https_client::reply r;
    if (!h.request(form.empty() ? "GET" : "POST", url, form.empty() ? std::string_view() : "application/x-www-form-urlencoded",
                   form, r, err, 30, 1 << 20))
        return false;
    status = r.status;
    if (!json_reader(r.body).document(doc))
    {
        err = url + " answered " + std::to_string(r.status) + " with no JSON document";
        return false;
    }
    return true;
}

std::string form_value(std::string_view v)
{
    return socketley::http::url_encode(v, false);
}

// The provider's token endpoint and, when it serves one, its device endpoint, from its discovery document.
bool discover(https_client::client& h, const std::string& issuer, std::string& token_url, std::string& device_url,
              std::string& err)
{
    int status = 0;
    jvalue d;
    if (!ask(h, issuer + "/.well-known/openid-configuration", {}, status, d, err))
        return false;
    if (status != 200 || string_of(d, "issuer") != issuer)
    {
        err = issuer + " is not an OpenID provider by that name";
        return false;
    }
    token_url.assign(string_of(d, "token_endpoint"));
    device_url.assign(string_of(d, "device_authorization_endpoint"));
    return !token_url.empty();
}

// The tokens of a token endpoint's answer kept as `k`'s, the refresh token kept when none came with them, and
// written to disk unless `keep` is false.
bool take_tokens(const jvalue& d, kept& k, std::string& err, bool keep = true)
{
    const std::string_view access = string_of(d, "access_token");
    if (access.empty())
    {
        err = "the provider gave no access token";
        return false;
    }
    k.access_token.assign(access);
    if (const std::string_view r = string_of(d, "refresh_token"); !r.empty())
        k.refresh_token.assign(r);
    k.expires = now_s() + int_of(d, "expires_in", 3600);
    return !keep || write_kept(k, err);
}

// The device grant: a code shown here and allowed in a browser, its tokens in `k`, kept on disk only when `keep`.
int device_sign_in(const std::string& given, const std::string& client, bool keep, kept& k)
{
    const std::string issuer = issuer_of(given);
    https_client::client h;
    std::string err, token_url, device_url;
    if (!h.init(err) || !discover(h, issuer, token_url, device_url, err))
    {
        std::cout << socketley::ascii::printable(err) << "\n";
        return 2;
    }
    if (device_url.empty())
    {
        std::cout << issuer << " offers no device sign-in\n";
        return 2;
    }
    int status = 0;
    jvalue d;
    // A sign-in not kept asks for no refresh token, so nothing outlives the access token's hour.
    const std::string scope = keep ? "openid offline_access" : "openid";
    if (!ask(h, device_url, "client_id=" + form_value(client) + "&scope=" + form_value(scope), status, d, err))
    {
        std::cout << socketley::ascii::printable(err) << "\n";
        return 2;
    }
    if (status != 200)
    {
        std::cout << issuer << " refused the sign-in: " << socketley::ascii::printable(string_of(d, "error_description"))
                  << "\n";
        return 1;
    }
    const std::string device_code(string_of(d, "device_code"));
    const std::string user_code(string_of(d, "user_code"));
    const std::string page(string_of(d, "verification_uri_complete").empty() ? string_of(d, "verification_uri")
                                                                              : string_of(d, "verification_uri_complete"));
    int64_t interval = std::max<int64_t>(int_of(d, "interval", 5), 1);
    const int64_t until = now_s() + int_of(d, "expires_in", 600);
    // The page and code go out with no control character, so neither can show the person another page than it names.
    std::cout << "Open " << socketley::ascii::printable(page) << "\nand allow the code "
              << socketley::ascii::printable(user_code) << "\n" << std::flush;

    k.issuer = issuer;
    k.client_id = client;
    while (now_s() < until)
    {
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        if (!ask(h, token_url, "grant_type=" + form_value("urn:ietf:params:oauth:grant-type:device_code") +
                                   "&client_id=" + form_value(client) + "&device_code=" + form_value(device_code),
                 status, d, err))
        {
            std::cout << socketley::ascii::printable(err) << "\n";
            return 2;
        }
        if (status == 200)
        {
            if (!take_tokens(d, k, err, keep))
            {
                std::cout << socketley::ascii::printable(err) << "\n";
                return 2;
            }
            return 0;
        }
        const std::string_view e = string_of(d, "error");
        if (e == "authorization_pending")
            continue;
        if (e == "slow_down")
        {
            interval += 5;
            continue;
        }
        std::cout << (e == "access_denied" ? std::string("the code was refused")
                                           : e == "expired_token" ? std::string("the code expired")
                                                                  : socketley::ascii::printable(string_of(d, "error_description")))
                  << "\n";
        return 1;
    }
    std::cout << "the code expired before it was allowed\n";
    return 1;
}

}   // namespace

int cli_sign_in_once(const std::string& given, std::string& token)
{
    kept k;
    const int rc = device_sign_in(given, std::string(socketley::idp::cli_client), false, k);
    token = rc == 0 ? k.access_token : std::string();
    return rc;
}

bool cli_access_token(const std::string& given, std::string& token, std::string& err)
{
    const std::string issuer = issuer_of(given);
    kept k;
    if (!read_kept(issuer, k))
    {
        err = "not signed in at " + issuer + "; run `socketley login " + std::string(given) + "`";
        return false;
    }
    // A minute's margin, so the token does not run out on its way.
    if (k.expires > now_s() + 60)
    {
        token = k.access_token;
        return true;
    }
    https_client::client h;
    std::string token_url, device_url;
    if (k.refresh_token.empty() || !h.init(err) || !discover(h, issuer, token_url, device_url, err))
    {
        if (err.empty())
            err = "the sign-in at " + issuer + " has run out; run `socketley login " + std::string(given) + "`";
        return false;
    }
    int status = 0;
    jvalue d;
    if (!ask(h, token_url, "grant_type=refresh_token&client_id=" + form_value(k.client_id) + "&refresh_token=" +
                               form_value(k.refresh_token), status, d, err) || status != 200)
    {
        err = "the sign-in at " + issuer + " has run out; run `socketley login " + std::string(given) + "`";
        return false;
    }
    if (!take_tokens(d, k, err))
        return false;
    token = k.access_token;
    return true;
}

int cli_login(int argc, char** argv)
{
    std::string given, client(socketley::idp::cli_client);
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--client" && i + 1 < argc)
            client = argv[++i];
        else if (given.empty() && !a.starts_with("--"))
            given = a;
        else
        {
            std::cout << "usage: socketley login <idp address> [--client <id>]\n";
            return 1;
        }
    }
    if (given.empty())
    {
        std::cout << "usage: socketley login <idp address> [--client <id>]\n";
        return 1;
    }
    kept k;
    return device_sign_in(given, client, true, k);
}

int cli_logout(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cout << "usage: socketley logout <idp address>\n";
        return 1;
    }
    std::error_code ec;
    fs::remove(token_path(issuer_of(argv[2])), ec);
    return 0;
}
