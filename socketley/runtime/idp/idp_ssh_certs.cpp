#include "idp_ssh_certs.h"

#include <algorithm>
#include <charconv>
#include <filesystem>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include "../../shared/crypto/ssh_cert.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/persist/paths.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/text_list.h"

namespace socketley::idp
{

namespace
{

std::string idp_dir()
{
    return (socketley_paths::resolve().state_dir / "idp").string();
}

// The whole of `text` at `path`, by a rename, so a reader never finds half of it.
bool replace(const std::string& path, std::string_view text, mode_t mode)
{
    return socketley::replace_file(path, text, socketley::durability::data, nullptr, mode);
}

bool number(std::string_view s, uint64_t& out)
{
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && end == s.data() + s.size() && !s.empty();
}

}   // namespace

std::string ssh_certs_path(std::string_view idp)
{
    return idp_dir() + "/" + std::string(idp) + ".ssh-certs";
}

std::string ssh_krl_path(std::string_view idp)
{
    return idp_dir() + "/" + std::string(idp) + ".ssh-krl";
}

bool parse_ssh_certs(std::string_view text, std::vector<issued_cert>& out)
{
    while (!text.empty())
    {
        std::string_view line = take_item(text, '\n');
        if (trim_blanks(line).empty())
            continue;
        issued_cert c;
        const std::string_view serial = take_item(line, ' '), sub = take_item(line, ' '),
                               until = take_item(line, ' '), state = line;
        if (!number(serial, c.serial) || sub.empty() || !number(until, c.valid_before) ||
            (state != "issued" && state != "revoked"))
            return false;
        c.sub = std::string(sub);
        c.revoked = state == "revoked";
        out.push_back(std::move(c));
    }
    return true;
}

std::string render_ssh_certs(const std::vector<issued_cert>& certs)
{
    std::string out;
    for (const issued_cert& c : certs)
        out += std::to_string(c.serial) + " " + c.sub + " " + std::to_string(c.valid_before) +
               (c.revoked ? " revoked\n" : " issued\n");
    return out;
}

bool update_ssh_certs(std::string_view idp, std::string_view ca_blob, uint64_t now,
                      const std::function<void(std::vector<issued_cert>&)>& change, std::string& why)
{
    std::error_code ec;
    std::filesystem::create_directories(idp_dir(), ec);
    const std::string path = ssh_certs_path(idp);
    const int lock = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock < 0 || ::flock(lock, LOCK_EX) < 0)
    {
        if (lock >= 0)
            ::close(lock);
        why = "the SSH certificates of " + std::string(idp) + " cannot be locked";
        return false;
    }
    std::string text;
    std::vector<issued_cert> certs;
    bool ok = read_file(path, text, {.missing_ok = true}, &why) && parse_ssh_certs(text, certs);
    if (!ok && why.empty())
        why = path + " holds a line that is no certificate; it is left as it is";
    if (ok)
    {
        change(certs);
        std::erase_if(certs, [now](const issued_cert& c) { return c.valid_before <= now; });
        std::vector<uint64_t> revoked;
        for (const issued_cert& c : certs)
            if (c.revoked)
                revoked.push_back(c.serial);
        // Readable by sshd whoever it runs as, since a list of revoked serials tells nobody anything.
        ok = replace(path, render_ssh_certs(certs), 0600) &&
             replace(ssh_krl_path(idp), socketley::ssh::krl_of(ca_blob, std::move(revoked), now), 0644);
        if (!ok)
            why = "the SSH certificates of " + std::string(idp) + " or their revocation list could not be written";
    }
    ::close(lock);
    return ok;
}

}   // namespace socketley::idp
