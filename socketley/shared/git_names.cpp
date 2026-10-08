#include "git_names.h"

namespace git_names
{

bool valid_url(std::string_view url, std::string& why)
{
    std::string_view rest;
    for (std::string_view scheme : {"https://", "http://", "git://"})
        if (url.starts_with(scheme))
            rest = url.substr(scheme.size());
    if (rest.empty())
    {
        why = "a repository is fetched over https://, http:// or git://";
        return false;
    }
    if (url.size() > 512)
    {
        why = "the URL is longer than 512 characters";
        return false;
    }
    for (unsigned char c : url)
        if (c <= ' ' || c >= 0x7f || c == '\\' || c == '"' || c == '\'' || c == '`')
        {
            why = "the URL holds a character that is no URL's";
            return false;
        }
    const size_t slash = rest.find('/');
    const std::string_view host = rest.substr(0, slash);
    if (host.empty() || slash == std::string_view::npos || slash + 1 >= rest.size())
    {
        why = "the URL names a host and a repository on it";
        return false;
    }
    if (host.find('@') != std::string_view::npos)
    {
        why = "credentials do not go in the URL; a private repository is read with the account's token";
        return false;
    }
    return true;
}

bool valid_branch(std::string_view b, std::string& why)
{
    if (b == "*")
        return true;
    bool ok = !b.empty() && b.size() <= 200 && b.front() != '-' && b.front() != '/' && b.back() != '/' &&
              b.back() != '.' && b.find("..") == std::string_view::npos && b.find("//") == std::string_view::npos &&
              b.find("@{") == std::string_view::npos && !b.ends_with(".lock");
    for (unsigned char c : b)
        ok = ok && c > ' ' && c < 0x7f && c != '~' && c != '^' && c != ':' && c != '?' && c != '*' && c != '[' &&
             c != '\\';
    if (!ok)
        why = "\"" + std::string(b) + "\" is no branch name";
    return ok;
}

bool valid_name(std::string_view n, std::string& why)
{
    bool ok = !n.empty() && n.size() <= 100 && n.front() != '.' && n.front() != '-' && n != "_backups";
    for (char c : n)
        ok = ok && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                    c == '-' || c == '_');
    if (!ok)
        why = "a repository's folder is letters, digits, '.', '-' and '_', not led by '.' or '-', and not _backups";
    return ok;
}

std::string name_of(std::string_view url)
{
    while (url.ends_with('/'))
        url.remove_suffix(1);
    std::string_view n = url.substr(url.rfind('/') + 1);
    if (n.ends_with(".git"))
        n.remove_suffix(4);
    std::string out;
    for (char c : n)
        out += (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                       c == '_'
                   ? c
                   : '-';
    while (!out.empty() && (out.front() == '.' || out.front() == '-'))
        out.erase(0, 1);
    return out.empty() || out == "_backups" ? std::string("repository") : out;
}

bool safe_path(std::string_view p)
{
    if (p.empty() || p.size() > 900 || p.front() == '/' || p.back() == '/')
        return false;
    for (size_t s = 0; s <= p.size();)
    {
        const size_t e = std::min(p.find('/', s), p.size());
        const std::string_view part = p.substr(s, e - s);
        if (part.empty() || part == "." || part == "..")
            return false;
        s = e + 1;
    }
    return true;
}

}   // namespace git_names
