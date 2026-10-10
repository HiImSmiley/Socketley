#pragma once
// What a repository kept in a storage runtime's library (git_mirrors.h) may be named and fetched from, asked by the
// runtime when one is added and by `socketley git-sync` again before it runs git.
#include <string>
#include <string_view>

namespace git_names
{

// https://, http:// or git:// with a host and a path, without credentials in it and without a character git or a
// shell would read as anything but the URL; ssh and local paths are not fetched from.
bool valid_url(std::string_view url, std::string& why);

// A branch as git takes it (git check-ref-format, short of its rarest rules), or "*" for every branch.
bool valid_branch(std::string_view branch, std::string& why);

// The folder a repository's files are written under: letters, digits, '.', '-' and '_', not led by '.' or '-', and
// not "_backups", where the backups go.
bool valid_name(std::string_view name, std::string& why);

// The name a repository is given when none is: the last part of its URL without ".git".
std::string name_of(std::string_view url);

// The library a user's repositories go to when none is named, "git-<user>", so two users sharing never share one.
std::string library_for(std::string_view user);

// Whether a path from a tree may be written as a key below the folder: no "." or ".." part, no empty one, and at
// most 900 bytes.
bool safe_path(std::string_view path);

}   // namespace git_names
