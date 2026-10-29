#pragma once
// A directory that is this user's alone, the only kind a path anyone could have made first may be trusted as.
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <string>

namespace socketley
{

// Whether `dir` is a directory, not a link, owned by this user with no group or other bits; made 0700 first when
// `make` is set and it is absent, since mkdir answering EEXIST says nothing about whose it is.
inline bool private_dir(const std::string& dir, bool make)
{
    if (make && ::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        return false;
    struct stat st{};
    if (::lstat(dir.c_str(), &st) < 0)
        return false;
    return S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

}   // namespace socketley
