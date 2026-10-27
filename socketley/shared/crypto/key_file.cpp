#include "key_file.h"

#include <cstdio>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace socketley::key_file
{

namespace
{

EVP_PKEY* read_key(const std::string& path)
{
    BIO* b = BIO_new_file(path.c_str(), "r");
    if (!b)
        return nullptr;
    EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    return k;
}

}   // namespace

EVP_PKEY* load_or_make(const std::string& path, std::string_view what, EVP_PKEY* (*make)(), std::string& err)
{
    if (::access(path.c_str(), F_OK) == 0)
    {
        if (EVP_PKEY* k = read_key(path))
            return k;
        ERR_clear_error();
        err = std::string(what) + " " + path + " does not load";
        return nullptr;
    }
    EVP_PKEY* k = make();
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    // Written beside and linked into place whole, so a failure leaves no empty or cut key that would never load.
    const std::string tmp = path + ".new." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE* f = fd >= 0 ? fdopen(fd, "w") : nullptr;
    bool ok = k && f && PEM_write_PrivateKey(f, k, nullptr, nullptr, 0, nullptr, nullptr) == 1 && fflush(f) == 0 &&
              ::fsync(fd) == 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    else if (fd >= 0)
        ::close(fd);
    ok = ok && ::link(tmp.c_str(), path.c_str()) == 0;
    if (fd >= 0)
        ::unlink(tmp.c_str());
    if (ok)
        return k;
    EVP_PKEY_free(k);
    ERR_clear_error();
    // Another process linked its key first, which is the one both must use.
    if (EVP_PKEY* theirs = read_key(path))
        return theirs;
    ERR_clear_error();
    err = std::string(what) + " " + path + " could not be written";
    return nullptr;
}

}   // namespace socketley::key_file
