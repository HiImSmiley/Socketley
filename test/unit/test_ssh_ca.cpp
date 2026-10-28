#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/crypto/ed25519.h"
#include "shared/crypto/jws.h"
#include "shared/crypto/ssh_cert.h"
#include "shared/util/base64.h"
#include <cstdlib>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace socketley;

namespace
{

std::string unhex(std::string_view h)
{
    std::string out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<char>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
    return out;
}

// Keys and a certificate ssh-keygen made, so the reader is checked against the writer everyone runs.
constexpr const char* user_ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTZa3UpuRNOjkxwDTZiEB+wDXHaHJw7Cx+sKMt0cTXJ alice@laptop";
constexpr const char* user_rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbkgJ8RkRKt6kpTuZVZXOp8QTZF8Wgi2BciKUH/GPVoiJvUPucpLGCi47UT4/xUj1//t500w0Vgr9pMZNkTzX6s3VDlULnTtvR5YVpUI4qGEHVyi533ti7sru1VrKCAfNMZktTPKzh7BIxcSSWNoQ+jXCznmJOa2pQEetb//HW+MbvcP8IXii6zF5KiH/oGHp5XU6eaQKW6NpbH2njMtvjzLXP5bj2dPuDIiPkn16Pr67vhOmEfvCpy8BCzHq17/e99CTsWHEZAe9PtOlKVxJsOHeRKKCsUizeYujLD7eWHRyVFCmajvOZxsTOlL0pIisNWjAp5kDc0no6fTF/8HsH rsa-key";
constexpr const char* user_ec = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOgotK8AyjzEGK5tBo6UhI//UHAP/pvJWobredED24l2pRgPLov5wFV8ji4GC2B8lDqkXnok7pecSzEvwMEWVTM= ";
constexpr const char* their_cert = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIOV8L4lftgLEepfDlBBE1MLAPJypmBscWGRTR7aD7xCXAAAAICTZa3UpuRNOjkxwDTZiEB+wDXHaHJw7Cx+sKMt0cTXJAAAAAAAAACoAAAABAAAACmFsaWNlQHRlc3QAAAARAAAABWFsaWNlAAAABHJvb3QAAAAAauAE7AAAAABsv+dLAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgDg7B+qzVttKUVtBB0wmzBJik+HTpsj3UaZ9KErPM3w0AAABTAAAAC3NzaC1lZDI1NTE5AAAAQFNUIYyok07eO8oQ6q3zRGK3b9FyKCykd+AsXeyvq0W8R/YjRe/wCAaaFccFEjltpecM36XuyaWepoMKkAaU4QU= alice@laptop";

struct tmp_dir
{
    std::string path;
    tmp_dir() : path(fs::temp_directory_path() / ("ssh_ca_test_" + std::to_string(::getpid())))
    {
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~tmp_dir() { fs::remove_all(path); }
};

// What `ssh-keygen -L` prints for a certificate file, empty when ssh-keygen is not installed.
std::string ssh_keygen_list(const std::string& file)
{
    std::string out;
    FILE* p = ::popen(("ssh-keygen -L -f '" + file + "' 2>&1").c_str(), "r");
    if (!p)
        return out;
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0)
        out.append(buf, n);
    ::pclose(p);
    return out;
}

bool have_ssh_keygen() { return std::system("command -v ssh-keygen >/dev/null 2>&1") == 0; }

}   // namespace

TEST_CASE("ed25519 signs and verifies as RFC 8032's test vectors say")
{
    struct vec { const char *seed, *pub, *msg, *sig; };
    const vec vs[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    };
    for (const vec& v : vs)
    {
        EVP_PKEY* k = ed25519::from_seed(unhex(v.seed));
        REQUIRE(k);
        CHECK(ed25519::public_raw(k) == unhex(v.pub));
        const std::string msg = unhex(v.msg);
        const std::string sig = ed25519::sign(k, msg);
        CHECK(sig == unhex(v.sig));
        CHECK(ed25519::verify(unhex(v.pub), msg, sig));
        std::string bad = sig;
        bad[10] = static_cast<char>(bad[10] ^ 1);
        CHECK_FALSE(ed25519::verify(unhex(v.pub), msg, bad));
        CHECK_FALSE(ed25519::verify(unhex(v.pub), msg + "x", sig));
        EVP_PKEY_free(k);
    }
    CHECK(ed25519::from_seed("short") == nullptr);
    CHECK_FALSE(ed25519::verify("short", "", std::string(64, '\0')));
}

TEST_CASE("an Ed25519 key file is made once, 0600, and refused when it holds another kind of key")
{
    tmp_dir d;
    const std::string path = d.path + "/ca/key.pem";
    std::string err;
    EVP_PKEY* a = ed25519::load_or_make(path, "the CA key", err);
    REQUIRE(a);
    struct stat st{};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    EVP_PKEY* b = ed25519::load_or_make(path, "the CA key", err);
    REQUIRE(b);
    CHECK(ed25519::public_raw(a) == ed25519::public_raw(b));
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);

    const std::string ec_path = d.path + "/p256.pem";
    EVP_PKEY* ec = jws::load_or_make_key(ec_path, "a P-256 key", err);
    REQUIRE(ec);
    EVP_PKEY_free(ec);
    err.clear();
    CHECK(ed25519::load_or_make(ec_path, "the CA key", err) == nullptr);
    CHECK(err.find("not an Ed25519 key") != std::string::npos);
}

TEST_CASE("public keys are read as ssh-keygen writes them, and their fingerprints agree")
{
    struct row { const char* line; const char* type; const char* fp; const char* comment; };
    const row rows[] = {
        {user_ed, "ssh-ed25519", "SHA256:vbG/8e+ZJVEb8X8aQRZEQPZqpAF9aEJyBGr4Wk5RAZ4", "alice@laptop"},
        {user_rsa, "ssh-rsa", "SHA256:J/wMSZE77h8GXCSQY9ctuNhgIxOpu+IwpbYoU8DD05I", "rsa-key"},
        {user_ec, "ecdsa-sha2-nistp256", "SHA256:ANLiqO1UgBQA14iuZcdeme/ZcEwzLEUsTkerB7xx1pE", ""},
    };
    for (const row& r : rows)
    {
        ssh::public_key k;
        std::string err;
        INFO(r.type);
        REQUIRE(ssh::parse_public_key(r.line, k, err));
        CHECK(k.type == r.type);
        CHECK(k.comment == r.comment);
        CHECK(ssh::fingerprint(k.blob) == r.fp);
        CHECK(ssh::line_of(k.blob, k.comment) == std::string(r.line).substr(0, ssh::line_of(k.blob, k.comment).size()));
    }
    ssh::public_key k;
    std::string err;
    CHECK_FALSE(ssh::parse_public_key(their_cert, k, err));
    CHECK(err == "a certificate, not a public key");
    CHECK_FALSE(ssh::parse_public_key("ssh-dss AAAAB3NzaC1kc3M=", k, err));
    CHECK_FALSE(ssh::parse_public_key("ssh-ed25519 not-base64!", k, err));
    // The blob says rsa while the line says ed25519.
    const std::string rsa_b64 = std::string(user_rsa).substr(8, std::string(user_rsa).find(' ', 8) - 8);
    CHECK_FALSE(ssh::parse_public_key("ssh-ed25519 " + rsa_b64, k, err));
    // Bytes after the key's fields.
    ssh::public_key ok;
    REQUIRE(ssh::parse_public_key(user_ed, ok, err));
    CHECK_FALSE(ssh::parse_public_key("ssh-ed25519 " + base64::encode(ok.blob + "x"), k, err));
    CHECK_FALSE(ssh::parse_public_key("", k, err));
}

TEST_CASE("a certificate ssh-keygen signed is read whole and its signature checks")
{
    const std::string line = their_cert;
    const size_t a = line.find(' ') + 1, b = line.find(' ', a);
    std::string blob;
    REQUIRE(base64::decode(line.substr(a, b - a), blob));
    ssh::cert c;
    std::string err;
    REQUIRE(ssh::parse_cert(blob, c, err));
    CHECK(c.type == "ssh-ed25519-cert-v01@openssh.com");
    CHECK(c.kind == ssh::cert_kind::user);
    CHECK(c.serial == 42);
    CHECK(c.key_id == "alice@test");
    CHECK(c.principals == std::vector<std::string>{"alice", "root"});
    CHECK(c.extensions.size() == 5);
    CHECK(c.critical_options.empty());
    ssh::public_key k;
    REQUIRE(ssh::parse_public_key(user_ed, k, err));
    CHECK(c.subject_blob == k.blob);
    CHECK(ssh::fingerprint(c.signature_key) == "SHA256:yoGVUsOluQoKxE2qDiDl6gNpXy1xvIOrQDW3GqilwWs");
    CHECK(ssh::verify_cert(c));
    // Every cut is refused rather than read past.
    for (size_t n = 0; n < blob.size(); ++n)
    {
        ssh::cert t;
        CHECK_FALSE(ssh::parse_cert(std::string_view(blob).substr(0, n), t, err));
    }
    // Any byte changed in the signed part fails the signature.
    for (size_t i = 0; i < c.signed_part.size(); i += 7)
    {
        std::string bad = blob;
        bad[i] = static_cast<char>(bad[i] ^ 0x20);
        ssh::cert t;
        if (ssh::parse_cert(bad, t, err))
            CHECK_FALSE(ssh::verify_cert(t));
    }
    CHECK_FALSE(ssh::parse_cert(blob + "x", c, err));
}

TEST_CASE("the certificates this writes are read back whole and ssh-keygen reads them as the request said")
{
    std::string err;
    EVP_PKEY* ca = ed25519::generate();
    REQUIRE(ca);
    tmp_dir d;
    for (const char* line : {user_ed, user_rsa, user_ec})
    {
        ssh::public_key k;
        REQUIRE(ssh::parse_public_key(line, k, err));
        INFO(k.type);
        ssh::cert_request rq;
        rq.subject_blob = k.blob;
        rq.kind = ssh::cert_kind::user;
        rq.serial = 1000;
        rq.key_id = "alice@1790000000";
        rq.principals = {"alice", "root"};
        rq.valid_after = 1790000000;
        rq.valid_before = 1790028800;
        rq.critical_options = {{"source-address", "10.0.0.0/8"}};
        rq.extensions = ssh::default_user_extensions();
        const std::string blob = ssh::sign_cert(rq, ca, err);
        REQUIRE_FALSE(blob.empty());
        ssh::cert c;
        REQUIRE(ssh::parse_cert(blob, c, err));
        CHECK(c.subject_blob == k.blob);
        CHECK(c.serial == 1000);
        CHECK(c.principals == rq.principals);
        CHECK(c.valid_after == rq.valid_after);
        CHECK(c.valid_before == rq.valid_before);
        CHECK(c.critical_options == std::vector<std::pair<std::string, std::string>>{{"source-address", "10.0.0.0/8"}});
        CHECK(c.extensions == std::vector<std::pair<std::string, std::string>>{
                                  {"permit-agent-forwarding", ""}, {"permit-port-forwarding", ""}, {"permit-pty", ""}});
        CHECK(ssh::verify_cert(c));
        CHECK(c.signature_key == ssh::ed25519_blob(ed25519::public_raw(ca)));

        if (!have_ssh_keygen())
        {
            MESSAGE("ssh-keygen is not installed; the interoperability half is skipped");
            continue;
        }
        const std::string file = d.path + "/k-cert.pub";
        std::ofstream(file) << ssh::line_of(blob, "test") << "\n";
        const std::string listed = ssh_keygen_list(file);
        INFO(listed);
        CHECK(listed.find("user certificate") != std::string::npos);
        CHECK(listed.find("Key ID: \"alice@1790000000\"") != std::string::npos);
        CHECK(listed.find("Serial: 1000") != std::string::npos);
        CHECK(listed.find("source-address 10.0.0.0/8") != std::string::npos);
        CHECK(listed.find("permit-pty") != std::string::npos);
        CHECK(listed.find("permit-X11-forwarding") == std::string::npos);
        CHECK(listed.find("permit-user-rc") == std::string::npos);
        CHECK(listed.find("Signing CA: ED25519 " + ssh::fingerprint(c.signature_key)) != std::string::npos);
    }

    // A host certificate, and a request for a key of a type with no certificate form.
    ssh::public_key k;
    REQUIRE(ssh::parse_public_key(user_ed, k, err));
    ssh::cert_request host;
    host.subject_blob = k.blob;
    host.kind = ssh::cert_kind::host;
    host.principals = {"smileygames.online"};
    host.valid_before = ~uint64_t{0};
    ssh::cert hc;
    REQUIRE(ssh::parse_cert(ssh::sign_cert(host, ca, err), hc, err));
    CHECK(hc.kind == ssh::cert_kind::host);
    ssh::cert_request bad = host;
    bad.subject_blob = "nonsense";
    CHECK(ssh::sign_cert(bad, ca, err).empty());
    EVP_PKEY* ec = EVP_EC_gen("P-256");
    CHECK(ssh::sign_cert(host, ec, err).empty());
    CHECK(err == "the authority's key is not Ed25519");
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ca);
}
