#include "ssh_cert.h"
#include "ed25519.h"
#include "jws.h"
#include "../util/base64.h"
#include "../util/random_id.h"

#include <algorithm>

namespace socketley::ssh
{

namespace
{

// Each key type a certificate is made for, its certificate's type, and how many strings its key fields are.
struct key_form
{
    std::string_view key;
    std::string_view cert;
    int fields;
};

constexpr key_form forms[] = {
    {"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", 1},
    {"ssh-rsa", "ssh-rsa-cert-v01@openssh.com", 2},
    {"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com", 2},
    {"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com", 2},
    {"ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com", 2},
    {"sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com", 2},
    {"sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", 3},
};

const key_form* form_of_key(std::string_view type)
{
    for (const key_form& f : forms)
        if (f.key == type)
            return &f;
    return nullptr;
}

const key_form* form_of_cert(std::string_view type)
{
    for (const key_form& f : forms)
        if (f.cert == type)
            return &f;
    return nullptr;
}

void put_u32(std::string& out, uint32_t v)
{
    for (int s = 24; s >= 0; s -= 8)
        out.push_back(static_cast<char>((v >> s) & 0xff));
}

void put_u64(std::string& out, uint64_t v)
{
    for (int s = 56; s >= 0; s -= 8)
        out.push_back(static_cast<char>((v >> s) & 0xff));
}

void put_string(std::string& out, std::string_view s)
{
    put_u32(out, static_cast<uint32_t>(s.size()));
    out.append(s);
}

// A cursor over wire bytes that refuses to read past their end.
struct reader
{
    std::string_view in;

    bool u32(uint32_t& v)
    {
        if (in.size() < 4)
            return false;
        v = 0;
        for (int i = 0; i < 4; ++i)
            v = (v << 8) | static_cast<unsigned char>(in[static_cast<size_t>(i)]);
        in.remove_prefix(4);
        return true;
    }
    bool u64(uint64_t& v)
    {
        if (in.size() < 8)
            return false;
        v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | static_cast<unsigned char>(in[static_cast<size_t>(i)]);
        in.remove_prefix(8);
        return true;
    }
    bool string(std::string_view& s)
    {
        uint32_t n = 0;
        if (!u32(n) || in.size() < n)
            return false;
        s = in.substr(0, n);
        in.remove_prefix(n);
        return true;
    }
};

// The key fields of a public key blob after its type, which a certificate carries as they are.
bool key_fields(std::string_view blob, const key_form*& form, std::string_view& fields)
{
    reader r{blob};
    std::string_view type;
    if (!r.string(type) || !(form = form_of_key(type)))
        return false;
    const std::string_view rest = r.in;
    std::string_view f;
    for (int i = 0; i < form->fields; ++i)
        if (!r.string(f))
            return false;
    if (!r.in.empty())
        return false;
    // An Ed25519 key is 32 bytes and nothing else.
    if (type == "ssh-ed25519" && rest.size() != 4 + 32)
        return false;
    fields = rest;
    return true;
}

// A sequence of strings packed into one, as the principals are.
std::string packed(const std::vector<std::string>& items)
{
    std::string out;
    for (const std::string& s : items)
        put_string(out, s);
    return out;
}

bool unpack_strings(std::string_view in, std::vector<std::string>& out)
{
    reader r{in};
    std::string_view s;
    while (!r.in.empty())
    {
        if (!r.string(s))
            return false;
        out.emplace_back(s);
    }
    return true;
}

// Options and extensions: a name and a value, the value itself a string inside the string when present.
bool unpack_options(std::string_view in, std::vector<std::pair<std::string, std::string>>& out)
{
    reader r{in};
    std::string_view name, data;
    while (!r.in.empty())
    {
        if (!r.string(name) || !r.string(data))
            return false;
        std::string value;
        if (!data.empty())
        {
            reader v{data};
            std::string_view inner;
            if (!v.string(inner) || !v.in.empty())
                return false;
            value = inner;
        }
        out.emplace_back(name, std::move(value));
    }
    return true;
}

}   // namespace

bool parse_public_key(std::string_view line, public_key& out, std::string& err)
{
    const auto skip_space = [](std::string_view& s) {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
            s.remove_prefix(1);
    };
    const auto word = [](std::string_view& s) {
        const size_t n = std::min(s.find_first_of(" \t"), s.size());
        std::string_view w = s.substr(0, n);
        s.remove_prefix(n);
        return w;
    };
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
        line.remove_suffix(1);
    skip_space(line);
    const std::string_view type = word(line);
    skip_space(line);
    const std::string_view b64 = word(line);
    skip_space(line);
    if (form_of_cert(type))
    {
        err = "a certificate, not a public key";
        return false;
    }
    if (!form_of_key(type))
    {
        err = "a key of a type that has no certificate form: " + std::string(type.substr(0, 64));
        return false;
    }
    std::string blob;
    const key_form* form = nullptr;
    std::string_view fields;
    if (!base64::decode(b64, blob) || !key_fields(blob, form, fields) || form->key != type)
    {
        err = "a public key that does not decode";
        return false;
    }
    out.type = std::string(type);
    out.blob = std::move(blob);
    out.comment = std::string(line);
    return true;
}

std::string fingerprint(std::string_view blob)
{
    std::string b64 = base64::encode(jws::sha256(blob));
    while (!b64.empty() && b64.back() == '=')
        b64.pop_back();
    return "SHA256:" + b64;
}

std::string ed25519_blob(std::string_view raw)
{
    std::string out;
    put_string(out, "ssh-ed25519");
    put_string(out, raw);
    return out;
}

std::string line_of(std::string_view blob, std::string_view comment)
{
    reader r{blob};
    std::string_view type;
    if (!r.string(type))
        return {};
    std::string out = std::string(type) + " " + base64::encode(blob);
    if (!comment.empty())
        out += " " + std::string(comment);
    return out;
}

std::vector<std::string> default_user_extensions()
{
    return {"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"};
}

std::string sign_cert(const cert_request& req, EVP_PKEY* ca, std::string& err)
{
    const key_form* form = nullptr;
    std::string_view fields;
    if (!key_fields(req.subject_blob, form, fields))
    {
        err = "a subject key of a type that has no certificate form";
        return {};
    }
    const std::string ca_raw = ed25519::public_raw(ca);
    if (ca_raw.empty())
    {
        err = "the authority's key is not Ed25519";
        return {};
    }
    std::string nonce(32, '\0');
    if (!random_bytes(nonce.data(), nonce.size()))
    {
        err = "no random bytes for the nonce";
        return {};
    }
    // Options and extensions are sorted by name, which OpenSSH requires of both.
    auto options = req.critical_options;
    std::sort(options.begin(), options.end());
    auto extensions = req.extensions;
    std::sort(extensions.begin(), extensions.end());
    extensions.erase(std::unique(extensions.begin(), extensions.end()), extensions.end());
    std::string opts;
    for (const auto& [name, value] : options)
    {
        put_string(opts, name);
        std::string data;
        if (!value.empty())
            put_string(data, value);
        put_string(opts, data);
    }
    std::string exts;
    for (const std::string& name : extensions)
    {
        put_string(exts, name);
        put_string(exts, "");
    }

    std::string out;
    put_string(out, form->cert);
    put_string(out, nonce);
    out.append(fields);
    put_u64(out, req.serial);
    put_u32(out, static_cast<uint32_t>(req.kind));
    put_string(out, req.key_id);
    put_string(out, packed(req.principals));
    put_u64(out, req.valid_after);
    put_u64(out, req.valid_before);
    put_string(out, opts);
    put_string(out, exts);
    put_string(out, "");
    put_string(out, ed25519_blob(ca_raw));
    const std::string sig = ed25519::sign(ca, out);
    if (sig.empty())
    {
        err = "the authority's signature failed";
        return {};
    }
    std::string sig_blob;
    put_string(sig_blob, "ssh-ed25519");
    put_string(sig_blob, sig);
    put_string(out, sig_blob);
    return out;
}

bool parse_cert(std::string_view blob, cert& out, std::string& err)
{
    const auto fail = [&](const char* why) {
        err = why;
        return false;
    };
    reader r{blob};
    std::string_view type, nonce;
    if (!r.string(type))
        return fail("a certificate cut short");
    const key_form* form = form_of_cert(type);
    if (!form)
        return fail("a certificate of an unknown type");
    if (!r.string(nonce))
        return fail("a certificate cut short");
    std::string subject;
    put_string(subject, form->key);
    std::string_view f;
    for (int i = 0; i < form->fields; ++i)
    {
        if (!r.string(f))
            return fail("a certificate cut short");
        put_string(subject, f);
    }
    uint32_t kind = 0;
    std::string_view key_id, principals, options, extensions, reserved, sig_key;
    if (!r.u64(out.serial) || !r.u32(kind) || !r.string(key_id) || !r.string(principals) ||
        !r.u64(out.valid_after) || !r.u64(out.valid_before) || !r.string(options) || !r.string(extensions) ||
        !r.string(reserved) || !r.string(sig_key))
        return fail("a certificate cut short");
    if (kind != static_cast<uint32_t>(cert_kind::user) && kind != static_cast<uint32_t>(cert_kind::host))
        return fail("a certificate that is neither for a user nor for a host");
    const std::string_view signed_part = blob.substr(0, blob.size() - r.in.size());
    std::string_view sig;
    if (!r.string(sig))
        return fail("a certificate cut short");
    if (!r.in.empty())
        return fail("bytes after the certificate's signature");
    out.type = std::string(type);
    out.nonce = std::string(nonce);
    out.subject_blob = std::move(subject);
    out.kind = static_cast<cert_kind>(kind);
    out.key_id = std::string(key_id);
    out.principals.clear();
    out.critical_options.clear();
    out.extensions.clear();
    if (!unpack_strings(principals, out.principals))
        return fail("principals that do not decode");
    if (!unpack_options(options, out.critical_options) || !unpack_options(extensions, out.extensions))
        return fail("options that do not decode");
    out.signature_key = std::string(sig_key);
    out.signature = std::string(sig);
    out.signed_part = std::string(signed_part);
    return true;
}

bool verify_cert(const cert& c)
{
    reader k{c.signature_key};
    std::string_view ktype, kraw;
    if (!k.string(ktype) || ktype != "ssh-ed25519" || !k.string(kraw) || !k.in.empty())
        return false;
    reader s{c.signature};
    std::string_view stype, sraw;
    if (!s.string(stype) || stype != "ssh-ed25519" || !s.string(sraw) || !s.in.empty())
        return false;
    return ed25519::verify(kraw, c.signed_part, sraw);
}

}   // namespace socketley::ssh
