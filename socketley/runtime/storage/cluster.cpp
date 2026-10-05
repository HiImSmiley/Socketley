#include "cluster.h"

#include <charconv>

#include "../../shared/byte_codec.h"

namespace socketley::storage
{

bool parse_cluster(std::string_view text, cluster_config& out, std::string& why)
{
    out = cluster_config{};
    std::vector<replication_target> nodes;
    for (const target_line& line : split_target_lines(text))
    {
        const auto& f = line.fields;
        const std::string where = "line " + std::to_string(line.line_no) + ": ";
        if (f[0] == "self" && f.size() == 2 && out.self.empty() && valid_target_name(f[1]))
        {
            out.self = std::string(f[1]);
            continue;
        }
        if (f[0] == "key" && f.size() == 3 && out.access_key.empty())
        {
            out.access_key = std::string(f[1]);
            out.secret     = std::string(f[2]);
            if (out.access_key.size() > 127 || out.secret.empty())
            {
                why = where + "the key is an access key of at most 127 bytes and a secret";
                return false;
            }
            continue;
        }
        if (f[0] == "sync" && (f.size() == 2 || f.size() == 3))
        {
            uint32_t n = 0, ms = 5000;
            const auto a = std::from_chars(f[1].data(), f[1].data() + f[1].size(), n);
            const bool ok_n = a.ec == std::errc{} && a.ptr == f[1].data() + f[1].size();
            bool ok_ms = true;
            if (f.size() == 3)
            {
                const auto b = std::from_chars(f[2].data(), f[2].data() + f[2].size(), ms);
                ok_ms = b.ec == std::errc{} && b.ptr == f[2].data() + f[2].size() && ms > 0 && ms <= 600000;
            }
            if (!ok_n || !ok_ms)
            {
                why = where + "sync is a number of nodes and optionally the milliseconds a write waits for them";
                return false;
            }
            out.sync    = n;
            out.sync_ms = ms;
            continue;
        }
        if (f[0] != "node" || f.size() < 3 || f.size() > 4 || (f.size() == 4 && !f[3].starts_with("ca=")))
        {
            why = where + "a line is `self name`, `node name url [ca=file]`, `key access_key secret` or `sync n [ms]`, "
                          "and self and key are given once";
            return false;
        }
        replication_target t;
        t.name   = std::string(f[1]);
        t.region = "us-east-1";
        t.node   = true;
        if (f.size() == 4)
            t.http.ca_file = std::string(f[3].substr(3));
        if (!valid_target_name(t.name))
        {
            why = where + "a node's name is letters, digits, '-', '_' and '.'";
            return false;
        }
        if (std::string err; !parse_http_url(f[2], t.http, err))
        {
            why = where + err;
            return false;
        }
        if (!t.http.ca_file.empty() && !t.http.tls)
        {
            why = where + "ca= is for an https node";
            return false;
        }
        for (const replication_target& o : nodes)
            if (o.name == t.name)
            {
                why = where + "the node " + t.name + " is named twice";
                return false;
            }
        nodes.push_back(std::move(t));
    }
    if (out.self.empty() || out.access_key.empty())
    {
        why = "a cluster file names this node with `self name` and the nodes' key with `key access_key secret`";
        return false;
    }
    bool found = false;
    for (replication_target& t : nodes)
    {
        if (t.name == out.self)
        {
            found = true;
            continue;
        }
        t.access_key = out.access_key;
        t.secret     = out.secret;
        out.peers.push_back(std::move(t));
    }
    if (!found)
    {
        why = "the node " + out.self + " that `self` names is none of the file's nodes";
        return false;
    }
    if (out.sync > out.peers.size())
    {
        why = "sync names " + std::to_string(out.sync) + " nodes, and there are " + std::to_string(out.peers.size()) +
              " others";
        return false;
    }
    return true;
}

bool load_cluster(const std::string& path, cluster_config& out, std::string& why)
{
    std::string text;
    if (!read_targets_file(path, "cluster", text, why))
        return false;
    if (!parse_cluster(text, out, why))
    {
        why = path + ": " + why;
        return false;
    }
    return true;
}

std::string encode_cluster_record(const cluster_record& r)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(r.kind));
    w.bytes(r.owner);
    w.u8(r.what);
    w.bytes(r.value);
    w.bytes(r.version_id);
    return w.take();
}

bool decode_cluster_record(std::string_view in, cluster_record& out)
{
    bytes::reader r(in);
    uint8_t kind = 0;
    if (!r.u8(kind) || !r.bytes(out.owner, 4096) || !r.u8(out.what) || !r.bytes(out.value, 1 << 20) ||
        !r.bytes(out.version_id, 64))
        return false;
    out.kind = static_cast<char>(kind);
    return std::string_view("crdlihq").find(out.kind) != std::string_view::npos;
}

}   // namespace socketley::storage
