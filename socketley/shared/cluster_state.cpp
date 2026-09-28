#include "cluster_state.h"

#include "byte_codec.h"
#include "runtime_name.h"

#include <algorithm>
#include <cctype>
#include <functional>

namespace socketley::cluster
{

namespace {

// A cluster with more runtimes than this is refused, so a snapshot and a full log replay stay a bounded size.
constexpr size_t max_specs = 1024;

constexpr uint8_t state_version = 1;
constexpr char    state_tag     = 'S';

bool control_free(std::string_view s)
{
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}

// The characters a command line carries unquoted, so a node name with a space in it cannot split one argument in two.
std::string label(std::string_view name)
{
    std::string out;
    for (unsigned char c : name)
        out += (std::isalnum(c) || c == '-' || c == '_' || c == '.') ? static_cast<char>(c) : '_';
    return out;
}

}   // namespace

// ─── commands ───

std::string type_refusal(std::string_view type)
{
    if (type == "server" || type == "proxy" || type == "client")
        return {};
    if (type == "cache")
        return "a cache holds data and nothing here promotes a follower when its node dies, so it is not a cluster "
               "runtime yet";
    return "only a server, a proxy or a client can be a cluster runtime";
}

std::string refusal(const command& c)
{
    if (!valid_runtime_name(c.name))
        return "invalid runtime name: " + c.name;

    switch (c.op)
    {
    case op::create:
    {
        if (std::string why = type_refusal(c.sp.type); !why.empty())
            return why;
        if (c.sp.args.size() > max_args)
            return "the flags are longer than " + std::to_string(max_args) + " bytes";
        if (!control_free(c.sp.args))
            return "the flags carry a control character";
        size_t pos = 0;
        while (pos < c.sp.args.size())
        {
            const size_t end = c.sp.args.find_first_of(" \t", pos);
            const std::string_view tok = std::string_view(c.sp.args).substr(pos, end == std::string::npos ? end : end - pos);
            if (tok == "--test")
                return "--test would leave every replica a dry run";
            if (end == std::string::npos)
                break;
            pos = end + 1;
        }
        [[fallthrough]];
    }
    case op::scale:
        if (c.sp.replicas < 1 || c.sp.replicas > max_replicas)
            return "replicas must be between 1 and " + std::to_string(max_replicas);
        return {};
    case op::remove:
        return {};
    case op::assign:
    case op::unassign:
        return c.node == 0 ? "node 0 is not a node" : std::string();
    }
    return "unknown command";
}

std::string encode(const command& c)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(command_tag));
    w.u8(static_cast<uint8_t>(c.op));
    w.bytes(c.name);
    switch (c.op)
    {
    case op::create:
        w.bytes(c.sp.type);
        w.bytes(c.sp.args);
        w.u32(c.sp.replicas);
        break;
    case op::scale:
        w.u32(c.sp.replicas);
        break;
    case op::remove:
        break;
    case op::assign:
    case op::unassign:
        w.u64(c.node);
        break;
    }
    return w.take();
}

bool is_command(std::string_view data)
{
    return !data.empty() && data[0] == command_tag;
}

bool decode(std::string_view data, command& out)
{
    bytes::reader r(data);
    uint8_t tag = 0, o = 0;
    if (!r.u8(tag) || tag != static_cast<uint8_t>(command_tag) || !r.u8(o) || o < 1
        || o > static_cast<uint8_t>(op::unassign))
        return false;
    command c;
    c.op = static_cast<op>(o);
    if (!r.bytes(c.name, max_name))
        return false;
    switch (c.op)
    {
    case op::create:
        if (!r.bytes(c.sp.type, 16) || !r.bytes(c.sp.args, max_args) || !r.u32(c.sp.replicas))
            return false;
        break;
    case op::scale:
        if (!r.u32(c.sp.replicas))
            return false;
        break;
    case op::remove:
        break;
    case op::assign:
    case op::unassign:
        if (!r.u64(c.node))
            return false;
        break;
    }
    if (r.left() != 0 || !refusal(c).empty())
        return false;
    out = std::move(c);
    return true;
}

std::string expand_args(std::string_view args, std::string_view node_name)
{
    static constexpr std::string_view token = "{node}";
    const std::string who = label(node_name);
    std::string out;
    size_t pos = 0;
    for (;;)
    {
        const size_t hit = args.find(token, pos);
        out.append(args.substr(pos, hit == std::string_view::npos ? hit : hit - pos));
        if (hit == std::string_view::npos)
            return out;
        out += who;
        pos = hit + token.size();
    }
}

// ─── the state machine ───

bool state::apply(const command& c)
{
    switch (c.op)
    {
    case op::create:
        if (specs.count(c.name) || specs.size() >= max_specs)
            return false;
        specs[c.name] = c.sp;
        owners[c.name];
        return true;

    case op::remove:
        return specs.erase(c.name) + owners.erase(c.name) > 0;

    case op::scale:
    {
        auto it = specs.find(c.name);
        if (it == specs.end() || it->second.replicas == c.sp.replicas)
            return false;
        it->second.replicas = c.sp.replicas;
        return true;
    }

    case op::assign:
    {
        auto it = specs.find(c.name);
        if (it == specs.end())
            return false;
        auto& held = owners[c.name];
        // A second assign racing the first, from another leader's plan, finds the replicas full and loses.
        if (held.size() >= it->second.replicas)
            return false;
        return held.insert(c.node).second;
    }

    case op::unassign:
    {
        auto it = owners.find(c.name);
        return it != owners.end() && it->second.erase(c.node) > 0;
    }
    }
    return false;
}

size_t state::load(node_id n) const
{
    size_t k = 0;
    for (const auto& [name, held] : owners)
        k += held.count(n);
    return k;
}

size_t state::placed(const std::string& name) const
{
    auto it = owners.find(name);
    return it == owners.end() ? 0 : it->second.size();
}

size_t state::missing(const std::string& name) const
{
    auto it = specs.find(name);
    if (it == specs.end())
        return 0;
    const size_t have = placed(name);
    return it->second.replicas > have ? it->second.replicas - have : 0;
}

std::string conflict(const state& s, const command& c)
{
    switch (c.op)
    {
    case op::create:
        if (s.specs.count(c.name))
            return "cluster runtime already exists: " + c.name;
        if (s.specs.size() >= max_specs)
            return "the cluster already holds " + std::to_string(max_specs) + " runtimes";
        return {};
    case op::remove:
    case op::scale:
        if (!s.specs.count(c.name))
            return "cluster runtime not found: " + c.name;
        if (c.op == op::scale && s.specs.at(c.name).replicas == c.sp.replicas)
            return c.name + " already has " + std::to_string(c.sp.replicas) + " replicas";
        return {};
    case op::assign:
    case op::unassign:
        return {};
    }
    return {};
}

std::string encode(const state& s)
{
    bytes::writer w;
    w.u8(static_cast<uint8_t>(state_tag));
    w.u8(state_version);
    w.u32(static_cast<uint32_t>(s.specs.size()));
    for (const auto& [name, sp] : s.specs)
    {
        w.bytes(name);
        w.bytes(sp.type);
        w.bytes(sp.args);
        w.u32(sp.replicas);
        auto it = s.owners.find(name);
        const std::vector<uint64_t> held = it == s.owners.end() ? std::vector<uint64_t>{}
                                                                : std::vector<uint64_t>(it->second.begin(), it->second.end());
        w.ids(held);
    }
    return w.take();
}

bool decode(std::string_view data, state& out)
{
    bytes::reader r(data);
    uint8_t tag = 0, version = 0;
    uint32_t n = 0;
    if (!r.u8(tag) || tag != static_cast<uint8_t>(state_tag) || !r.u8(version) || version != state_version || !r.u32(n)
        || n > max_specs)
        return false;
    state s;
    for (uint32_t i = 0; i < n; ++i)
    {
        command c;
        c.op = op::create;
        std::vector<uint64_t> held;
        if (!r.bytes(c.name, max_name) || !r.bytes(c.sp.type, 16) || !r.bytes(c.sp.args, max_args)
            || !r.u32(c.sp.replicas) || !r.ids(held))
            return false;
        // What is stored passes through the same rules a proposal does, in the order encode writes it, so one state has one encoding.
        if (!refusal(c).empty() || (!s.specs.empty() && c.name <= s.specs.rbegin()->first) || held.size() > max_replicas)
            return false;
        if (!std::is_sorted(held.begin(), held.end(), std::less_equal<node_id>{}) || (!held.empty() && held.front() == 0))
            return false;
        std::set<node_id> owners(held.begin(), held.end());
        s.specs[c.name]  = c.sp;
        s.owners[c.name] = std::move(owners);
    }
    if (r.left() != 0)
        return false;
    out = std::move(s);
    return true;
}

// ─── placement ───

std::vector<command> plan(const state& s, const std::vector<node_id>& live_in)
{
    std::set<node_id> live(live_in.begin(), live_in.end());
    live.erase(0);

    // How many replicas each live node already holds, which is what a new replica is spread by.
    std::map<node_id, size_t> load;
    for (node_id n : live)
        load[n] = 0;
    for (const auto& [name, held] : s.owners)
        for (node_id n : held)
            if (live.count(n))
                ++load[n];

    std::vector<command> out;
    auto emit = [&out](op o, const std::string& name, node_id n)
    {
        command c;
        c.op   = o;
        c.name = name;
        c.node = n;
        out.push_back(std::move(c));
    };

    for (const auto& [name, sp] : s.specs)
    {
        std::set<node_id> keep;
        auto it = s.owners.find(name);
        if (it != s.owners.end())
            for (node_id n : it->second)
            {
                if (live.count(n))
                    keep.insert(n);
                else
                    emit(op::unassign, name, n);
            }

        // Too many, after a scale-down: the most loaded node gives one up, the highest id on a tie.
        while (keep.size() > sp.replicas)
        {
            node_id victim = *keep.begin();
            for (node_id n : keep)
                if (load[n] > load[victim] || (load[n] == load[victim] && n > victim))
                    victim = n;
            emit(op::unassign, name, victim);
            --load[victim];
            keep.erase(victim);
        }

        // Too few: the least loaded node that does not hold this runtime yet, the lowest id on a tie; none left is a shortfall.
        while (keep.size() < sp.replicas)
        {
            node_id best = 0;
            for (node_id n : live)
                if (!keep.count(n) && (best == 0 || load[n] < load[best]))
                    best = n;
            if (best == 0)
                break;
            emit(op::assign, name, best);
            ++load[best];
            keep.insert(best);
        }
    }
    return out;
}

}   // namespace socketley::cluster
