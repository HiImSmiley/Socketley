#include "runtime_schema.h"
#include "../shared/runtime_config_apply.h"

#include <string_view>

namespace runtime_schema
{

namespace
{

// The types a flag is offered for, one letter each: Server, Client, Proxy, cache (K), sTorage, Dns, sYnc.
struct row
{
    std::string_view flag, types, kind, label, help, section, choices = {}, placeholder = {}, aliases = {};
    bool hidden = false;
};

constexpr row rows[] = {
    // ── basics ──────────────────────────────────────────────────────────────
    {"-p", "SCPKTD", "int", "Port", "The port it listens on (a client: the port of its target).", "Basics", {}, "8080"},
    {"-s", "SCPKTD", "switch", "Start now", "Start it as soon as it is made.", "Basics"},
    {"-g", "SCPKTD", "text", "Group", "A group its proxies reach all members of with --backend @group.", "Basics", {}, "web", "--group"},
    {"--lua", "SCPKT", "path", "Lua script", "A script with the runtime's callbacks, run at start.", "Basics", {}, "/etc/socketley/app.lua"},
    {"--test", "SCPKTD", "switch", "Dry run", "Check the type, the name and every flag, and keep nothing.", "Basics", {}, {}, {}, true},

    // ── network ─────────────────────────────────────────────────────────────
    {"--bind", "SPKTD", "text", "Bind address", "The address the port is bound on alone, such as 127.0.0.1 for one only a proxy here reaches.", "Network", {}, "127.0.0.1"},
    {"--listen", "SPKT", "text", "Unix socket", "Listen on a unix socket instead of a port.", "Network", {}, "unix:/run/socketley/app.sock"},
    {"--shards", "SPKTD", "int", "Shards", "Worker processes sharing the port: the way one runtime uses more than one core.", "Network", {}, "4"},
    {"--domain", "SPKT", "list", "Names", "The names it is reached by through the entrance; empty for its own name.", "Network", {}, "chat, api.example.com"},
    {"--cpus", "SCPKTD", "text", "CPUs", "The CPUs its I/O may run on, as 0-3,6.", "Network", {}, "0-3"},

    // ── TLS ─────────────────────────────────────────────────────────────────
    {"--tls", "SCPKT", "switch", "TLS", "Encrypt its transport: terminate TLS on its port, or dial over it.", "TLS"},
    {"--cert", "SCPKT", "path", "Certificate", "The PEM certificate (chain allowed) a listener presents.", "TLS", {}, "/etc/ssl/site.pem"},
    {"--key", "SCPKT", "path", "Key", "The PEM key of the certificate.", "TLS", {}, "/etc/ssl/site.key"},
    {"--ca", "SCPKT", "path", "CA", "Mutual TLS on a listener; the trust store of a client or a proxy's backends.", "TLS", {}, "/etc/ssl/ca.pem"},
    {"--acme", "SPKT", "list", "ACME names", "Names to get a Let's Encrypt certificate for, renewed by itself.", "TLS", {}, "example.com, www.example.com"},
    {"--acme-email", "SPKT", "text", "ACME e-mail", "The address the CA writes to about the certificate.", "TLS", {}, "ops@example.com"},

    // ── limits ──────────────────────────────────────────────────────────────
    {"--max-connections", "SPKT", "int", "Max connections", "The most clients at once.", "Limits", {}, "10000", "--max-conn"},
    {"--rate-limit", "SPK", "int", "Rate limit", "Messages a second per connection.", "Limits", {}, "100"},
    {"--global-rate-limit", "SPK", "int", "Global rate limit", "Messages a second over all connections.", "Limits", {}, "10000"},
    {"--idle-timeout", "SPKT", "duration", "Idle timeout", "Close a connection quiet this long; none is closed for it unless this is given.", "Limits", {}, "5m"},
    {"--read-buffer", "SCPKT", "size", "Read buffer", "How much one connection may send unread before it is refused.", "Limits", {}, "1M"},
    {"--write-buffer", "SCPKT", "size", "Write buffer", "How much may be owed to one connection before it is let go; 8M unless given.", "Limits", {}, "8M"},
    {"--drain", "SPKT", "switch", "Drain on stop", "Finish what is in flight before stopping.", "Limits"},
    {"--reconnect", "C", "int", "Reconnect", "Connect again, backing off, when the connection is lost: the most attempts, 0 for no end.", "Limits", {}, "0"},

    // ── output ──────────────────────────────────────────────────────────────
    {"--log", "SCPKTD", "path", "State log", "A file it appends each state change to.", "Output", {}, "/var/log/socketley/app.log"},
    {"-w", "SC", "path", "Message file", "A file every received message is written to.", "Output", {}, "/var/log/socketley/msgs"},
    {"-b", "SC", "switch", "Print messages", "Print every received message.", "Output"},
    {"-bp", "SC", "switch", "…with name", "Print them with the runtime's name before each.", "Output"},
    {"-bt", "SC", "switch", "…with time", "Print them with the time before each.", "Output"},
    {"-bpt", "SC", "switch", "…with time and name", "Print them with the time and the name before each.", "Output", {}, {}, "-btp"},

    // ── server ──────────────────────────────────────────────────────────────
    {"--mode", "S", "choice", "Mode", "Who talks: both ways, in only, out only, or one master broadcasting.", "Server", "inout,in,out,master"},
    {"--send-to", "S", "list", "Answer to", "Who the built-in path answers: sender, others, master.", "Server", {}, "sender, others"},
    {"--udp", "SC", "switch", "UDP", "Datagrams instead of a stream.", "Server"},
    {"--http", "S", "path", "Static files", "Serve this directory over HTTP.", "Server", {}, "/srv/site"},
    {"--http-cache", "S", "switch", "Files in memory", "Read the static files into memory at start.", "Server"},
    {"--master-pw", "S", "text", "Master password", "The password that claims master mode.", "Server"},
    {"--no-master-pw", "S", "switch", "No master password", "Take the master password away, which ends master mode.", "Server"},
    {"--cache", "S", "text", "Cache", "A cache runtime its scripts and clients use.", "Server", {}, "store"},
    {"-u", "S", "list", "Upstreams", "Servers it relays to, host:port each.", "Server", {}, "10.0.0.5:9000", "--upstream"},

    // ── client ──────────────────────────────────────────────────────────────
    {"-t", "C", "text", "Target", "The server it connects to, host:port.", "Client", {}, "127.0.0.1:9000"},
    {"--mode", "C", "choice", "Mode", "Both ways, receive only or send only.", "Client", "inout,in,out"},

    // ── proxy ───────────────────────────────────────────────────────────────
    {"--backend", "P", "list", "Backends", "Where requests go: host:port, https://host, unix:/path, a runtime or @group. None makes it the entrance.", "Proxy", {}, "127.0.0.1:8080, @web"},
    {"--protocol", "P", "choice", "Protocol", "HTTP routes by path and name; TCP forwards bytes.", "Proxy", "http,tcp"},
    {"--strategy", "P", "choice", "Strategy", "How a backend is picked.", "Proxy", "round-robin,random,lua"},
    {"--auth", "P", "text", "Auth", "Who may pass: bearer:<file of tokens> or basic:<credentials file>.", "Proxy", {}, "basic:/etc/socketley/storage.creds"},
    {"--redirect-https", "P", "text", "Redirect to HTTPS", "Answer every request with a redirect to HTTPS on this port (443 when empty).", "Proxy", {}, "443"},
    {"--backend-timeout", "P", "duration", "Backend timeout", "How long a backend may take to begin its answer, 2s unless given; 0 waits for ever.", "Proxy", {}, "2s"},
    {"--retry", "P", "int", "Retries", "Try a failed request this many times on the next backend.", "Proxy", {}, "2"},
    {"--retry-all", "P", "switch", "Retry POST too", "Also retry requests that are not idempotent.", "Proxy"},
    {"--health-check", "P", "choice", "Health check", "Check the backends by connecting, or by asking a path.", "Health", "tcp,http"},
    {"--health-interval", "P", "duration", "Every", "Time between two checks.", "Health", {}, "5s"},
    {"--health-path", "P", "text", "Path", "The path an HTTP check asks.", "Health", {}, "/health"},
    {"--health-threshold", "P", "int", "Failures", "Failed checks before a backend is out.", "Health", {}, "3"},
    {"--circuit-threshold", "P", "int", "Circuit after", "Errors in a row that take a backend out.", "Health", {}, "5"},
    {"--circuit-timeout", "P", "duration", "Circuit open for", "How long a backend stays out before it is tried again.", "Health", {}, "30s"},
    {"--sidecar", "P", "switch", "Sidecar", "Health checks, circuit breaker, retries and drain in one.", "Health"},
    {"--client-ca", "P", "path", "Client CA", "Clients must present a certificate signed by this CA.", "Proxy TLS", {}, "/etc/ssl/clients.pem"},
    {"--client-cert", "P", "path", "Backend certificate", "The certificate it presents to TLS backends.", "Proxy TLS"},
    {"--client-key", "P", "path", "Backend key", "That certificate's key.", "Proxy TLS"},

    // ── cache ───────────────────────────────────────────────────────────────
    {"--mode", "K", "choice", "Access", "What its clients may do: read, read and write, or everything.", "Cache", "readonly,readwrite,admin"},
    {"--persistent", "K", "path", "Persist to", "The file it is kept in across restarts.", "Cache", {}, "/var/lib/socketley/store.bin"},
    {"--persistent-interval", "K", "duration", "Journal every", "How often accepted writes reach the journal.", "Cache", {}, "1s"},
    {"--maxmemory", "K", "size", "Max memory", "The most memory its data may take.", "Cache", {}, "512M"},
    {"--eviction", "K", "choice", "When full", "Refuse writes, or evict keys.", "Cache", "noeviction,allkeys-lru,allkeys-random"},
    {"--resp", "K", "switch", "Redis protocol only", "Speak RESP to every client, without detecting it.", "Cache"},
    {"--replicate", "K", "text", "Follow", "The leader cache it follows, host:port.", "Cache", {}, "10.0.0.5:9000"},
    {"--public", "K", "switch", "Public", "Serve clients on other machines too.", "Cache"},
    {"--cluster", "K", "switch", "Cluster map", "Publish a slot map so cluster clients go straight to each shard.", "Cache"},
    {"--cluster-replica", "K", "int", "Cluster replica", "Set by `cluster create`, never by hand.", "Cache", {}, {}, {}, true},

    // ── storage ─────────────────────────────────────────────────────────────
    {"--dir", "T", "path", "Directory", "Where the buckets live. Required.", "Storage", {}, "/var/lib/socketley/storage/files"},
    {"--credentials", "T", "path", "Credentials", "A file of access:secret pairs and [users], read again when it changes.", "Storage", {}, "/etc/socketley/storage.creds"},
    {"--access-key", "T", "text", "Access key", "One access key, when there is no credentials file.", "Storage"},
    {"--secret-key", "T", "text", "Secret key", "Its secret.", "Storage"},
    {"--anonymous", "T", "switch", "Anonymous", "Let in requests without credentials, as policies allow.", "Storage"},
    {"--website-domain", "T", "list", "Website names", "Names buckets' websites are reached under.", "Storage", {}, "web.example.com"},
    {"--tls-offloaded", "T", "list", "TLS proxies", "Proxies that end TLS in front of it, whose X-Forwarded-For names the client.", "Storage", {}, "127.0.0.1"},
    {"--max-bytes", "T", "size", "Quota", "The most bytes it holds.", "Storage", {}, "500G"},
    {"--fsync", "T", "choice", "Sync to disk", "When an answered write is on the disk.", "Durability", "always,interval,never"},
    {"--fsync-interval", "T", "duration", "Sync every", "How often interval syncs.", "Durability", {}, "1s"},
    {"--scrub", "T", "duration", "Scrub every", "Read every object back once in this long and check it; never unless given.", "Durability", {}, "30d"},
    {"--compress", "T", "duration", "Compress after", "Compress a version unwritten this long; never unless given.", "Durability", {}, "7d"},
    {"--mpu-expire", "T", "duration", "Abort uploads after", "Abort a multipart upload open this long; never unless given.", "Durability", {}, "7d"},
    {"--sse-key-file", "T", "path", "Encryption key", "The 32-byte master key of server-side encryption.", "Storage extras", {}, "/etc/socketley/sse.key"},
    {"--acls", "T", "switch", "ACLs", "Buckets without ownership controls take ACLs.", "Storage extras"},
    {"--notify-targets", "T", "path", "Webhooks", "The webhooks event notifications may go to.", "Storage extras"},
    {"--replication-targets", "T", "path", "Replication targets", "The S3 endpoints buckets may replicate to.", "Storage extras"},
    {"--tiers", "T", "path", "Tiers", "The S3 endpoints lifecycle may move versions to.", "Storage extras"},
    {"--federation", "T", "path", "Federation", "The OIDC provider and LDAP directory STS trusts.", "Storage extras"},
    {"--nodes", "T", "path", "Cluster nodes", "Make it a node of a storage cluster.", "Storage extras"},

    // ── dns ─────────────────────────────────────────────────────────────────
    {"--zone", "D", "list", "Zones", "Zone names (a file is written) or zone files. Required.", "DNS", {}, "example.com"},
    {"--publish", "D", "list", "Public addresses", "The addresses runtimes' names are answered with.", "DNS", {}, "203.0.113.7"},
    {"--proxy", "D", "text", "Entrance", "The entrance it makes (none for none).", "DNS", {}, "ns-proxy"},
    {"--proxy-port", "D", "int", "Entrance port", "The entrance's port; 443 also makes the redirect on 80.", "DNS", {}, "443"},
    {"--transfer", "D", "list", "Transfer to", "Addresses that may copy the zones (AXFR): secondaries.", "DNS", {}, "203.0.113.53"},
    {"--notify", "D", "list", "Notify", "Secondaries told of each change.", "DNS", {}, "203.0.113.53"},
    {"--rrl", "D", "int", "Rate limit", "Answers a second to one network; 0 for none.", "DNS", {}, "100"},

    // ── sync ────────────────────────────────────────────────────────────────
    {"--dir", "Y", "path", "Directory", "The directory whose files are carried. Required.", "Sync", {}, "/srv/photos"},
    {"--storage", "Y", "list", "Storage", "Where they go: a runtime and a bucket, or a URL and one. Required.", "Sync", {}, "ui/photos"},
    {"--mode", "Y", "choice", "Direction", "Who carries: out to the storage, in from it, or inout both ways.", "Sync", "out,in,inout"},
    {"--credentials", "Y", "path", "Credentials", "A file holding access_key and secret_key. Required.", "Sync", {}, "/etc/socketley/sync.creds"},
    {"--prefix", "Y", "text", "Prefix", "The key everything is written under, below the bucket.", "Sync", {}, "laptop/"},
    {"--every", "Y", "text", "Walk every", "How often the whole directory is walked; never for only on a change.", "Sync", {}, "1h"},
    {"--exclude", "Y", "list", "Exclude", "Patterns not carried, against the path below the directory.", "Sync", {}, "*.tmp, .git/*"},
    {"--repositories", "Y", "path", "Repositories", "The file a storage writes for a user's own sync runtime, which pulls their git repositories.", "Sync", {}, "/var/lib/socketley/storage/ui/.ui/sync/user.json"},
};

void quote(std::string& o, std::string_view v)
{
    o += '"';
    for (char c : v)
    {
        if (c == '"' || c == '\\')
            o += '\\';
        o += c;
    }
    o += '"';
}

}   // namespace

const std::string& json()
{
    static const std::string out = [] {
        std::string o = "{\"types\":[\"server\",\"client\",\"proxy\",\"cache\",\"storage\",\"dns\"],\"flags\":[";
        bool first = true;
        for (const row& r : rows)
        {
            o += first ? "\n" : ",\n";
            first = false;
            o += "{\"flag\":";
            quote(o, r.flag);
            o += ",\"types\":[";
            bool f2 = true;
            for (char t : r.types)
            {
                const char* name = t == 'S' ? "server" : t == 'C' ? "client" : t == 'P' ? "proxy" : t == 'K' ? "cache"
                                 : t == 'T' ? "storage" : t == 'Y' ? "sync" : "dns";
                o += f2 ? "" : ",";
                f2 = false;
                quote(o, name);
            }
            o += "],\"kind\":";
            quote(o, r.kind);
            o += ",\"label\":";
            quote(o, r.label);
            o += ",\"help\":";
            quote(o, r.help);
            o += ",\"section\":";
            quote(o, r.section);
            if (!r.choices.empty())
            {
                o += ",\"choices\":";
                quote(o, r.choices);
            }
            if (!r.placeholder.empty())
            {
                o += ",\"placeholder\":";
                quote(o, r.placeholder);
            }
            if (!r.aliases.empty())
            {
                o += ",\"aliases\":";
                quote(o, r.aliases);
            }
            if (r.hidden)
                o += ",\"hidden\":true";
            o += "}";
        }
        o += "\n],\"live\":[";
        bool f3 = true;
        for (std::string_view k : live_config_keys)
        {
            o += f3 ? "" : ",";
            f3 = false;
            quote(o, k);
        }
        o += "]}";
        return o;
    }();
    return out;
}

}   // namespace runtime_schema
