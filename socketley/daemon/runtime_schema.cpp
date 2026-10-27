#include "runtime_schema.h"
#include "../shared/runtime/runtime_config_apply.h"
#include "../shared/json/json_escape.h"

#include <string_view>

namespace runtime_schema
{

namespace
{

// The types a flag is offered for, one letter each: Server, Client, Proxy, cache (K), sTorage, Dns, sYnc, Idp, dB, Mqtt,
// mail (E).
struct row
{
    std::string_view flag, types, kind, label, help, section, choices = {}, placeholder = {}, aliases = {};
    bool hidden = false;
};

constexpr row rows[] = {
    // ── basics ──────────────────────────────────────────────────────────────
    {"-p", "SCPKTDIBME", "int", "Port", "The port it listens on (a client: the port of its target).", "Basics", {}, "8080"},
    {"-s", "SCPKTDIBME", "switch", "Start now", "Start it as soon as it is made.", "Basics"},
    {"-g", "SCPKTDME", "text", "Group", "A group its proxies reach all members of with --backend @group.", "Basics", {}, "web", "--group"},
    {"--lua", "SCPKTME", "path", "Lua script", "A script with the runtime's callbacks, run at start.", "Basics", {}, "/etc/socketley/app.lua"},
    {"--test", "SCPKTDIBME", "switch", "Dry run", "Check the type, the name and every flag, and keep nothing.", "Basics", {}, {}, {}, true},

    // ── network ─────────────────────────────────────────────────────────────
    {"--bind", "SPKTDIBME", "text", "Bind address", "The address the port is bound on alone, such as 127.0.0.1 for one only a proxy here reaches.", "Network", {}, "127.0.0.1"},
    {"--listen", "SPKT", "text", "Unix socket", "Listen on a unix socket instead of a port.", "Network", {}, "unix:/run/socketley/app.sock"},
    {"--shards", "SPKTDIBME", "int", "Shards", "Worker processes sharing the port: the way one runtime uses more than one core.", "Network", {}, "4"},
    {"--domain", "SPKTIBE", "list", "Names", "The names it is reached by through the entrance; empty for its own name.", "Network", {}, "chat, api.example.com"},
    {"--cpus", "SCPKTDIBME", "text", "CPUs", "The CPUs its I/O may run on, as 0-3,6.", "Network", {}, "0-3"},

    // ── TLS ─────────────────────────────────────────────────────────────────
    {"--tls", "SCPKTME", "switch", "TLS", "Encrypt its transport: terminate TLS on its port, or dial over it.", "TLS"},
    {"--cert", "SCPKTME", "path", "Certificate", "The PEM certificate (chain allowed) a listener presents.", "TLS", {}, "/etc/ssl/site.pem"},
    {"--key", "SCPKTME", "path", "Key", "The PEM key of the certificate.", "TLS", {}, "/etc/ssl/site.key"},
    {"--ca", "SCPKTM", "path", "CA", "Mutual TLS on a listener; the trust store of a client or a proxy's backends.", "TLS", {}, "/etc/ssl/ca.pem"},
    {"--acme", "SPKT", "list", "ACME names", "Names to get a Let's Encrypt certificate for, renewed by itself.", "TLS", {}, "example.com, www.example.com"},
    {"--acme-email", "SPKT", "text", "ACME e-mail", "The address the CA writes to about the certificate.", "TLS", {}, "ops@example.com"},

    // ── limits ──────────────────────────────────────────────────────────────
    {"--max-connections", "SPKTIBME", "int", "Max connections", "The most clients at once.", "Limits", {}, "10000", "--max-conn"},
    {"--rate-limit", "SPK", "int", "Rate limit", "Messages a second per connection.", "Limits", {}, "100"},
    {"--global-rate-limit", "SPK", "int", "Global rate limit", "Messages a second over all connections.", "Limits", {}, "10000"},
    {"--idle-timeout", "SPKT", "duration", "Idle timeout", "Close a connection quiet this long; none is closed for it unless this is given.", "Limits", {}, "5m"},
    {"--read-buffer", "SCPKT", "size", "Read buffer", "How much one connection may send unread before it is refused.", "Limits", {}, "1M"},
    {"--write-buffer", "SCPKTM", "size", "Write buffer", "How much may be owed to one connection before it is let go; 8M unless given.", "Limits", {}, "8M"},
    {"--drain", "SPKT", "switch", "Drain on stop", "Finish what is in flight before stopping.", "Limits"},
    {"--reconnect", "C", "int", "Reconnect", "Connect again, backing off, when the connection is lost: the most attempts, 0 for no end.", "Limits", {}, "0"},

    // ── output ──────────────────────────────────────────────────────────────
    {"--log", "SCPKTDME", "path", "State log", "A file it appends each state change to.", "Output", {}, "/var/log/socketley/app.log"},
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
    {"--sync", "T", "choice", "Sync runtimes", "Runtimes that pull users' git repositories: none, one for all, or one each.", "Storage extras", "never,active,per-user"},
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
    {"--dnssec", "D", "switch", "DNSSEC", "Signs its zones; the parent takes the DS socketley dns ds prints.", "DNS", {}, ""},

    // ── sync ────────────────────────────────────────────────────────────────
    {"--dir", "Y", "path", "Directory", "The directory whose files are carried. Required.", "Sync", {}, "/srv/photos"},
    {"--storage", "Y", "list", "Storage", "Where they go: a runtime and a bucket, or a URL and one. Required.", "Sync", {}, "ui/photos"},
    {"--mode", "Y", "choice", "Direction", "Who carries: out to the storage, in from it, or inout both ways.", "Sync", "out,in,inout"},
    {"--credentials", "Y", "path", "Credentials", "A file holding access_key and secret_key. Required.", "Sync", {}, "/etc/socketley/sync.creds"},
    {"--prefix", "Y", "text", "Prefix", "The key everything is written under, below the bucket.", "Sync", {}, "laptop/"},
    {"--every", "Y", "text", "Walk every", "How often the whole directory is walked; never for only on a change.", "Sync", {}, "1h"},
    {"--exclude", "Y", "list", "Exclude", "Patterns not carried, against the path below the directory.", "Sync", {}, "*.tmp, .git/*"},
    {"--clients", "I", "path", "Clients", "The applications that sign in through it: id, secret or -, and redirect addresses a line.", "Identity", {}, "/etc/socketley/idp.clients"},
    {"--issuer", "I", "text", "Issuer", "The https address it is reached at; https://<first name> when not given.", "Identity", {}, "https://auth.example.com"},
    {"--idp", "T", "text", "Identity provider", "The idp runtime whose sign-in the web interface takes, its users being the users of the same name here.", "Storage", {}, "auth"},
    {"--cookie-domain", "I", "text", "Cookie domain", "The domain whose names share one sign-in, for a proxy's --auth idp:.", "Identity", {}, "example.com"},
    {"--ssh-ca", "I", "int", "SSH certificates", "Signs SSH certificates for signed-in users, holding this many hours; off when not given.", "Identity", {}, "8"},
    {"--schema", "B", "path", "Schema", "The collections, a line each: name, access (private, owner, shared, public, catalog) and indexed fields.", "Database", {}, "/etc/socketley/db.schema"},
    {"--keys", "B", "path", "Keys", "Service keys a backend sends as Authorization: Bearer, name and secret a line.", "Database", {}, "/etc/socketley/db.keys"},
    {"--idp", "B", "text", "Identity provider", "The idp runtime whose accounts own documents and sign in by its cookie or access tokens.", "Database", {}, "auth"},
    {"--idp-audience", "B", "list", "Token clients", "The idp's clients whose access tokens it takes; a token of any other is refused.", "Database", {}, "spa"},
    {"--origins", "B", "list", "Web origins", "The pages a browser may call it from, with its sign-in; * for any, without it.", "Database", {}, "https://app.example.com"},
    {"--max-bytes", "B", "size", "Quota", "The most bytes the documents hold.", "Database", {}, "2G"},
    {"--cache", "B", "size", "Cache", "The memory the documents last read are kept in; the rest come from the disk.", "Database", {}, "256M"},
    {"--replicate", "B", "text", "Copy of", "The http or https address of the database this one follows; a copy answers reads.", "Replication", {}, "https://data.example.com"},
    {"--replicate-key", "B", "path", "Its key", "A file holding a key of that database.", "Replication", {}, "/etc/socketley/db.replica-key"},
    {"--backup-dir", "B", "path", "Backups", "The directory backups are written into.", "Backups", {}, "/var/backups/socketley"},
    {"--backup-every", "B", "duration", "Back up every", "How often a backup is taken.", "Backups", {}, "1d"},
    {"--backup-keep", "B", "int", "Keep", "How many backups are kept.", "Backups", {}, "7"},
    {"--repositories", "Y", "path", "Repositories", "The file a storage writes for a user's own sync runtime, which pulls their git repositories.", "Sync", {}, "/var/lib/socketley/storage/ui/.ui/sync/user.json"},

    // ── mqtt ────────────────────────────────────────────────────────────────
    {"--users", "M", "path", "Users", "Accounts that sign in with a password, user:hash a line as `socketley mqtt-passwd` writes them.", "MQTT", {}, "/etc/socketley/mqtt.users"},
    {"--idp", "M", "text", "Identity provider", "The idp runtime whose access tokens sign clients in, given as the password.", "MQTT", {}, "auth"},
    {"--idp-audience", "M", "list", "Token clients", "The idp's clients whose access tokens it takes; a token of any other is refused.", "MQTT", {}, "spa"},
    {"--acl", "M", "path", "Access rules", "Who may publish and subscribe to what: user, topic and pattern lines, read again when it changes.", "MQTT", {}, "/etc/socketley/mqtt.acl"},
    {"--anonymous", "M", "switch", "Anonymous", "Let clients in without credentials, as the access rules allow.", "MQTT"},
    {"--routes", "M", "path", "Topic rules", "Where messages go besides their subscribers: a cache, a db, a storage, a server or another broker.", "MQTT", {}, "/etc/socketley/mqtt.routes"},
    {"--ws", "M", "int", "WebSocket port", "A port browsers reach the broker on over WebSocket.", "MQTT", {}, "8083"},
    {"--persistent", "M", "path", "Persist to", "The file sessions and retained messages are kept in across restarts; on for one under the state directory.", "MQTT", {}, "on"},
    {"--persistent-interval", "M", "duration", "Write every", "How often what changed reaches that file.", "MQTT", {}, "1s"},
    {"--max-packet", "M", "size", "Max packet", "The largest packet a client may send; 256K unless given.", "MQTT limits", {}, "256K"},
    {"--session-expiry", "M", "duration", "Session expiry", "The longest a session outlives its connection; 1d unless given.", "MQTT limits", {}, "1d"},
    {"--session-queue", "M", "int", "Session queue", "Messages kept for one session while its client is away; 1000 unless given.", "MQTT limits", {}, "1000"},
    {"--retained-max", "M", "size", "Retained bytes", "The most bytes retained messages take; 64M unless given.", "MQTT limits", {}, "64M"},
    {"--max-sessions", "M", "int", "Max sessions", "The most sessions it keeps, connected or not; 100000 unless given.", "MQTT limits", {}, "100000"},
    {"--keepalive-max", "M", "int", "Max keep alive", "The longest keep alive a client is granted, in seconds; 1200 unless given.", "MQTT limits", {}, "1200"},

    // ── mail ────────────────────────────────────────────────────────────────
    {"--mail-domain", "E", "list", "Mail domains", "The domains whose mail it takes; the zones of --dns where none is given.", "Mail", {}, "example.com"},
    {"--dns", "E", "text", "DNS runtime", "The dns runtime whose zones are its domains, given their MX, SPF, DKIM and DMARC records.", "Mail", {}, "ns"},
    {"--hostname", "E", "text", "Host name", "The name it greets with and its MX records name; mail.<first domain> unless given.", "Mail", {}, "mail.example.com"},
    {"--no-reply", "E", "switch", "No-reply sender", "Send as no-reply@<domain> where no sender is said, and take no mail to that address.", "Mail"},
    {"--idp", "E", "text", "Identity provider", "The idp runtime whose users have mailboxes here and sign in to send.", "Mail", {}, "auth"},
    {"--idp-audience", "E", "list", "Token clients", "The idp's clients whose access tokens it takes; a token of any other is refused.", "Mail", {}, "spa"},
    {"--storage", "E", "text", "Mailboxes", "The storage runtime, and bucket, the mailboxes are kept in.", "Mail", {}, "files/mail"},
    {"--users", "E", "path", "Users", "Accounts that sign in to send, user:hash a line as `socketley mqtt-passwd` writes them.", "Mail", {}, "/etc/socketley/mail.users"},
    {"--aliases", "E", "path", "Aliases", "Addresses taken besides the users', `address target` a line.", "Mail", {}, "/etc/socketley/mail.aliases"},
    {"--relay", "E", "text", "Smarthost", "Send all mail for elsewhere through this server, smtp[s]://[user:password@]host[:port].", "Mail", {}, "smtps://user:pw@smtp.example.net"},
    {"--submission", "E", "int", "Submission port", "A port users send from with STARTTLS and a password.", "Mail ports", {}, "587"},
    {"--submissions", "E", "int", "Submission over TLS", "A port users send from over TLS from the first byte.", "Mail ports", {}, "465"},
    {"--imap", "E", "int", "IMAP port", "A port mail clients read the mailboxes on.", "Mail ports", {}, "143"},
    {"--imaps", "E", "int", "IMAP over TLS", "A port mail clients read the mailboxes on over TLS.", "Mail ports", {}, "993"},
    {"--sieve", "E", "int", "ManageSieve port", "A port users put their Sieve filters on, over STARTTLS.", "Mail ports", {}, "4190"},
    {"--dnsbl", "E", "text", "DNS blocklists", "Zones listing addresses whose mail is refused when they connect.", "Mail limits", {}, "zen.spamhaus.org"},
    {"--pop3", "E", "int", "POP3 port", "A port mail clients fetch the INBOX on with POP3.", "Mail ports", {}, "110"},
    {"--pop3s", "E", "int", "POP3 over TLS", "A port mail clients fetch the INBOX on over TLS.", "Mail ports", {}, "995"},
    {"--jmap", "E", "int", "JMAP port", "A port mail clients and web apps read and send mail on with JMAP.", "Mail ports", {}, "8443"},
    {"--web", "E", "int", "Webmail port", "The webmail and JMAP in plain HTTP on 127.0.0.1, for the entrance --domain names it through.", "Mail ports", {}, "9480"},
    {"--lmtp", "E", "int", "LMTP port", "A port a mail server on this machine hands mail for the mailboxes to.", "Mail ports", {}, "24"},
    {"--mta-sts-port", "E", "int", "MTA-STS port", "An HTTPS port the MTA-STS policy of its domains is served on.", "Mail ports", {}, "443"},
    {"--greylist", "E", "duration", "Greylist delay", "Tell a first sender, recipient and network to come back after this long.", "Mail limits", {}, "5m"},
    {"--rspamd", "E", "text", "Rspamd", "The Rspamd a stranger's mail is scored by, http://host:port.", "Mail limits", {}, "http://127.0.0.1:11333"},
    {"--recipient-delimiter", "E", "text", "Subaddress delimiter", "What divides a user from a tag, user+tag; none for no tags.", "Mail", {}, "+"},
    {"--reports", "E", "switch", "Send reports", "Send the DMARC and TLS reports other domains ask for.", "Mail", {}, ""},
    {"--refuse-attachments", "E", "list", "Refused attachments", "Extensions mail from elsewhere is refused for: default for programs, scripts and macro documents, or none.", "Mail", {}, "default"},
    {"--clamav", "E", "text", "ClamAV", "The clamd every message from elsewhere is scanned by, host:port or its socket.", "Mail", {}, "127.0.0.1:3310"},
    {"--dmarc-policy", "E", "choice", "DMARC policy", "What its DMARC record asks of mail that fails its checks; quarantine unless given.", "Mail", "none,quarantine,reject"},
    {"--bimi", "E", "text", "BIMI logo", "The https URL of its SVG logo, and after a comma its mark certificate's, for the BIMI record.", "Mail", {}, "https://example.com/logo.svg"},
    {"--dmarc-rua", "E", "text", "DMARC reports to", "Where other servers send DMARC reports of its domains: the rua= it publishes.", "Mail", {}, "dmarc@example.com"},
    {"--tls-rpt", "E", "text", "TLS reports to", "Where other servers send TLS reports of its domains (RFC 8460).", "Mail", {}, "tlsrpt@example.com"},
    {"--mta-sts", "E", "text", "MTA-STS mode", "Publish an MTA-STS policy of this mode for its domains: enforce or testing.", "Mail", {}, "enforce"},
    {"--default-quota", "E", "size", "Default quota", "What a mailbox holds where the user has no mail_quota of their own.", "Mail limits", {}, "1G"},
    {"--quota-warn", "E", "int", "Quota warning", "At what percent of the quota a user is told, once, 0 for never.", "Mail limits", {}, "90"},
    {"--arc-trust", "E", "text", "ARC forwarders", "Forwarders whose ARC seal lets mail that fails DMARC through.", "Mail", {}, "lists.example.org"},
    {"--dkim-next", "E", "text", "Next DKIM selector", "A DKIM key made and published before it signs, for rotation.", "Mail", {}, "skl2"},
    {"--notify-targets", "E", "path", "Event targets", "Where each message stored in a mailbox is told: webhooks and other runtimes, `name url` a line.", "Mail", {}, "/etc/socketley/mail.targets"},
    {"--max-size", "E", "size", "Max message", "The largest message taken; 25M unless given.", "Mail limits", {}, "25M"},
    {"--max-recipients", "E", "int", "Max recipients", "The most recipients of one message; 100 unless given.", "Mail limits", {}, "100"},
    {"--autoexpunge", "E", "duration", "Empty Junk and Trash", "How long a message stays in Junk or Trash before it is gone; never unless given.", "Mail limits", {}, "30d"},
    {"--queue-lifetime", "E", "duration", "Queue lifetime", "How long a message is tried before it is bounced; 5d unless given.", "Mail limits", {}, "5d"},
    {"--dkim-selector", "E", "text", "DKIM selector", "The selector its DKIM key is published under; skl unless given.", "Mail", {}, "skl"},
};

}   // namespace

// The key `show` and `import` name a flag's value by in a runtime's state, the dashboard's to read and write.
struct state_key_row
{
    std::string_view flag, key;
};
constexpr state_key_row state_keys[] = {
    {"-p", "port"},
    {"-g", "group"},
    {"--lua", "lua_script"},
    {"--bind", "bind"},
    {"--listen", "listen"},
    {"--shards", "shards"},
    {"--domain", "domain"},
    {"--cpus", "cpus"},
    {"--tls", "tls"},
    {"--cert", "cert_path"},
    {"--key", "key_path"},
    {"--ca", "ca_path"},
    {"--acme", "acme_domains"},
    {"--acme-email", "acme_email"},
    {"--max-connections", "max_connections"},
    {"--rate-limit", "rate_limit"},
    {"--global-rate-limit", "global_rate_limit"},
    {"--idle-timeout", "idle_timeout"},
    {"--read-buffer", "read_buffer"},
    {"--write-buffer", "write_buffer"},
    {"--drain", "drain"},
    {"--reconnect", "reconnect"},
    {"--log", "log_file"},
    {"-w", "write_file"},
    {"-b", "bash_output"},
    {"-bp", "bash_prefix"},
    {"-bt", "bash_timestamp"},
    {"--send-to", "send_to"},
    {"--udp", "udp"},
    {"--http", "http_dir"},
    {"--http-cache", "http_cache"},
    {"--master-pw", "master_pw"},
    {"--cache", "cache_name"},
    {"-u", "upstreams"},
    {"-t", "target"},
    {"--backend", "backends"},
    {"--protocol", "protocol"},
    {"--strategy", "strategy"},
    {"--auth", "auth"},
    {"--redirect-https", "redirect_https"},
    {"--backend-timeout", "backend_timeout"},
    {"--retry", "retry_count"},
    {"--retry-all", "retry_all"},
    {"--health-check", "health_check"},
    {"--health-interval", "health_interval"},
    {"--health-path", "health_path"},
    {"--health-threshold", "health_threshold"},
    {"--circuit-threshold", "circuit_threshold"},
    {"--circuit-timeout", "circuit_timeout"},
    {"--client-ca", "mesh_client_ca"},
    {"--client-cert", "mesh_client_cert"},
    {"--client-key", "mesh_client_key"},
    {"--persistent", "persistent_path"},
    {"--persistent-interval", "persistent_interval"},
    {"--maxmemory", "max_memory"},
    {"--eviction", "eviction"},
    {"--resp", "resp_forced"},
    {"--replicate", "replicate_target"},
    {"--public", "public"},
    {"--cluster", "cluster"},
    {"--dir", "dir"},
    {"--credentials", "credentials"},
    {"--access-key", "access_key"},
    {"--secret-key", "secret_key"},
    {"--anonymous", "anonymous"},
    {"--website-domain", "website_domain"},
    {"--tls-offloaded", "tls_offloaded"},
    {"--max-bytes", "max_bytes"},
    {"--fsync", "fsync"},
    {"--sync", "sync"},
    {"--fsync-interval", "fsync_interval"},
    {"--scrub", "scrub"},
    {"--compress", "compress"},
    {"--mpu-expire", "mpu_expire"},
    {"--sse-key-file", "sse_key_file"},
    {"--acls", "acls"},
    {"--notify-targets", "notify_targets"},
    {"--replication-targets", "replication_targets"},
    {"--tiers", "tiers"},
    {"--federation", "federation"},
    {"--nodes", "nodes"},
    {"--zone", "zones"},
    {"--publish", "publish"},
    {"--proxy", "proxy"},
    {"--transfer", "transfer"},
    {"--notify", "notify"},
    {"--rrl", "rrl"},
    {"--dnssec", "dnssec"},
    {"--clients", "clients"},
    {"--issuer", "issuer"},
    {"--cookie-domain", "cookie_domain"},
    {"--ssh-ca", "ssh_ca"},
    {"--idp", "idp"},
    {"--idp-audience", "idp_audience"},
    {"--schema", "schema"},
    {"--keys", "keys"},
    {"--origins", "origins"},
    {"--replicate-key", "replicate_key"},
    {"--backup-dir", "backup_dir"},
    {"--backup-every", "backup_every"},
    {"--backup-keep", "backup_keep"},
    {"--storage", "storage"},
    {"--prefix", "prefix"},
    {"--exclude", "exclude"},
    {"--every", "every"},
    {"--repositories", "repositories"},
    {"--users", "users"},
    {"--acl", "acl"},
    {"--routes", "routes"},
    {"--ws", "ws_port"},
    {"--max-packet", "max_packet"},
    {"--session-expiry", "session_expiry"},
    {"--session-queue", "session_queue"},
    {"--retained-max", "retained_max"},
    {"--max-sessions", "max_sessions"},
    {"--keepalive-max", "keepalive_max"},
    {"--mail-domain", "mail_domain"},
    {"--dns", "dns"},
    {"--hostname", "hostname"},
    {"--no-reply", "no_reply"},
    {"--aliases", "aliases"},
    {"--relay", "relay"},
    {"--submission", "submission"},
    {"--submissions", "submissions"},
    {"--imap", "imap"},
    {"--imaps", "imaps"},
    {"--sieve", "sieve"},
    {"--dnsbl", "dnsbl"},
    {"--pop3", "pop3"},
    {"--pop3s", "pop3s"},
    {"--jmap", "jmap"},
    {"--web", "web"},
    {"--lmtp", "lmtp"},
    {"--mta-sts-port", "mta_sts_port"},
    {"--greylist", "greylist"},
    {"--rspamd", "rspamd"},
    {"--recipient-delimiter", "recipient_delimiter"},
    {"--reports", "reports"},
    {"--dmarc-rua", "dmarc_rua"},
    {"--dmarc-policy", "dmarc_policy"},
    {"--refuse-attachments", "refuse_attachments"},
    {"--clamav", "clamav"},
    {"--bimi", "bimi"},
    {"--tls-rpt", "tls_rpt"},
    {"--mta-sts", "mta_sts"},
    {"--default-quota", "default_quota"},
    {"--quota-warn", "quota_warn"},
    {"--arc-trust", "arc_trust"},
    {"--dkim-next", "dkim_next"},
    {"--max-size", "max_size"},
    {"--max-recipients", "max_recipients"},
    {"--queue-lifetime", "queue_lifetime"},
    {"--autoexpunge", "autoexpunge"},
    {"--dkim-selector", "dkim_selector"},
};

// A flag one type keeps under another key than the rest: a cache's access mode, a db's cache size and leader.
std::string_view state_key(const row& r)
{
    if (r.flag == "--mode" && r.types == "K")
        return "cache_mode";
    if (r.types == "B" && (r.flag == "--cache" || r.flag == "--replicate"))
        return r.flag.substr(2);
    if (r.flag == "--mode")
        return "mode";
    for (const state_key_row& k : state_keys)
        if (k.flag == r.flag)
            return k.key;
    return {};
}

bool is_path_flag(std::string_view flag)
{
    // An empty argument is no flag, though it equals every row's empty alias.
    if (flag.empty())
        return false;
    for (const row& r : rows)
        if (r.kind == "path" && (r.flag == flag || r.aliases == flag))
            return true;
    return false;
}

namespace
{

char letter_of(runtime_type type)
{
    switch (type)
    {
        case runtime_server:  return 'S';
        case runtime_client:  return 'C';
        case runtime_proxy:   return 'P';
        case runtime_cache:   return 'K';
        case runtime_storage: return 'T';
        case runtime_dns:     return 'D';
        case runtime_sync:    return 'Y';
        case runtime_idp:     return 'I';
        case runtime_db:      return 'B';
        case runtime_mqtt:    return 'M';
        case runtime_mail:    return 'E';
        default:              return 0;
    }
}

}   // namespace

std::vector<flag_entry> flags_for(runtime_type type)
{
    std::vector<flag_entry> out;
    const char letter = letter_of(type);
    if (!letter)
        return out;
    for (const row& r : rows)
        if (r.types.find(letter) != std::string_view::npos)
            out.push_back({r.flag, r.kind, state_key(r)});
    return out;
}

bool offered(std::string_view flag, runtime_type type)
{
    const char letter = letter_of(type);
    if (!letter || flag.empty())
        return false;
    for (const row& r : rows)
        if ((r.flag == flag || r.aliases == flag) && r.types.find(letter) != std::string_view::npos)
            return true;
    return false;
}

const std::string& json()
{
    static const std::string out = [] {
        std::string o = "{\"types\":[\"server\",\"client\",\"proxy\",\"cache\",\"storage\",\"dns\",\"sync\",\"idp\",\"db\",\"mqtt\",\"mail\"],\"flags\":[";
        bool first = true;
        for (const row& r : rows)
        {
            o += first ? "\n" : ",\n";
            first = false;
            o += "{\"flag\":";
            socketley::json::quote_into(o, r.flag);
            o += ",\"types\":[";
            bool f2 = true;
            for (char t : r.types)
            {
                const char* name = t == 'S' ? "server" : t == 'C' ? "client" : t == 'P' ? "proxy" : t == 'K' ? "cache"
                                 : t == 'T' ? "storage" : t == 'Y' ? "sync" : t == 'I' ? "idp" : t == 'B' ? "db" : t == 'M' ? "mqtt" : t == 'E' ? "mail" : "dns";
                o += f2 ? "" : ",";
                f2 = false;
                socketley::json::quote_into(o, name);
            }
            o += "],\"kind\":";
            socketley::json::quote_into(o, r.kind);
            o += ",\"label\":";
            socketley::json::quote_into(o, r.label);
            o += ",\"help\":";
            socketley::json::quote_into(o, r.help);
            o += ",\"section\":";
            socketley::json::quote_into(o, r.section);
            if (!r.choices.empty())
            {
                o += ",\"choices\":";
                socketley::json::quote_into(o, r.choices);
            }
            if (!r.placeholder.empty())
            {
                o += ",\"placeholder\":";
                socketley::json::quote_into(o, r.placeholder);
            }
            if (!r.aliases.empty())
            {
                o += ",\"aliases\":";
                socketley::json::quote_into(o, r.aliases);
            }
            if (const std::string_view k = state_key(r); !k.empty())
            {
                o += ",\"key\":";
                socketley::json::quote_into(o, k);
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
            socketley::json::quote_into(o, k);
        }
        o += "]}";
        return o;
    }();
    return out;
}

}   // namespace runtime_schema
