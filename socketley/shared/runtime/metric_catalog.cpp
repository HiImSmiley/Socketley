#include "metric_catalog.h"

#include <algorithm>
#include <array>
#include <charconv>

#include "stats_text.h"

namespace socketley::metric_catalog
{

const char* kind_name(kind k)
{
    switch (k)
    {
        case kind::counter: return "counter";
        case kind::gauge:   return "gauge";
        case kind::untyped: return "untyped";
        case kind::histogram: return "histogram";
    }
    return "untyped";
}

namespace
{

constexpr field counter(std::string_view key, std::string_view name, std::string_view help, merge how = merge::sum)
{
    return field{key, family{name, kind::counter, help}, {}, {}, how};
}

constexpr field gauge(std::string_view key, std::string_view name, std::string_view help, merge how = merge::sum)
{
    return field{key, family{name, kind::gauge, help}, {}, {}, how};
}

// A latency_histogram line, written as the family's buckets, sum and count.
constexpr field histogram(std::string_view key, std::string_view name, std::string_view help)
{
    return field{key, family{name, kind::histogram, help}};
}

// A figure of a family several figures share, told apart by one label.
constexpr field member(std::string_view key, const family& f, std::string_view label, std::string_view value)
{
    return field{key, f, label, value};
}

// A figure left to the catch-all family, named for how its shards merge.
constexpr field unnamed(std::string_view key, merge how)
{
    return field{key, family{}, {}, {}, how};
}

// ── storage ─────────────────────────────────────────────────────────────────

constexpr family storage_requests{"socketley_storage_requests_total", kind::counter,
                                  "Requests a storage runtime served, by operation."};
constexpr family storage_errors{"socketley_storage_errors_total", kind::counter,
                                "S3 errors a storage runtime answered, by code."};

constexpr field storage_fields[] = {
    gauge("buckets", "socketley_storage_buckets", "Buckets a storage runtime holds.", merge::first),
    gauge("objects", "socketley_storage_objects", "Objects a storage runtime holds."),
    gauge("bytes", "socketley_storage_bytes_stored", "Object bytes a storage runtime holds."),
    counter("bytes_in", "socketley_storage_bytes_received_total",
            "Bytes a storage runtime read from its clients, including protocol framing."),
    counter("bytes_out", "socketley_storage_bytes_sent_total",
            "Bytes a storage runtime wrote to its clients, including protocol framing."),
    counter("zero_copy_bytes", "socketley_storage_zero_copy_bytes_total",
            "Object bytes sent from file to socket without entering the process."),
    counter("tls_handshakes", "socketley_storage_tls_handshakes_total", "TLS handshakes a storage runtime completed."),
    counter("tls_failures", "socketley_storage_tls_failures_total", "TLS handshakes that failed or never finished."),
    counter("h2_conns", "socketley_storage_http2_connections_total", "Connections a storage runtime served over HTTP/2."),
    counter("h2_streams", "socketley_storage_http2_streams_total",
            "HTTP/2 streams a storage runtime opened, one per request."),
    counter("h2_refused", "socketley_storage_http2_refused_total",
            "HTTP/2 streams refused for the limit on those open at once."),
    counter("h2_resets_in", "socketley_storage_http2_resets_received_total", "HTTP/2 streams the client reset."),
    counter("h2_resets_out", "socketley_storage_http2_resets_sent_total", "HTTP/2 streams a storage runtime reset."),
    counter("h2_goaways", "socketley_storage_http2_goaways_total", "HTTP/2 connections a storage runtime ended with GOAWAY."),
    counter("h3_conns", "socketley_storage_http3_connections_total", "QUIC connections a storage runtime served over HTTP/3."),
    gauge("h3_open", "socketley_storage_http3_open_connections", "QUIC connections a storage runtime has open now."),
    counter("h3_streams", "socketley_storage_http3_streams_total",
            "HTTP/3 streams a storage runtime opened, one per request."),
    counter("h3_retries", "socketley_storage_http3_retries_total",
            "Retry packets a storage runtime sent to make new clients prove their address."),
    counter("h3_forwarded", "socketley_storage_http3_forwarded_total",
            "QUIC packets a shard handed to the shard holding their connection, after a client moved."),
    counter("notify_sent", "socketley_storage_notify_sent_total", "Event notifications delivered."),
    counter("notify_failed", "socketley_storage_notify_failed_total", "Event notification attempts that failed."),
    gauge("notify_queued", "socketley_storage_notify_queued", "Event notifications waiting to be delivered."),
    counter("notify_dropped", "socketley_storage_notify_dropped_total", "Event notifications dropped past the queue's bound."),
    gauge("replication_pending", "socketley_storage_replication_pending",
          "Versions and delete markers waiting to be replicated."),
    counter("replication_completed", "socketley_storage_replication_completed_total",
            "Versions and delete markers a replication target took."),
    counter("replication_failed", "socketley_storage_replication_failed_total",
            "Versions a replication target refused for good."),
    counter("replication_retries", "socketley_storage_replication_retries_total", "Replication attempts tried again."),
    counter("replication_bytes", "socketley_storage_replication_bytes_total", "Body bytes replication targets took."),
    gauge("cluster_pending", "socketley_storage_cluster_pending", "Changes waiting for another node of the cluster."),
    counter("cluster_sent", "socketley_storage_cluster_sent_total", "Changes the other nodes of the cluster took."),
    counter("cluster_failed", "socketley_storage_cluster_failed_total", "Changes the other nodes refused for good."),
    counter("cluster_in", "socketley_storage_cluster_received_total", "Bucket, IAM and share records other nodes sent."),
    gauge("cluster_seeding", "socketley_storage_cluster_seeding",
          "Nodes this runtime has not yet sent everything it holds."),
    counter("cluster_overflows", "socketley_storage_cluster_overflows_total", "Queues for a node let go for a full resend."),
    counter("cluster_synced", "socketley_storage_cluster_synced_total", "Writes answered once the nodes sync names had them."),
    counter("cluster_sync_timeouts", "socketley_storage_cluster_sync_timeouts_total",
            "Writes answered when their wait for the nodes was over."),
    counter("scrub_objects", "socketley_storage_scrub_objects_total", "Versions the scrub read back."),
    counter("scrub_bytes", "socketley_storage_scrub_bytes_total", "Bytes the scrub read back."),
    counter("scrub_corrupt", "socketley_storage_scrub_corrupt_total", "Copies the scrub found whose bytes are not their MD5's."),
    counter("scrub_passes", "socketley_storage_scrub_passes_total", "Whole passes of the scrub."),
    counter("scrub_heals", "socketley_storage_scrub_heals_total", "Corrupt copies another node was asked to send again."),
    counter("scrub_unhealed", "socketley_storage_scrub_unhealed_total", "Corrupt copies no other node held whole."),
    counter("compressed_objects", "socketley_storage_compressed_objects_total", "Versions compressed where they lie."),
    counter("compressed_bytes_in", "socketley_storage_compressed_bytes_in_total", "Bytes of the versions compressed."),
    counter("compressed_bytes_out", "socketley_storage_compressed_bytes_out_total",
            "What the versions compressed take on disk."),
    counter("tier_moved", "socketley_storage_tier_moved_total", "Versions a lifecycle moved to a tier."),
    counter("tier_moved_bytes", "socketley_storage_tier_moved_bytes_total", "Bytes of the versions moved to a tier."),
    counter("tier_failed", "socketley_storage_tier_failed_total", "Moves to a tier that did not finish."),
    counter("tier_reads", "socketley_storage_tier_reads_total", "Windows read back from a tier for a client."),
    counter("tier_read_failures", "socketley_storage_tier_read_failures_total", "Windows a tier did not give back."),
    counter("lifecycle_expired", "socketley_storage_lifecycle_expired_total", "Objects and versions lifecycle rules removed."),
    counter("lifecycle_aborted", "socketley_storage_lifecycle_aborted_total", "Uploads lifecycle rules aborted."),
    counter("multipart_completed", "socketley_storage_multipart_completed_total", "Multipart uploads completed."),
    counter("media_made", "socketley_storage_media_made_total", "Thumbnails and stream segments made."),
    counter("media_failed", "socketley_storage_media_failed_total", "Media that could not be made."),
    counter("fsyncs", "socketley_storage_fsyncs_total", "Syncs the store made for durability."),
    histogram("request_latency", "socketley_storage_request_duration_seconds",
              "S3 requests from their first byte to their whole answer sent."),
    member("gets", storage_requests, "op", "get"),
    member("heads", storage_requests, "op", "head"),
    member("puts", storage_requests, "op", "put"),
    member("deletes", storage_requests, "op", "delete"),
    member("lists", storage_requests, "op", "list"),
    member("copies", storage_requests, "op", "copy"),
    field{"error_", storage_errors, "code", {}, merge::sum, true},
    // Every shard holds a whole copy of these.
    unnamed("max_bytes", merge::first),
    unnamed("tls", merge::first),
    unnamed("shard_index", merge::first),
};

// ── mail ────────────────────────────────────────────────────────────────────

constexpr field mail_fields[] = {
    counter("mail_received", "socketley_mail_received_total", "Messages a mail runtime took."),
    counter("mail_delivered", "socketley_mail_delivered_total", "Recipients a mail runtime delivered to."),
    counter("mail_deferred", "socketley_mail_deferred_total", "Tries a mail runtime put off."),
    counter("mail_bounced", "socketley_mail_bounced_total", "Recipients a mail runtime failed for good."),
    counter("mail_stored", "socketley_mail_stored_total", "Messages put into mailboxes."),
    gauge("mail_queued", "socketley_mail_queued", "Messages waiting in a mail runtime's queue."),
    gauge("mail_queued_bytes", "socketley_mail_queued_bytes", "Bytes waiting in a mail runtime's queue."),
    counter("mail_quarantined", "socketley_mail_quarantined_total", "Messages put into Junk."),
    counter("auth_failed", "socketley_mail_auth_failed_total", "Sign-ins a mail runtime refused."),
    histogram("mail_delivery_latency", "socketley_mail_delivery_duration_seconds",
              "Remote delivery attempts from a connection taking a message to the answer for its recipients, in loop "
              "turns."),
    field{"mail_self_listed", family{"socketley_mail_blocklisted", kind::gauge,
                                     "1 while a blocklist of its --dnsbl names the address a mail runtime sends from."},
          {}, {}, merge::max, false, true},
};

// ── tunnel ──────────────────────────────────────────────────────────────────

constexpr field tunnel_fields[] = {
    gauge("links", "socketley_tunnel_links", "Links a tunnel holds now: agents and people at an edge, the edge at an agent."),
    gauge("agents", "socketley_tunnel_agents", "Agents an edge knows, joined or invited."),
    counter("streams", "socketley_tunnel_streams_total", "Streams a tunnel opened for visitors and people."),
    counter("refused", "socketley_tunnel_refused_total", "Upgrades and streams a tunnel refused."),
    counter("visitors_refused", "socketley_tunnel_visitors_refused_total", "Requests a protected service's auth refused."),
    counter("bytes_in", "socketley_tunnel_bytes_in_total", "Bytes a tunnel read from its local connections and sent on."),
    counter("bytes_out", "socketley_tunnel_bytes_out_total", "Bytes a tunnel received and wrote to its local connections."),
    gauge("shares", "socketley_tunnel_shares", "Ports people share at an edge now."),
    gauge("flows", "socketley_tunnel_flows", "UDP flows a tunnel carries now, a visitor each."),
    counter("datagrams", "socketley_tunnel_datagrams_total", "UDP datagrams a tunnel carried onto its link."),
    counter("datagrams_dropped", "socketley_tunnel_datagrams_dropped_total",
            "UDP datagrams a tunnel dropped: no agent, a full link, too many flows, or cut."),
    gauge("agents_joined", "socketley_tunnel_agents_joined", "Agents an edge knows that have joined, so are expected linked."),
    gauge("agents_connected", "socketley_tunnel_agents_connected", "Agents an edge has a link to now."),
    counter("links_made", "socketley_tunnel_links_made_total", "Links a tunnel made, agents and people at an edge."),
    counter("joined", "socketley_tunnel_joins_total", "Invited agents that joined an edge."),
    counter("shared", "socketley_tunnel_shares_made_total", "Ports people shared at an edge."),
};

// ── server ──────────────────────────────────────────────────────────────────

constexpr field server_fields[] = {
    gauge("peak_connections", "socketley_server_peak_connections", "The most connections a server held at once.",
          merge::max),
    gauge("upstreams_connected", "socketley_server_upstreams_connected", "Upstreams a server has a connection to now."),
    gauge("upstreams_configured", "socketley_server_upstreams", "Upstreams a server was given.", merge::first),
    counter("cache_requests", "socketley_server_cache_requests_total", "Requests a server posted to its cache runtime."),
    gauge("cache_requests_pending", "socketley_server_cache_requests_pending",
          "Requests to its cache runtime a server is waiting on."),
    counter("cache_requests_refused", "socketley_server_cache_requests_refused_total",
            "Requests to its cache runtime refused for a full queue."),
    counter("cache_store_batches_dropped", "socketley_server_cache_store_batches_dropped_total",
            "Batches of messages for the cache a server dropped, so messages the cache does not hold."),
    histogram("http_latency", "socketley_server_http_request_duration_seconds",
              "HTTP requests from their head to their whole answer handed to the socket, in loop turns."),
    unnamed("mode", merge::first),
    unnamed("master_fd", merge::first),
};

// ── client ──────────────────────────────────────────────────────────────────

constexpr field client_fields[] = {
    counter("dial_attempts", "socketley_client_dial_attempts_total",
            "Connects a client tried, beside the connections the kernel confirmed."),
};

// ── proxy ───────────────────────────────────────────────────────────────────

constexpr field proxy_fields[] = {
    gauge("backend_connections", "socketley_proxy_backend_connections", "Connections a proxy holds to its backends now."),
    gauge("backends", "socketley_proxy_backends", "Backends a proxy was given.", merge::first),
    gauge("declared_routes", "socketley_proxy_declared_routes", "Routes a proxy enforces out of what its backends declared.",
          merge::first),
    gauge("healthy_backends", "socketley_proxy_healthy_backends", "Backends its health checks find healthy now.",
          merge::first),
    gauge("open_circuits", "socketley_proxy_open_circuits", "Backends a proxy's circuit breaker keeps closed off now.",
          merge::max),
    counter("backend_responses", "socketley_proxy_backend_responses_total",
            "Responses a proxy's backends answered whole, HTTP only."),
    counter("backend_failures", "socketley_proxy_backend_failures_total",
            "Backend connects and exchanges that failed, which its circuit breaker counts."),
    counter("files_served", "socketley_proxy_files_served_total",
            "Files a FastCGI proxy answered from --root itself, without the application server."),
    counter("files_not_modified", "socketley_proxy_files_not_modified_total",
            "Of those, the ones answered 304 because the client's copy was still the file."),
    gauge("pooled_connections", "socketley_proxy_pooled_connections", "Idle backend connections a proxy keeps for reuse."),
    gauge("parked_connections", "socketley_proxy_parked_connections",
          "Backend connections kept on a keep-alive client for its next request."),
    gauge("peak_connections", "socketley_proxy_peak_connections", "The most client connections a proxy held at once.",
          merge::max),
    counter("h2_conns", "socketley_proxy_http2_connections_total", "Connections a proxy served over HTTP/2."),
    counter("h2_streams", "socketley_proxy_http2_streams_total", "HTTP/2 streams a proxy opened, one per request."),
    counter("h2_refused", "socketley_proxy_http2_refused_total", "HTTP/2 streams refused for the limit on those open at once."),
    counter("h2_resets_in", "socketley_proxy_http2_resets_received_total", "HTTP/2 streams the client reset."),
    counter("h2_resets_out", "socketley_proxy_http2_resets_sent_total", "HTTP/2 streams a proxy reset."),
    counter("h2_goaways", "socketley_proxy_http2_goaways_total", "HTTP/2 connections a proxy ended with GOAWAY."),
    counter("h3_conns", "socketley_proxy_http3_connections_total", "QUIC connections a proxy served over HTTP/3."),
    counter("h3_streams", "socketley_proxy_http3_streams_total", "HTTP/3 streams a proxy opened, one per request."),
    counter("h3_retries", "socketley_proxy_http3_retries_total",
            "Retry packets a proxy sent to make new clients prove their address."),
    counter("h3_forwarded", "socketley_proxy_http3_forwarded_total",
            "QUIC packets a shard handed to the shard holding their connection."),
    histogram("request_latency", "socketley_proxy_request_duration_seconds",
              "HTTP requests from their head to the last byte of their backend's answer, in loop turns."),
    histogram("connect_latency", "socketley_proxy_backend_connect_duration_seconds",
              "New backend connections from the connect to its completion, in loop turns."),
    histogram("first_byte_latency", "socketley_proxy_backend_first_byte_seconds",
              "HTTP requests from the backend being asked, or connected, to its answer's first byte, in loop turns."),
};

// ── cache ───────────────────────────────────────────────────────────────────

constexpr field cache_fields[] = {
    gauge("keys", "socketley_cache_keys", "Keys a cache holds."),
    counter("commands_processed", "socketley_cache_commands_total", "Commands a cache ran."),
    counter("get_hits", "socketley_cache_get_hits_total", "Reads that found their key."),
    counter("get_misses", "socketley_cache_get_misses_total", "Reads that found no key."),
    counter("keys_expired", "socketley_cache_keys_expired_total", "Keys a cache removed when their time was up."),
    gauge("memory_used", "socketley_cache_memory_used_bytes", "Memory a cache's data takes, as its limit counts it."),
    gauge("max_memory", "socketley_cache_max_memory_bytes", "The memory a cache was limited to, 0 for none."),
    gauge("channels", "socketley_cache_channels", "Pub/sub channels with a subscriber."),
    gauge("followers", "socketley_cache_followers", "Replicas following this cache now."),
    gauge("master_link", "socketley_cache_master_link", "1 while a replica has a connection to its leader."),
    gauge("master_sync_in_progress", "socketley_cache_master_sync_in_progress",
          "1 while a replica's connection to its leader has not finished its first sync."),
    histogram("batch_latency", "socketley_cache_batch_duration_seconds",
              "A read's commands to their replies handed to the socket, per flush, in loop turns."),
    unnamed("mode", merge::first),
    unnamed("eviction", merge::first),
    unnamed("repl_role", merge::first),
};

// ── db ──────────────────────────────────────────────────────────────────────

// A db's shards read one store, so what it holds is any shard's and what they did is the sum.
constexpr field db_fields[] = {
    gauge("documents", "socketley_db_documents", "Documents a db holds.", merge::first),
    gauge("collections", "socketley_db_collections", "Collections a db holds.", merge::first),
    gauge("bytes", "socketley_db_bytes", "Document bytes a db holds.", merge::first),
    gauge("max_bytes", "socketley_db_max_bytes", "The bytes a db was limited to, 0 for none.", merge::first),
    gauge("disk_bytes", "socketley_db_disk_bytes", "Bytes a db's files take on disk.", merge::first),
    gauge("segments", "socketley_db_segments", "Journal segments a db keeps.", merge::first),
    counter("merges", "socketley_db_merges_total", "Merges of journal segments.", merge::first),
    gauge("keys", "socketley_db_keys", "Service keys a db accepts.", merge::first),
    gauge("seq", "socketley_db_sequence", "The sequence number of a db's last write.", merge::max),
    gauge("durable", "socketley_db_durable_sequence", "The last write a db knows is on disk.", merge::max),
    counter("cache_hits", "socketley_db_cache_hits_total", "Document reads its cache answered."),
    counter("cache_misses", "socketley_db_cache_misses_total", "Document reads that went to disk."),
    counter("reads", "socketley_db_reads_total", "Reads a db answered."),
    counter("writes", "socketley_db_writes_total", "Writes a db took."),
    counter("queries", "socketley_db_queries_total", "Queries a db answered."),
    counter("syncs", "socketley_db_syncs_total", "Syncs a db made for durability."),
    counter("refused", "socketley_db_refused_total", "Requests a db refused."),
    counter("conflicts", "socketley_db_conflicts_total", "Writes refused for a revision that was not the latest."),
    counter("expired", "socketley_db_expired_total", "Documents a db removed when their time was up."),
    gauge("feeds", "socketley_db_feeds", "Change feeds open now."),
    counter("events_sent", "socketley_db_events_sent_total", "Changes a db sent on its feeds."),
    counter("backups", "socketley_db_backups_total", "Backups a db made."),
    counter("backup_failures", "socketley_db_backup_failures_total", "Backups that failed."),
    counter("script_calls", "socketley_db_script_calls_total", "Calls of a db's script."),
    gauge("replica_connected", "socketley_db_replica_connected", "1 while a replica db has a connection to its primary.",
          merge::max),
    counter("replicated", "socketley_db_replicated_total", "Writes a replica took from its primary."),
    counter("resets", "socketley_db_replica_resets_total", "Times a replica started again from a full copy."),
    histogram("request_latency", "socketley_db_request_duration_seconds",
              "Requests from their arrival to their answer, a wait for the disk or another shard included, in loop "
              "turns."),
};

// ── dns ─────────────────────────────────────────────────────────────────────

constexpr family dns_queries{"socketley_dns_queries_total", kind::counter, "Queries a dns runtime took, by transport."};
constexpr family dns_responses{"socketley_dns_responses_total", kind::counter,
                               "Answers a dns runtime gave, by response code."};

constexpr field dns_fields[] = {
    gauge("zones", "socketley_dns_zones", "Zones a dns runtime serves.", merge::first),
    gauge("records", "socketley_dns_records", "Records in the zones a dns runtime serves.", merge::first),
    member("udp_queries", dns_queries, "transport", "udp"),
    member("tcp_queries", dns_queries, "transport", "tcp"),
    member("noerror", dns_responses, "rcode", "NOERROR"),
    member("nxdomain", dns_responses, "rcode", "NXDOMAIN"),
    member("refused", dns_responses, "rcode", "REFUSED"),
    member("formerr", dns_responses, "rcode", "FORMERR"),
    member("notimp", dns_responses, "rcode", "NOTIMP"),
    member("other_rcode", dns_responses, "rcode", "other"),
    counter("truncated", "socketley_dns_truncated_total", "UDP answers cut short for TCP."),
    counter("referrals", "socketley_dns_referrals_total", "Answers that referred to another server."),
    counter("dropped", "socketley_dns_dropped_total", "Queries dropped unanswered as malformed."),
    counter("rrl_dropped", "socketley_dns_rrl_dropped_total", "Answers response rate limiting dropped."),
    counter("rrl_slipped", "socketley_dns_rrl_slipped_total", "Answers response rate limiting cut short instead."),
    counter("send_failed", "socketley_dns_send_failed_total", "Answers the kernel would not send."),
    counter("tcp_conns", "socketley_dns_tcp_connections_total", "TCP connections a dns runtime took."),
    counter("tcp_refused", "socketley_dns_tcp_refused_total", "TCP connections refused past the limit."),
    counter("tcp_evicted", "socketley_dns_tcp_evicted_total", "Idle TCP connections closed to make room."),
    counter("transfers", "socketley_dns_transfers_total", "Zone transfers served."),
    counter("transfers_refused", "socketley_dns_transfers_refused_total", "Zone transfers refused."),
    counter("notify_sent", "socketley_dns_notify_sent_total", "NOTIFY messages sent to secondaries."),
    counter("notify_acked", "socketley_dns_notify_acked_total", "NOTIFY messages a secondary answered."),
    counter("notify_given_up", "socketley_dns_notify_given_up_total", "NOTIFY messages given up on."),
    counter("zone_reloads", "socketley_dns_zone_reloads_total", "Zone files read again after a change."),
    counter("zone_reload_failures", "socketley_dns_zone_reload_failures_total",
            "Zone files that changed and could not be read."),
};

// ── idp ─────────────────────────────────────────────────────────────────────

constexpr field idp_fields[] = {
    gauge("accounts", "socketley_idp_accounts", "Accounts an idp holds.", merge::first),
    gauge("clients", "socketley_idp_clients", "OAuth clients an idp knows.", merge::first),
    counter("sign_ins", "socketley_idp_sign_ins_total", "Sign-ins an idp let through."),
    counter("sign_ins_refused", "socketley_idp_sign_ins_refused_total", "Sign-ins refused for a wrong user or secret."),
    counter("sign_ins_barred", "socketley_idp_sign_ins_barred_total",
            "Sign-ins refused unchecked, for too many failures from the address or for the user."),
    counter("codes", "socketley_idp_codes_total", "Authorization codes an idp issued."),
    counter("tokens", "socketley_idp_tokens_total", "Tokens an idp issued."),
    counter("refreshes", "socketley_idp_refreshes_total", "Tokens an idp refreshed."),
    counter("userinfo", "socketley_idp_userinfo_total", "Userinfo requests an idp answered."),
    histogram("sign_in_latency", "socketley_idp_sign_in_duration_seconds",
              "Password sign-ins from their form to their answer, the hash included, in loop turns."),
};

// ── mqtt ────────────────────────────────────────────────────────────────────

constexpr family mqtt_received{"socketley_mqtt_received_total", kind::counter, "Messages a broker took, by QoS."};
constexpr family mqtt_sent{"socketley_mqtt_sent_total", kind::counter, "Messages a broker delivered, by QoS."};
constexpr family mqtt_dropped{"socketley_mqtt_dropped_total", kind::counter,
                              "Messages a broker dropped undelivered, by reason."};
constexpr family mqtt_denied{"socketley_mqtt_denied_total", kind::counter,
                             "Publishes and subscriptions its ACL refused, by operation."};

constexpr field mqtt_fields[] = {
    gauge("sessions", "socketley_mqtt_sessions", "Sessions a broker holds, connected or kept."),
    gauge("sessions_connected", "socketley_mqtt_sessions_connected", "Sessions with a client connected now."),
    gauge("subscriptions", "socketley_mqtt_subscriptions", "Subscriptions a broker holds."),
    gauge("retained", "socketley_mqtt_retained", "Retained messages a broker holds."),
    gauge("retained_bytes", "socketley_mqtt_retained_bytes", "Bytes of the retained messages."),
    gauge("queued", "socketley_mqtt_queued", "Messages queued for sessions."),
    gauge("inflight", "socketley_mqtt_inflight", "QoS 1 and 2 messages sent and not yet acknowledged."),
    member("received_qos0", mqtt_received, "qos", "0"),
    member("received_qos1", mqtt_received, "qos", "1"),
    member("received_qos2", mqtt_received, "qos", "2"),
    member("sent_qos0", mqtt_sent, "qos", "0"),
    member("sent_qos1", mqtt_sent, "qos", "1"),
    member("sent_qos2", mqtt_sent, "qos", "2"),
    member("dropped_slow", mqtt_dropped, "reason", "slow"),
    member("dropped_queue", mqtt_dropped, "reason", "queue"),
    member("dropped_expired", mqtt_dropped, "reason", "expired"),
    member("dropped_too_large", mqtt_dropped, "reason", "too_large"),
    member("dropped_denied", mqtt_dropped, "reason", "denied"),
    member("denied_publish", mqtt_denied, "op", "publish"),
    member("denied_subscribe", mqtt_denied, "op", "subscribe"),
    counter("connects", "socketley_mqtt_connects_total", "CONNECTs a broker accepted."),
    counter("connects_refused", "socketley_mqtt_connects_refused_total", "CONNECTs a broker refused."),
    counter("auth_refused", "socketley_mqtt_auth_refused_total", "CONNECTs refused for their credentials."),
    counter("takeovers", "socketley_mqtt_takeovers_total", "Sessions a new connection of the same client took over."),
    counter("takeovers_refused", "socketley_mqtt_takeovers_refused_total", "Takeovers a broker refused."),
    counter("wills_sent", "socketley_mqtt_wills_sent_total", "Will messages a broker published."),
    counter("sessions_expired", "socketley_mqtt_sessions_expired_total", "Sessions ended when their expiry was up."),
    counter("sessions_evicted", "socketley_mqtt_sessions_evicted_total", "Sessions ended to stay under the limit."),
    counter("protocol_errors", "socketley_mqtt_protocol_errors_total", "Connections closed for a protocol error."),
    counter("retained_refused", "socketley_mqtt_retained_refused_total", "Retained messages refused past the limit."),
    counter("tls_failures", "socketley_mqtt_tls_failures_total", "TLS handshakes that failed or never finished."),
    counter("websocket_refused", "socketley_mqtt_websocket_refused_total", "WebSocket upgrades a broker refused."),
    counter("snapshots", "socketley_mqtt_snapshots_total", "Snapshots of the broker's state written."),
    gauge("snapshot_failing", "socketley_mqtt_snapshot_failing", "1 while the last snapshot could not be written.",
          merge::max),
    gauge("snapshot_unsaved", "socketley_mqtt_snapshot_unsaved", "1 while a change waits for its snapshot.", merge::max),
};

// ── sync ────────────────────────────────────────────────────────────────────

constexpr field sync_fields[] = {
    gauge("indexed", "socketley_sync_indexed", "Files the index holds, over every target."),
    counter("carried", "socketley_sync_carried_total", "Files a sync carried to the storage."),
    counter("removed", "socketley_sync_removed_total", "Files a sync removed from the storage."),
    counter("bytes_carried", "socketley_sync_bytes_carried_total", "Bytes a sync carried."),
    gauge("waiting", "socketley_sync_waiting", "Changes waiting to be carried."),
    counter("failures", "socketley_sync_failures_total", "Files or repository runs a sync could not carry."),
    gauge("failing", "socketley_sync_failing", "Failures since the last thing a sync carried, which an alert is raised on."),
    gauge("watched", "socketley_sync_watched", "Directories inotify watches, 0 when the walk is all that sees a change."),
    counter("brought", "socketley_sync_brought_total", "Files an inout sync brought here from the storage."),
    counter("removed_here", "socketley_sync_removed_here_total", "Files an inout sync removed here, gone from the storage."),
    counter("conflicts", "socketley_sync_conflicts_total", "Files both sides changed, the storage's copy kept beside."),
    gauge("last_run_secs", "socketley_sync_last_run_seconds", "Seconds since the last walk of the directory ended."),
    gauge("repositories", "socketley_sync_repositories", "Git repositories a sync pulls."),
    counter("runs", "socketley_sync_runs_total", "Pulls of a repository a sync ran."),
};

// ── metrics ─────────────────────────────────────────────────────────────────

constexpr family metrics_refused{"socketley_metrics_samples_refused_total", kind::counter,
                                 "Samples a metrics runtime refused, by why."};

constexpr field metrics_fields[] = {
    gauge("series", "socketley_metrics_series", "Series a metrics runtime holds."),
    gauge("head_series", "socketley_metrics_head_series", "Series with samples not yet cut into a block."),
    counter("samples", "socketley_metrics_samples_appended_total", "Samples a metrics runtime stored."),
    counter("refused_series", "socketley_metrics_series_refused_total", "New series refused past --max-series."),
    member("refused_out_of_order", metrics_refused, "reason", "out_of_order"),
    member("refused_too_old", metrics_refused, "reason", "too_old"),
    gauge("bytes_on_disk", "socketley_metrics_disk_bytes", "Bytes a metrics runtime's store holds on the disk."),
    gauge("bytes_in_ram", "socketley_metrics_memory_bytes", "Bytes a metrics runtime's store holds in memory."),
    gauge("targets", "socketley_metrics_targets", "Targets a metrics runtime scrapes."),
    gauge("targets_up", "socketley_metrics_targets_up", "Targets whose last scrape answered."),
    counter("scrapes", "socketley_metrics_scrapes_total", "Scrapes a metrics runtime made."),
    counter("scrape_failures", "socketley_metrics_scrape_failures_total", "Scrapes that got no answer to store."),
    counter("queries", "socketley_metrics_queries_total", "PromQL queries a metrics runtime answered."),
    gauge("local_series", "socketley_metrics_local_series", "This daemon's own series the local feed holds."),
};

constexpr field mcp_fields[] = {
    counter("requests", "socketley_mcp_requests_total", "MCP messages an mcp runtime took."),
    counter("tool_calls", "socketley_mcp_tool_calls_total", "Tools an mcp runtime ran."),
    counter("tool_errors", "socketley_mcp_tool_errors_total", "Tool runs that said they failed."),
    counter("errors", "socketley_mcp_errors_total", "Messages answered with a JSON-RPC error."),
    counter("legacy_requests", "socketley_mcp_legacy_requests_total", "Messages of a revision before 2026-07-28."),
    counter("refused", "socketley_mcp_refused_total", "Requests refused before a message: a key, an origin or a method."),
    gauge("tools", "socketley_mcp_tools", "Tools an mcp runtime offers.", merge::first),
    gauge("resources", "socketley_mcp_resources", "Resources an mcp runtime offers.", merge::first),
    gauge("prompts", "socketley_mcp_prompts", "Prompts an mcp runtime offers.", merge::first),
    gauge("keys", "socketley_mcp_keys", "Keys an mcp runtime takes.", merge::first),
};

constexpr type_entry entries[] = {
    {runtime_storage, storage_fields,
     {"socketley_storage_stat", kind::untyped, "A storage runtime's other stats figures, by name."}, true},
    {runtime_mail, mail_fields, {"socketley_mail_stat", kind::untyped, "A mail runtime's other stats figures, by name."}},
    {runtime_tunnel, tunnel_fields,
     {"socketley_tunnel_stat", kind::untyped, "A tunnel's other stats figures, by name."}},
    {runtime_server, server_fields,
     {"socketley_server_stat", kind::untyped, "A server's other stats figures, by name."}},
    {runtime_client, client_fields,
     {"socketley_client_stat", kind::untyped, "A client's other stats figures, by name."}},
    {runtime_proxy, proxy_fields, {"socketley_proxy_stat", kind::untyped, "A proxy's other stats figures, by name."}},
    {runtime_cache, cache_fields, {"socketley_cache_stat", kind::untyped, "A cache's other stats figures, by name."}},
    {runtime_db, db_fields, {"socketley_db_stat", kind::untyped, "A db's other stats figures, by name."}},
    {runtime_dns, dns_fields, {"socketley_dns_stat", kind::untyped, "A dns runtime's other stats figures, by name."}},
    {runtime_idp, idp_fields, {"socketley_idp_stat", kind::untyped, "An idp's other stats figures, by name."}},
    {runtime_mqtt, mqtt_fields, {"socketley_mqtt_stat", kind::untyped, "A broker's other stats figures, by name."}},
    {runtime_sync, sync_fields, {"socketley_sync_stat", kind::untyped, "A sync's other stats figures, by name."}},
    {runtime_metrics, metrics_fields,
     {"socketley_metrics_stat", kind::untyped, "A metrics runtime's other stats figures, by name."}},
    {runtime_mcp, mcp_fields, {"socketley_mcp_stat", kind::untyped, "An mcp runtime's other stats figures, by name."}},
};

// Each type's keys sorted, for the one lookup a figure costs; built once, on first use, by whichever thread comes.
struct key_index
{
    std::vector<std::pair<std::string_view, uint16_t>> keys;
    std::vector<uint16_t> prefixes;
    bool histograms{false};
};

const key_index& index_of(const type_entry& e)
{
    static const auto all = [] {
        std::array<key_index, std::size(entries)> out;
        for (size_t t = 0; t < std::size(entries); ++t)
        {
            for (size_t i = 0; i < entries[t].fields.size(); ++i)
            {
                if (entries[t].fields[i].prefix)
                    out[t].prefixes.push_back(static_cast<uint16_t>(i));
                else
                    out[t].keys.emplace_back(entries[t].fields[i].key, static_cast<uint16_t>(i));
                out[t].histograms |= entries[t].fields[i].fam.type == kind::histogram;
            }
            std::sort(out[t].keys.begin(), out[t].keys.end());
        }
        return out;
    }();
    return all[static_cast<size_t>(&e - entries)];
}

int find_field(const type_entry& e, std::string_view key)
{
    const auto& keys = index_of(e).keys;
    const auto it = std::lower_bound(keys.begin(), keys.end(), key,
                                     [](const auto& p, std::string_view k) { return p.first < k; });
    return it != keys.end() && it->first == key ? it->second : -1;
}

void fold(uint64_t& held, uint64_t v, merge how)
{
    if (how == merge::sum)
        held += v;
    else if (how == merge::max)
        held = std::max(held, v);
}

}   // namespace

const type_entry* entry_for(runtime_type t)
{
    for (const type_entry& e : entries)
        if (e.type == t)
            return &e;
    return nullptr;
}

std::span<const type_entry> types()
{
    return entries;
}

void figures::parse(runtime_type t, std::string detail, uint64_t bytes_in, uint64_t bytes_out)
{
    m_entry = entry_for(t);
    m_text = std::move(detail);
    m_other.clear();
    m_hist.clear();
    if (!m_entry)
    {
        m_slot.clear();
        m_has.clear();
        return;
    }
    m_slot.assign(m_entry->fields.size(), 0);
    m_has.assign(m_entry->fields.size(), 0);
    // Fields of their type's own, so they never reach m_other, whose keys are places in the text.
    if (m_entry->shared_bytes)
    {
        int index = -1;
        put_field("bytes_in", bytes_in, index);
        put_field("bytes_out", bytes_out, index);
    }

    // A key comes again only in a sharded runtime's text, which labels each section, so one of one section is never
    // searched for.
    const bool sharded = m_text.find("[shard ") != std::string::npos;
    const bool histograms = index_of(*m_entry).histograms;
    socketley::stats_text::for_each_field(m_text, [&](std::string_view key, std::string_view num) {
        uint64_t v = 0;
        const auto [end, ec] = std::from_chars(num.data(), num.data() + num.size(), v);
        if (ec != std::errc{} || end != num.data() + num.size())
        {
            if (histograms)
                put_histogram(key, num);
            return;
        }
        put(key, v, sharded);
    });
}

bool figures::put_histogram(std::string_view key, std::string_view value)
{
    const int index = find_field(*m_entry, key);
    if (index < 0 || m_entry->fields[static_cast<size_t>(index)].fam.type != kind::histogram)
        return false;
    latency_histogram h;
    if (!latency_histogram::parse(value, h))
        return false;
    for (histogram_slot& s : m_hist)
        if (s.field == index)
        {
            s.h.merge(h);
            return true;
        }
    m_hist.push_back({static_cast<uint16_t>(index), h});
    return true;
}

bool figures::put_field(std::string_view key, uint64_t v, int& index)
{
    index = find_field(*m_entry, key);
    if (index < 0)
        return false;
    const auto i = static_cast<size_t>(index);
    if (m_has[i])
        fold(m_slot[i], v, m_entry->fields[i].how);
    else
    {
        m_slot[i] = v;
        m_has[i] = 1;
    }
    return true;
}

void figures::put(std::string_view key, uint64_t v, bool sharded)
{
    int index = -1;
    merge how = merge::sum;
    int16_t prefix_field = -1;
    if (put_field(key, v, index))
    {
        const field& f = m_entry->fields[static_cast<size_t>(index)];
        if (!f.fam.name.empty() && !f.also_stat)
            return;
        how = f.how;
    }
    else
        for (const uint16_t p : index_of(*m_entry).prefixes)
            if (key.starts_with(m_entry->fields[p].key))
            {
                prefix_field = static_cast<int16_t>(p);
                break;
            }
    if (sharded)
        for (other& o : m_other)
            if (key_of(o) == key)
            {
                fold(o.value, v, o.how);
                return;
            }
    m_other.push_back({static_cast<uint32_t>(key.data() - m_text.data()), static_cast<uint32_t>(key.size()), v,
                       prefix_field, how});
}

bool figures::get(std::string_view key, uint64_t& out) const
{
    if (!m_entry)
        return false;
    if (const int i = find_field(*m_entry, key); i >= 0 && m_has[static_cast<size_t>(i)])
    {
        out = m_slot[static_cast<size_t>(i)];
        return true;
    }
    for (const other& o : m_other)
        if (key_of(o) == key)
        {
            out = o.value;
            return true;
        }
    return false;
}

// A runtime's histogram as the exposition format has it: cumulative buckets in ascending `le` up to +Inf, then the sum
// in seconds and the count, which equals the +Inf bucket.
void emit_histogram(const field& f, uint16_t index, const source& r, sink_ref out)
{
    for (const figures::histogram_slot& s : r.fig->m_hist)
    {
        if (s.field != index)
            continue;
        label ls[3];
        size_t n = 0;
        ls[n++] = {"name", r.name};
        if (!f.label_name.empty())
            ls[n++] = {f.label_name, f.label_value};
        uint64_t seen = 0;
        for (int b = 0; b < latency_histogram::buckets; ++b)
        {
            seen += s.h.bucket(b);
            ls[n] = {"le", latency_histogram::le[static_cast<size_t>(b)]};
            out(series::of(f.fam, std::span<const label>(ls, n + 1), seen, "_bucket"));
        }
        const std::span<const label> plain(ls, n);
        out(series::of(f.fam, plain, static_cast<double>(s.h.sum_ns()) / 1e9, "_sum"));
        out(series::of(f.fam, plain, seen, "_count"));
    }
}

void emit(const type_entry& e, std::span<const source> runtimes, sink_ref out)
{
    label ls[2];
    const auto fields = e.fields;
    for (size_t i = 0; i < fields.size();)
    {
        size_t j = i + 1;
        while (j < fields.size() && fields[j].fam.name == fields[i].fam.name)
            ++j;
        if (fields[i].fam.name.empty())
        {
            i = j;
            continue;
        }
        for (const source& r : runtimes)
        {
            if (!r.fig || r.fig->m_entry != &e)
                continue;
            ls[0] = {"name", r.name};
            for (size_t k = i; k < j; ++k)
            {
                const field& f = fields[k];
                if (f.prefix)
                {
                    for (const figures::other& o : r.fig->m_other)
                        if (o.prefix_field == static_cast<int16_t>(k))
                        {
                            ls[1] = {f.label_name, r.fig->key_of(o).substr(f.key.size())};
                            out(series::of(f.fam, std::span<const label>(ls, 2), o.value));
                        }
                    continue;
                }
                if (f.fam.type == kind::histogram)
                {
                    emit_histogram(f, static_cast<uint16_t>(k), r, out);
                    continue;
                }
                if (!r.fig->m_has[k])
                    continue;
                size_t n = 1;
                if (!f.label_name.empty())
                    ls[n++] = {f.label_name, f.label_value};
                out(series::of(f.fam, std::span<const label>(ls, n), r.fig->m_slot[k]));
            }
        }
        i = j;
    }
    for (const source& r : runtimes)
    {
        if (!r.fig || r.fig->m_entry != &e)
            continue;
        ls[0] = {"name", r.name};
        for (const figures::other& o : r.fig->m_other)
            if (o.prefix_field < 0)
            {
                ls[1] = {"stat", r.fig->key_of(o)};
                out(series::of(e.stat, std::span<const label>(ls, 2), o.value));
            }
    }
}

}   // namespace socketley::metric_catalog
