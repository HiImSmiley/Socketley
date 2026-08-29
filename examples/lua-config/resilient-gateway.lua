-- =============================================================================
-- resilient-gateway.lua - Every flag a proxy has, from a configuration file
-- =============================================================================
--
-- The health-check, circuit-breaker, retry and TLS families were unreachable
-- from a configuration for a long time: cli_config mapped twenty-five of the
-- daemon's sixty-one flags and dropped the rest in silence.  Setting them meant
-- a `create` command line, which meant they lived somewhere other than the file
-- describing the deployment.  This file is what closing that gap buys.
--
-- USAGE (from the repository root):
--   socketley --lua examples/lua-config/resilient-gateway.lua
--
-- Nothing here starts: `start = true` is deliberately absent so the file can be
-- read, applied and inspected with `socketley show gateway` without binding a
-- port.  Add it once the certificate paths below point at real files.
-- =============================================================================

local CERTS = "/etc/socketley/certs"

runtimes = {
    -- =========================================================================
    -- The three backends this gateway protects.
    -- =========================================================================
    { type = "server", name = "api-a", port = 9101, mode = "inout", group = "api" },
    { type = "server", name = "api-b", port = 9102, mode = "inout", group = "api" },
    { type = "server", name = "api-c", port = 9103, mode = "inout", group = "api" },

    -- =========================================================================
    -- The gateway.
    -- =========================================================================
    {
        type = "proxy",
        name = "gateway",
        port = 8443,
        protocol = "http",
        strategy = "round-robin",

        -- A group name resolves to whatever is in it at connection time, so a
        -- fourth backend joining `api` needs no change here.
        backends = { "@api" },

        -- ── Health checks ────────────────────────────────────────────────────
        -- An unhealthy backend leaves the pool until it answers again, which
        -- is the difference between one backend dying and the gateway dying.
        health_check = "http",
        health_path = "/healthz",
        health_interval = 5,
        health_threshold = 3,

        -- ── Circuit breaker ──────────────────────────────────────────────────
        -- Five consecutive failures open the circuit for thirty seconds, so a
        -- backend that is down stops costing every request a timeout.
        circuit_threshold = 5,
        circuit_timeout = 30,

        -- ── Retries and timeouts ─────────────────────────────────────────────
        -- retry_all retries non-idempotent requests too, which is a decision
        -- about your backends and not a default worth inheriting.
        backend_timeout = 10,
        retry = 2,
        retry_all = false,

        -- ── TLS on the way in ────────────────────────────────────────────────
        tls = true,
        cert = CERTS .. "/gateway.crt",
        key = CERTS .. "/gateway.key",

        -- ── Mutual TLS ───────────────────────────────────────────────────────
        -- client_ca verifies the certificates callers present; client_cert and
        -- client_key are the pair this gateway presents to its backends.
        client_ca = CERTS .. "/clients-ca.crt",
        client_cert = CERTS .. "/gateway-client.crt",
        client_key = CERTS .. "/gateway-client.key",

        -- ── Limits ───────────────────────────────────────────────────────────
        max_connections = 10000,
        rate_limit = 100,
        global_rate_limit = 5000,
        idle_timeout = 60,

        log = "/tmp/gateway.log"
    },

    -- =========================================================================
    -- `sidecar` is shorthand for health-check tcp, a circuit, two retries and
    -- drain, which is the set a mesh sidecar wants and nobody remembers.
    -- =========================================================================
    {
        type = "proxy",
        name = "sidecar",
        port = 15001,
        backends = { "127.0.0.1:9101" },
        sidecar = true
    }
}

--[[
=== WHAT TO LOOK AT ===

socketley show gateway     -- every field above, back out of the daemon
socketley show sidecar     -- what `sidecar = true` actually set

=== WHAT IS REFUSED, AND WHY IT IS WORTH KNOWING ===

A key this file misspells is refused by name rather than dropped:

    htp_cache = true   ->  could not create gateway:
                             unknown key: htp_cache

A value of the wrong shape is refused the same way (`port = "8443"` is a
string, not a number), and so is any value containing whitespace -- the
daemon's command line has no quoting, so a password with a space in it would
arrive as two arguments and set something else.

A key the daemon refuses on that type comes back in the daemon's own words:

    client_ca on a cleartext proxy  ->  --client-ca: verifies the certificates
                                        clients present, which needs --tls
                                        --cert --key on this proxy's own
                                        listener

The remaining entries are still applied, and the exit code is 1.
]]
