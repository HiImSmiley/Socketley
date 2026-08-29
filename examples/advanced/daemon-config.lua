-- Daemon configuration file
-- Place at /etc/socketley/config.lua (system) or ~/.config/socketley/config.lua (dev)
-- Or set SOCKETLEY_CONFIG=/path/to/config.lua

daemon = {
    -- This daemon's name in a cluster, and the directory it publishes into.
    -- Both are needed together: a cluster directory identifies its members by
    -- name.  Set at startup here, or on a running daemon with `socketley --lua`.
    name = "node1",
    cluster = "/shared/cluster",

    -- Log verbosity: debug, info, warn, error
    log_level = "info",

    -- Prometheus metrics HTTP endpoint (0 or omit to disable)
    -- GET http://localhost:9100/metrics returns Prometheus exposition format
    metrics_port = 9100,

    -- Where this daemon's I/O runs, and whether the ring polls kernel-side.
    -- Both are settled before the ring exists, so they are read only from
    -- here -- and `socketley daemon --cpus`/`--sqpoll` outranks this file.
    cpus = "max",
    sqpoll = true
}

-- `config` is this table's older name and still works.  Naming both in one
-- file is refused rather than merged.
