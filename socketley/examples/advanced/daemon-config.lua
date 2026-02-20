-- Daemon configuration file
-- Place at /etc/socketley/config.lua (system) or ~/.config/socketley/config.lua (dev)
-- Or set SOCKETLEY_CONFIG=/path/to/config.lua

config = {
    -- Log verbosity: debug, info, warn, error
    log_level = "info",

    -- Prometheus metrics HTTP endpoint (0 or omit to disable)
    -- GET http://localhost:9100/metrics returns Prometheus exposition format
    metrics_port = 9100
}
