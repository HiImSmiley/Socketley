#!/bin/bash
# =============================================================================
# broker.sh - An MQTT broker for devices, apps and browsers
# =============================================================================
#
# Passwords in a file of its own, rules for who reads and writes what, a
# WebSocket port for browsers, and sessions kept across restarts. Then the
# sensors' readings handed to a cache's stream, beside the subscribers.
# =============================================================================

set -e
DIR=$(mktemp -d)

printf 'sensorpass\n' | socketley mqtt-passwd "$DIR/users" sensor-17
printf 'apppass\n'    | socketley mqtt-passwd "$DIR/users" app

cat > "$DIR/acl" <<'EOF'
user sensor-17
topic write sensor/sensor-17/#
user app
topic read sensor/#
topic readwrite app/#
EOF

cat > "$DIR/routes" <<'EOF'
sensor/+/temp   cache://telemetry/stream/temps-%1
EOF

socketley create cache telemetry -p 6390 -s
socketley create mqtt broker --users "$DIR/users" --acl "$DIR/acl" --routes "$DIR/routes" \
    --ws 8083 --persistent on -s
sleep 0.5

# What a device sends, and what an app hears.
socketley mqtt-sub broker 'sensor/#' --count 1 &
sleep 0.3
socketley mqtt-pub broker --qos 1 sensor/sensor-17/temp 21.5
wait

socketley mqtt-sessions broker
socketley stats broker | grep -E '^(sessions|retained|rule_0_)'

socketley stop broker telemetry
socketley remove broker telemetry
rm -rf "$DIR"
