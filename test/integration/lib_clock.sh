#!/usr/bin/env bash
# Durations read off the boot clock, which only goes forward: a guest's wall clock is stepped by its host's time
# sync, and a duration taken from `date` came out up to 0.9 s short under load. Ten milliseconds apart, read
# without starting a process.
mono_ms() { local up; read -r up _ < /proc/uptime; echo $(( ${up%.*} * 1000 + 10#${up#*.} * 10 )); }
mono_ns() { echo $(( $(mono_ms) * 1000000 )); }
# Seconds with their fraction, where a test does its arithmetic on decimals.
mono_s() { local up; read -r up _ < /proc/uptime; echo "$up"; }
