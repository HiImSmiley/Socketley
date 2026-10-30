# The 2000-port windows a test may claim: the fixed ones, and every one between 31000 and the machine's ephemeral
# range, which a gate machine widens by moving that range up (net.ipv4.ip_local_port_range).
sl_port_windows() {
    local lo w
    lo=$(awk '{print $1}' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo 32768)
    echo 19000 21000 23000 25000 27000 29000 5000 7000 9000 11000 13000 15000 17000 3000
    for ((w = 31000; w + 2000 <= lo; w += 2000)); do echo "$w"; done
}
