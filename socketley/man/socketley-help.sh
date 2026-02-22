#!/bin/bash
# =============================================================================
# socketley-help.sh - Interactive Help System
# =============================================================================
#
# An interactive menu-driven help system for socketley.
# Navigate with numbers, get examples, and explore all features.
#
# USAGE:
#   ./socketley-help.sh
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Clear screen and show header
show_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                      ║"
    echo "║   ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗██╗     ███████╗██╗   ██╗ ║"
    echo "║   ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██║     ██╔════╝╚██╗ ██╔╝ ║"
    echo "║   ███████╗██║   ██║██║     █████╔╝ █████╗     ██║   ██║     █████╗   ╚████╔╝  ║"
    echo "║   ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   ██║     ██╔══╝    ╚██╔╝   ║"
    echo "║   ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   ███████╗███████╗   ██║    ║"
    echo "║   ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝    ║"
    echo "║                                                                      ║"
    echo "║                    Interactive Help System                           ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show main menu
main_menu() {
    show_header
    echo -e "${BOLD}What would you like to learn about?${NC}\n"
    echo -e "  ${GREEN}1)${NC} Quick Start Guide"
    echo -e "  ${GREEN}2)${NC} CLI Commands"
    echo -e "  ${GREEN}3)${NC} Runtime Types"
    echo -e "  ${GREEN}4)${NC} Flags & Options"
    echo -e "  ${GREEN}5)${NC} Lua Configuration"
    echo -e "  ${GREEN}6)${NC} Examples"
    echo -e "  ${GREEN}7)${NC} Architecture Overview"
    echo -e "  ${GREEN}8)${NC} Troubleshooting"
    echo -e "  ${GREEN}9)${NC} Installation & Packaging"
    echo ""
    echo -e "  ${RED}q)${NC} Quit"
    echo ""
    read -p "Enter choice: " choice
    case $choice in
        1) quick_start ;;
        2) cli_commands ;;
        3) runtime_types ;;
        4) flags_options ;;
        5) lua_config ;;
        6) examples_menu ;;
        7) architecture ;;
        8) troubleshooting ;;
        9) installation_help ;;
        q|Q) exit 0 ;;
        *) main_menu ;;
    esac
}

# Quick Start Guide
quick_start() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Quick Start Guide ═══${NC}\n"

    echo -e "${BOLD}Step 1: Start the Daemon${NC}"
    echo -e "  ${CYAN}socketley daemon &${NC}"
    echo "  The daemon must be running for all other commands."
    echo ""

    echo -e "${BOLD}Step 2: Create a Server${NC}"
    echo -e "  ${CYAN}socketley create server myserver -p 9000 -s${NC}"
    echo "  Creates and starts a server on port 9000."
    echo ""

    echo -e "${BOLD}Step 3: Create a Client${NC}"
    echo -e "  ${CYAN}socketley create client myclient -t 127.0.0.1:9000 -s${NC}"
    echo "  Connects to the server."
    echo ""

    echo -e "${BOLD}Step 4: Check Status${NC}"
    echo -e "  ${CYAN}socketley ls${NC}    # All runtimes"
    echo -e "  ${CYAN}socketley ps${NC}    # Running only"
    echo ""

    echo -e "${BOLD}Step 5: Stop & Cleanup${NC}"
    echo -e "  ${CYAN}socketley stop myserver myclient${NC}"
    echo -e "  ${CYAN}socketley remove myserver myclient${NC}"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# CLI Commands
cli_commands() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ CLI Commands ═══${NC}\n"

    echo -e "${BOLD}daemon${NC}"
    echo "  Start the socketley daemon (required first)"
    echo -e "  ${CYAN}socketley daemon${NC}"
    echo ""

    echo -e "${BOLD}create <type> <name> [flags]${NC}"
    echo "  Create a new runtime"
    echo -e "  ${CYAN}socketley create server api -p 9000 -s${NC}"
    echo ""

    echo -e "${BOLD}attach <type> <name> <port> [--owner <name>]${NC}"
    echo "  Register an external process as a runtime visible in ls/ps."
    echo "  The daemon does NOT bind the port or manage I/O — the external"
    echo "  process owns its connections. Useful for SDK-embedded runtimes."
    echo -e "  ${CYAN}socketley attach server my-app 8080${NC}"
    echo -e "  ${CYAN}socketley attach server my-app 8080 --owner api${NC}"
    echo ""

    echo -e "${BOLD}start <name|pattern>... [-i]${NC}"
    echo "  Start runtimes. Accepts multiple names, glob patterns (*,?,[])"
    echo "  -i: Interactive mode (stdin/stdout live session, single name only)"
    echo -e "  ${CYAN}socketley start api${NC}"
    echo -e "  ${CYAN}socketley start api -i${NC}    # interactive session"
    echo -e "  ${CYAN}socketley start *${NC}         # start all non-running"
    echo -e "  ${CYAN}socketley start my*${NC}       # start all starting with 'my'"
    echo ""

    echo -e "${BOLD}stop <name|pattern>...${NC}"
    echo "  Stop running runtimes. Accepts multiple names, glob patterns"
    echo -e "  ${CYAN}socketley stop api${NC}"
    echo -e "  ${CYAN}socketley stop api cli${NC}  # stop both"
    echo -e "  ${CYAN}socketley stop my*${NC}      # stop all starting with 'my'"
    echo -e "  ${CYAN}socketley stop *${NC}        # stop all running"
    echo ""

    echo -e "${BOLD}remove <name|pattern>...${NC}"
    echo "  Remove runtimes. Accepts multiple names, glob patterns"
    echo -e "  ${CYAN}socketley remove api${NC}"
    echo -e "  ${CYAN}socketley remove api cli${NC}  # remove both"
    echo -e "  ${CYAN}socketley remove *${NC}        # stop all + remove all"
    echo ""

    echo -e "${BOLD}send <name> [message]${NC}"
    echo "  Send message to server (broadcast) or client"
    echo -e "  ${CYAN}socketley send myserver \"Hello everyone\"${NC}"
    echo -e "  ${CYAN}echo \"Hello\" | socketley send myserver${NC}  # stdin"
    echo ""

    echo -e "${BOLD}ls${NC}"
    echo "  List all runtimes (Docker-style: ID, NAME, TYPE, PORT, CONN, STATUS, CREATED)"
    echo ""

    echo -e "${BOLD}ps${NC}"
    echo "  List running runtimes (same format as ls)"
    echo ""

    echo -e "${BOLD}stats <name|pattern>...${NC}"
    echo "  Show runtime statistics. Accepts multiple names, glob patterns"
    echo -e "  ${CYAN}socketley stats myserver${NC}"
    echo -e "  ${CYAN}socketley stats api* cache*${NC}  # stats for matching"
    echo -e "  ${CYAN}socketley stats *${NC}            # stats for all"
    echo ""

    echo -e "${BOLD}reload <name|pattern>...${NC}"
    echo "  Restart running runtimes (stop + start). Glob patterns supported"
    echo -e "  ${CYAN}socketley reload myserver${NC}"
    echo -e "  ${CYAN}socketley reload api*${NC}  # restart all api- runtimes"
    echo -e "  ${CYAN}socketley reload *${NC}     # restart all running"
    echo ""

    echo -e "${BOLD}reload-lua <name|pattern>...${NC}"
    echo "  Hot-reload Lua script without stopping the runtime"
    echo -e "  ${CYAN}socketley reload-lua myserver${NC}"
    echo -e "  ${CYAN}socketley reload-lua *${NC}"
    echo ""

    echo -e "${BOLD}show <name|pattern>...${NC}"
    echo "  Print runtime JSON configuration. Glob patterns supported"
    echo -e "  ${CYAN}socketley show myserver${NC}"
    echo -e "  ${CYAN}socketley show cache*${NC}   # all cache runtimes"
    echo -e "  ${CYAN}socketley show *${NC}        # all runtimes"
    echo ""

    echo -e "${BOLD}edit <name> [flags]${NC}"
    echo "  Edit runtime configuration"
    echo -e "  ${CYAN}socketley edit myserver${NC}           # Opens config in \$EDITOR"
    echo -e "  ${CYAN}socketley edit myserver -r${NC}        # Opens editor, auto-reloads Lua"
    echo -e "  ${CYAN}socketley edit myserver -p 9001${NC}   # Direct flag-based edit"
    echo ""

    echo -e "${BOLD}owner <name>${NC}"
    echo "  Show ownership info: parent, children, on_parent_stop policy"
    echo -e "  ${CYAN}socketley owner chess-rapid${NC}"
    echo ""

    echo -e "${BOLD}--lua <file.lua>${NC}"
    echo "  Load Lua configuration"
    echo -e "  ${CYAN}socketley --lua setup.lua${NC}"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Runtime Types
runtime_types() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Runtime Types ═══${NC}\n"

    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│${NC} ${BOLD}SERVER${NC}                                                        ${GREEN}│${NC}"
    echo -e "${GREEN}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}│${NC} Accepts connections, broadcasts messages to clients            ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC} Default port: 8000                                             ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC} Flags: --mode inout|in|out                                     ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC} Example: socketley create server api -p 9000 -s                ${GREEN}│${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} ${BOLD}CLIENT${NC}                                                        ${BLUE}│${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│${NC} Connects to servers, sends/receives messages                   ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} Default target: 127.0.0.1:8000                                 ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} Flags: -t host:port, --mode inout|in|out                       ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} Example: socketley create client cli -t 127.0.0.1:9000 -s      ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} ${BOLD}PROXY${NC}                                                         ${YELLOW}│${NC}"
    echo -e "${YELLOW}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${YELLOW}│${NC} HTTP/TCP reverse proxy with load balancing                    ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} Default port: 8080                                            ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} Flags: --backend, --strategy, --protocol                      ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} Example: socketley create proxy gw -p 8080 --backend api -s   ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}CACHE${NC}                                                         ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Key-value store with optional persistence                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Default port: 9000                                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Flags: --persistent file, --mode readonly|readwrite|admin      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Example: socketley create cache store --persistent data.bin -s ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Modes:                                                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   readonly  - GET, SIZE only (deny writes)                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   readwrite - GET, SET, DEL, SIZE (default)                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   admin     - All commands including FLUSH, LOAD               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Protocol (TCP, newline-terminated, all lowercase):             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Strings: set key val, get key, del key, exists key          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            incr/decr key, incrby/decrby key n                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            append key val, strlen key, getset key newval       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            mget k1 k2 ..., mset k1 v1 k2 v2 ...              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            type key, keys pattern                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            setnx key val, setex key sec val, psetex key ms val ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            scan cursor [match pat] [count n]                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Lists:   lpush/rpush key val, lpop/rpop key, llen key       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            lrange key start stop, lindex key idx               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Sets:    sadd key member, srem key member, scard key         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            sismember key member, smembers key                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Hashes:  hset key field val, hget key field, hdel key field ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            hgetall key, hlen key                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   TTL:     expire key seconds, ttl key, persist key            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            pexpire key ms, pttl key, expireat key ts             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}            pexpireat key ts                                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   RESP:    SET key val [NX|XX] [EX n] [PX ms]                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   PubSub: subscribe ch, unsubscribe ch, publish ch msg         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Memory: maxmemory, memory                                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Admin:  flush [path], load [path], size                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Type enforcement: key holds one type only                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Multi-line responses end with \"end\"                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Features: Pub/Sub, RESP2 (Redis-compatible), Replication,      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}           Maxmemory + LRU eviction                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Access: echo \"set foo bar\" | nc localhost 9000                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}         redis-cli -p 9000 SET foo bar  (RESP mode)             ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Flags & Options
flags_options() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Flags & Options ═══${NC}\n"

    echo -e "${BOLD}Common Flags (all runtime types):${NC}"
    echo "┌──────────────────┬─────────────────────────────────────────┐"
    echo "│ Flag             │ Description                             │"
    echo "├──────────────────┼─────────────────────────────────────────┤"
    echo "│ -p <port>        │ Set port                                │"
    echo "│ -s               │ Start immediately                       │"
    echo "│ --test           │ Dry run (validate only)                 │"
    echo "│ --log <file>     │ Log state transitions                   │"
    echo "│ -w <file>        │ Write messages to file                  │"
    echo "│ --lua <script>   │ Attach Lua configuration script         │"
    echo "│ -b               │ Output messages to stdout               │"
    echo "│ -bp              │ Output with [name] prefix               │"
    echo "│ -bt              │ Output with [HH:MM:SS] timestamp        │"
    echo "│ -bpt             │ Output with timestamp and prefix        │"
    echo "│ --max-connections│ Limit concurrent connections            │"
    echo "│ --rate-limit <n> │ Messages/sec per connection (token bkt) │"
    echo "│ --drain          │ Graceful shutdown (flush pending writes)│"
    echo "│ --tls            │ Enable TLS encryption                   │"
    echo "│ --cert <file>    │ TLS certificate (PEM)                   │"
    echo "│ --key <file>     │ TLS private key (PEM)                   │"
    echo "│ --ca <file>      │ TLS CA certificate                      │"
    echo "└──────────────────┴─────────────────────────────────────────┘"
    echo ""

    echo -e "${BOLD}Server/Client Flags:${NC}"
    echo "┌──────────────────┬─────────────────────────────────────────┐"
    echo "│ --mode inout     │ Bidirectional (default)                 │"
    echo "│ --mode in        │ Receive only                            │"
    echo "│ --mode out       │ Send only                               │"
    echo "│ --mode master    │ Master mode (one controller) [server]   │"
    echo "│ --master-pw <pw> │ Static password for master auth         │"
    echo "│ --master-forward │ Forward non-master msgs to master       │"
    echo "│ --udp            │ Use UDP instead of TCP                  │"
    echo "└──────────────────┴─────────────────────────────────────────┘"
    echo ""
    echo -e "${BOLD}Auto-detected Features (no flags):${NC}"
    echo "  WebSocket: Detected per-connection from HTTP upgrade headers"
    echo "  Cache access: Send \"cache <cmd>\" through --cache-linked server"
    echo ""

    echo -e "${BOLD}Client-only Flags:${NC}"
    echo "┌──────────────────────┬─────────────────────────────────────────┐"
    echo "│ -t <host:port>       │ Target server                           │"
    echo "│ --reconnect [max]    │ Auto-reconnect with exponential backoff │"
    echo "└──────────────────────┴─────────────────────────────────────────┘"
    echo ""

    echo -e "${BOLD}Proxy Flags:${NC}"
    echo "┌────────────────────────┬─────────────────────────────────────┐"
    echo "│ --backend <addr>       │ Backend (ip:port or runtime name)   │"
    echo "│ --strategy <strategy>  │ round-robin, random, lua            │"
    echo "│ --protocol <protocol>  │ http (default), tcp                 │"
    echo "└────────────────────────┴─────────────────────────────────────┘"
    echo ""

    echo -e "${BOLD}Cache Flags:${NC}"
    echo "┌────────────────────────┬─────────────────────────────────────┐"
    echo "│ --persistent <file>    │ Persistence file path               │"
    echo "│ --mode readonly        │ GET, SIZE only (deny writes)        │"
    echo "│ --mode readwrite       │ GET, SET, DEL, SIZE (default)       │"
    echo "│ --mode admin           │ All commands incl. FLUSH, LOAD      │"
    echo "│ --maxmemory <size>     │ Max memory (e.g. 100M, 1G)          │"
    echo "│ --eviction <policy>    │ noeviction, allkeys-lru, allkeys-rnd│"
    echo "│ --resp                 │ Force RESP2 (Redis wire protocol)    │"
    echo "│ --replicate <host:port>│ Connect as follower to leader cache  │"
    echo "└────────────────────────┴─────────────────────────────────────┘"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Lua Configuration
lua_config() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Lua Configuration ═══${NC}\n"

    echo -e "${BOLD}Configuration File Structure:${NC}"
    echo -e "${CYAN}runtimes = {"
    echo "    {"
    echo "        type = \"server\","
    echo "        name = \"api\","
    echo "        port = 9000,"
    echo "        mode = \"inout\","
    echo "        autostart = true"
    echo "    },"
    echo "    -- more runtimes..."
    echo -e "}${NC}"
    echo ""

    echo -e "${BOLD}Available Callbacks:${NC}"
    echo "┌──────────────────────────────┬──────────────────────────────────┐"
    echo "│ on_start()                   │ Called when runtime starts       │"
    echo "│ on_stop()                    │ Called when runtime stops        │"
    echo "│ on_message(msg)              │ Called on message received       │"
    echo "│ on_connect(client_id)        │ Called on client connect         │"
    echo "│ on_disconnect(client_id)     │ Called on client disconnect      │"
    echo "│ on_send(msg)                 │ Called on message sent           │"
    echo "│ on_route(method, path)       │ Proxy: custom backend selection  │"
    echo "│ on_master_auth(id, pw)       │ Server: master mode auth         │"
    echo "│ on_tick(dt)                  │ Periodic timer (tick_ms global)  │"
    echo "│ on_miss(key)→val,ttl         │ Cache: GET miss — fetch from DB  │"
    echo "│ on_write(key,val,ttl)        │ Cache: after SET — write to DB   │"
    echo "│ on_delete(key)               │ Cache: after DEL — delete in DB  │"
    echo "│ on_expire(key)               │ Cache: after TTL expiry          │"
    echo "└──────────────────────────────┴──────────────────────────────────┘"
    echo ""

    echo -e "${BOLD}Runtime Properties (self.):${NC}"
    echo "  self.name, self.port, self.state, self.type, self.protocol"
    echo ""

    echo -e "${BOLD}Runtime Methods:${NC}"
    echo "  self.send(msg)         - Send message (client)"
    echo "  self.send(id, msg)     - Send to specific client (server)"
    echo "  self.broadcast(msg)    - Broadcast (server)"
    echo "  self.publish(ch, msg)  - Publish to channel (cache)"
    echo ""
    echo -e "${BOLD}Cache Methods (Lua):${NC}"
    echo "  Strings: self.get(key), self.set(key, val), self.del(key)"
    echo "  Lists:   self.lpush(key, val), self.rpush(key, val)"
    echo "           self.lpop(key), self.rpop(key), self.llen(key)"
    echo "  Sets:    self.sadd(key, m), self.srem(key, m), self.scard(key)"
    echo "           self.sismember(key, m)"
    echo "  Hashes:  self.hset(key, f, v), self.hget(key, f)"
    echo "           self.hdel(key, f), self.hlen(key)"
    echo "  TTL:     self.expire(key, sec), self.ttl(key), self.persist(key)"
    echo ""

    echo -e "${BOLD}Global Functions:${NC}"
    echo "  socketley.log(msg)  - Print with [lua] prefix"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Examples Menu
examples_menu() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Examples ═══${NC}\n"
    echo -e "  ${GREEN}1)${NC} Basic Server"
    echo -e "  ${GREEN}2)${NC} Server + Client"
    echo -e "  ${GREEN}3)${NC} HTTP Proxy"
    echo -e "  ${GREEN}4)${NC} Load Balancer"
    echo -e "  ${GREEN}5)${NC} Persistent Cache"
    echo -e "  ${GREEN}6)${NC} Lua Config Example"
    echo -e "  ${GREEN}7)${NC} UDP Server"
    echo -e "  ${GREEN}8)${NC} Pub/Sub (Cache)"
    echo -e "  ${GREEN}9)${NC} RESP Mode (Redis-compatible)"
    echo -e "  ${GREEN}10)${NC} Cache Replication"
    echo -e "  ${GREEN}11)${NC} Stats & Reload"
    echo -e "  ${GREEN}12)${NC} Interactive Mode (-i)"
    echo -e "  ${GREEN}13)${NC} Master Mode"
    echo -e "  ${GREEN}14)${NC} WebSocket Server"
    echo -e "  ${GREEN}15)${NC} Cache Access via Server"
    echo ""
    echo -e "  ${RED}b)${NC} Back to main menu"
    echo ""
    read -p "Enter choice: " choice
    case $choice in
        1) example_basic_server ;;
        2) example_server_client ;;
        3) example_http_proxy ;;
        4) example_load_balancer ;;
        5) example_persistent_cache ;;
        6) example_lua_config ;;
        7) example_udp_server ;;
        8) example_pubsub ;;
        9) example_resp ;;
        10) example_replication ;;
        11) example_stats_reload ;;
        12) example_interactive ;;
        13) example_master_mode ;;
        14) example_websocket ;;
        15) example_cache_access ;;
        b|B) main_menu ;;
        *) examples_menu ;;
    esac
}

example_basic_server() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Basic Server Example ═══${NC}\n"
    echo -e "${CYAN}# Start daemon"
    echo "socketley daemon &"
    echo ""
    echo "# Create and start server"
    echo "socketley create server myserver -p 9000 -s"
    echo ""
    echo "# Test with netcat"
    echo "nc localhost 9000"
    echo ""
    echo "# Cleanup"
    echo "socketley stop myserver"
    echo -e "socketley remove myserver${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_server_client() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Server + Client Example ═══${NC}\n"
    echo -e "${CYAN}# Create server"
    echo "socketley create server api -p 9000 -s"
    echo ""
    echo "# Create client connecting to server"
    echo "socketley create client cli -t 127.0.0.1:9000 -s"
    echo ""
    echo "# Check status"
    echo "socketley ps"
    echo ""
    echo "# Cleanup"
    echo "socketley stop cli api"
    echo -e "socketley remove cli api${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_http_proxy() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ HTTP Proxy Example ═══${NC}\n"
    echo -e "${CYAN}# Create backend"
    echo "socketley create server backend -p 9001 -s"
    echo ""
    echo "# Create HTTP proxy"
    echo "socketley create proxy gateway -p 8080 --backend 127.0.0.1:9001 -s"
    echo ""
    echo "# Test (path prefix stripped)"
    echo "curl localhost:8080/gateway/api/users"
    echo ""
    echo "# Cleanup"
    echo "socketley stop gateway backend"
    echo -e "socketley remove gateway backend${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_load_balancer() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Load Balancer Example ═══${NC}\n"
    echo -e "${CYAN}# Create multiple backends"
    echo "socketley create server api1 -p 9001 -s"
    echo "socketley create server api2 -p 9002 -s"
    echo "socketley create server api3 -p 9003 -s"
    echo ""
    echo "# Create load balancer"
    echo "socketley create proxy lb -p 8080 \\"
    echo "    --backend 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 \\"
    echo "    --strategy round-robin -s"
    echo ""
    echo "# Test (requests distributed across backends)"
    echo "for i in {1..6}; do curl localhost:8080/lb/test; done"
    echo ""
    echo "# Cleanup"
    echo "socketley stop lb api1 api2 api3"
    echo -e "socketley remove lb api1 api2 api3${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_persistent_cache() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Persistent Cache Example ═══${NC}\n"
    echo -e "${CYAN}# Create persistent cache"
    echo "socketley create cache store -p 9000 --persistent /tmp/cache.bin -s"
    echo ""
    echo "# Data persists across restarts"
    echo "socketley stop store"
    echo "socketley start store  # Data is restored!"
    echo ""
    echo "# Cleanup"
    echo "socketley stop store"
    echo "socketley remove store"
    echo -e "rm /tmp/cache.bin${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_lua_config() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Lua Config Example ═══${NC}\n"
    echo -e "${CYAN}# config.lua"
    echo "runtimes = {"
    echo "    { type = \"server\", name = \"api\", port = 9000, autostart = true },"
    echo "    { type = \"client\", name = \"cli\", target = \"127.0.0.1:9000\", autostart = true }"
    echo "}"
    echo ""
    echo "function on_start()"
    echo "    socketley.log(\"Started: \" .. self.name)"
    echo "end"
    echo ""
    echo "function on_message(msg)"
    echo "    socketley.log(\"Got: \" .. msg)"
    echo "    self.broadcast(\"Echo: \" .. msg)"
    echo "end"
    echo ""
    echo "# Run:"
    echo -e "socketley --lua config.lua${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_udp_server() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ UDP Server Example ═══${NC}\n"
    echo -e "${CYAN}# Create UDP server (fire-and-forget messaging)"
    echo "socketley create server metrics -p 9000 --udp -b -s"
    echo ""
    echo "# Send datagrams with socat"
    echo "echo \"cpu.load 0.42\" | socat - UDP:localhost:9000"
    echo "echo \"mem.used 1024\" | socat - UDP:localhost:9000"
    echo ""
    echo "# Create UDP client"
    echo "socketley create client udpcli -t 127.0.0.1:9000 --udp -b -s"
    echo ""
    echo "# Cleanup"
    echo "socketley stop metrics udpcli"
    echo -e "socketley remove metrics udpcli${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_pubsub() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Pub/Sub (Cache) Example ===${NC}\n"
    echo -e "${CYAN}# Create cache"
    echo "socketley create cache store -p 9000 -s"
    echo ""
    echo "# Terminal 1: Subscribe"
    echo "echo 'subscribe news' | nc -q 60 localhost 9000"
    echo ""
    echo "# Terminal 2: Publish"
    echo "echo 'publish news breaking-update' | nc -q 1 localhost 9000"
    echo ""
    echo "# Subscriber receives: message news breaking-update"
    echo ""
    echo "# Lua: publish from script"
    echo "self.publish(\"news\", \"hello from lua\")"
    echo ""
    echo "# Cleanup"
    echo "socketley stop store"
    echo -e "socketley remove store${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_resp() {
    show_header
    echo -e "${BOLD}${YELLOW}=== RESP Mode (Redis-compatible) Example ===${NC}\n"
    echo -e "${CYAN}# Create RESP-mode cache (compatible with redis-cli)"
    echo "socketley create cache myredis -p 6379 --resp -s"
    echo ""
    echo "# Use redis-cli"
    echo "redis-cli -p 6379 SET mykey myval"
    echo "redis-cli -p 6379 GET mykey       # => myval"
    echo "redis-cli -p 6379 LPUSH q a b c"
    echo "redis-cli -p 6379 LRANGE q 0 -1"
    echo "redis-cli -p 6379 HSET user name alice"
    echo "redis-cli -p 6379 HGETALL user"
    echo ""
    echo "# Auto-detect: without --resp, first byte '*' switches to RESP"
    echo "socketley create cache auto -p 9000 -s"
    echo "redis-cli -p 9000 PING   # Auto-detected as RESP"
    echo ""
    echo "# Cleanup"
    echo "socketley stop myredis auto"
    echo -e "socketley remove myredis auto${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_replication() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Cache Replication Example ===${NC}\n"
    echo -e "${CYAN}# Create leader cache"
    echo "socketley create cache leader -p 9000 -s"
    echo ""
    echo "# Create follower (connects to leader)"
    echo "socketley create cache follower -p 9001 --replicate 127.0.0.1:9000 -s"
    echo ""
    echo "# Write to leader"
    echo "echo 'set user alice' | nc -q 1 localhost 9000"
    echo ""
    echo "# Read from follower (data replicated)"
    echo "echo 'get user' | nc -q 1 localhost 9001   # => alice"
    echo ""
    echo "# Stats show replication info"
    echo "socketley stats leader    # repl_role:leader, followers:1"
    echo "socketley stats follower  # repl_role:follower"
    echo ""
    echo "# Cleanup"
    echo "socketley stop follower leader"
    echo -e "socketley remove follower leader${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_stats_reload() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Stats & Reload Example ===${NC}\n"
    echo -e "${CYAN}# Create server with Lua script"
    echo "socketley create server api -p 9000 --lua handler.lua -s"
    echo ""
    echo "# View statistics"
    echo "socketley stats api"
    echo "# Output:"
    echo "#   name:api"
    echo "#   type:server"
    echo "#   port:9000"
    echo "#   connections:3"
    echo "#   total_connections:42"
    echo "#   total_messages:1500"
    echo "#   bytes_in:65000"
    echo "#   bytes_out:120000"
    echo ""
    echo "# Restart the runtime (stop + start)"
    echo "socketley reload api"
    echo ""
    echo "# Edit handler.lua, then hot-reload Lua only"
    echo "socketley reload-lua api"
    echo "# Lua context re-created without stopping the server"
    echo ""
    echo "# Cache stats include extra fields"
    echo "socketley stats mycache"
    echo "#   memory_used:1048576"
    echo "#   max_memory:268435456"
    echo -e "#   eviction:allkeys-lru${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_interactive() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Interactive Mode (-i) Example ===${NC}\n"
    echo -e "${CYAN}# Start a server in interactive mode"
    echo "socketley create server echo -p 9000"
    echo "socketley start echo -i"
    echo "# Type messages to broadcast to clients"
    echo "# Received messages appear on stdout"
    echo "# Press Ctrl+C to detach (server keeps running)"
    echo ""
    echo "# Attach to an already-running cache"
    echo "socketley start mycache -i"
    echo "# Type cache commands directly:"
    echo "#   set foo bar    => ok"
    echo "#   get foo        => bar"
    echo "#   lpush q hello  => ok"
    echo "#   lpop q         => hello"
    echo "# Press Ctrl+C to detach"
    echo ""
    echo "# Interactive client session"
    echo "socketley create client cli -t 127.0.0.1:9000"
    echo "socketley start cli -i"
    echo "# Type messages to send to server"
    echo -e "# Received messages from server appear on stdout${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_master_mode() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Master Mode Example ===${NC}\n"
    echo -e "${CYAN}# Create server in master mode with static password"
    echo "socketley create server broadcast -p 9000 \\"
    echo "    --mode master --master-pw secret -s"
    echo ""
    echo "# Client A claims master"
    echo "echo 'master secret' | nc localhost 9000"
    echo "# => master: ok"
    echo ""
    echo "# Client A sends message (broadcast to all others)"
    echo "echo 'hello everyone' | nc localhost 9000"
    echo ""
    echo "# Client B sends message (silently dropped)"
    echo ""
    echo "# With forwarding: non-master messages forwarded to master"
    echo "socketley create server ctrl -p 9000 \\"
    echo "    --mode master --master-pw admin --master-forward -s"
    echo ""
    echo "# Lua auth (instead of --master-pw):"
    echo "function on_master_auth(client_id, password)"
    echo "    return password == \"dynamic-secret\""
    echo "end"
    echo ""
    echo "# Cleanup"
    echo "socketley stop broadcast"
    echo -e "socketley remove broadcast${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_websocket() {
    show_header
    echo -e "${BOLD}${YELLOW}=== WebSocket Server Example ===${NC}\n"
    echo -e "${CYAN}# Create a server (WebSocket auto-detected, no flag needed)"
    echo "socketley create server ws -p 9000 -s"
    echo ""
    echo "# Browser JavaScript:"
    echo "const ws = new WebSocket('ws://localhost:9000');"
    echo "ws.onmessage = e => console.log(e.data);"
    echo "ws.send('hello');"
    echo ""
    echo "# Raw TCP clients also work on the same port:"
    echo "echo 'hello' | nc localhost 9000"
    echo ""
    echo "# Both WS and TCP clients receive broadcasts"
    echo "# WS messages are transparently framed/deframed"
    echo ""
    echo "# Works with master mode and cache access too:"
    echo "# WS client sends 'master secret' -> 'master: ok'"
    echo "# WS client sends 'cache get foo' -> 'bar'"
    echo ""
    echo "# Cleanup"
    echo "socketley stop ws"
    echo -e "socketley remove ws${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

example_cache_access() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Cache Access via Server Example ===${NC}\n"
    echo -e "${CYAN}# Create cache and server linked together"
    echo "socketley create cache db -p 9001 -s"
    echo "socketley create server api -p 9000 --cache db -s"
    echo ""
    echo "# Clients send cache commands through the server"
    echo "echo 'cache set user:1 alice' | nc localhost 9000"
    echo "# => ok"
    echo ""
    echo "echo 'cache get user:1' | nc localhost 9000"
    echo "# => alice"
    echo ""
    echo "echo 'cache hset user:1 name bob' | nc localhost 9000"
    echo "echo 'cache hget user:1 name' | nc localhost 9000"
    echo "# => bob"
    echo ""
    echo "# Normal messages are still broadcast as usual"
    echo "echo 'hello' | nc localhost 9000  # broadcast"
    echo ""
    echo "# Works with WebSocket clients too!"
    echo ""
    echo "# Cleanup"
    echo "socketley stop api db"
    echo -e "socketley remove api db${NC}"
    echo ""
    read -p "Press Enter to continue..."
    examples_menu
}

# Architecture Overview
architecture() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Architecture Overview ═══${NC}\n"

    echo "┌─────────────────────────────────────────────────────────────────────┐"
    echo "│                         socketley CLI                              │"
    echo "│                    (commands: create, run, stop, etc.)             │"
    echo "└───────────────────────────────┬─────────────────────────────────────┘"
    echo "                                │ IPC (Unix Socket)"
    echo "                                ▼"
    echo "┌─────────────────────────────────────────────────────────────────────┐"
    echo "│                       socketley daemon                             │"
    echo "│                  (central runtime manager)                         │"
    echo "├─────────────────────────────────────────────────────────────────────┤"
    echo "│                                                                     │"
    echo "│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐       │"
    echo "│   │  server  │   │  client  │   │  proxy   │   │  cache   │       │"
    echo "│   │ instance │   │ instance │   │ instance │   │ instance │       │"
    echo "│   └──────────┘   └──────────┘   └──────────┘   └──────────┘       │"
    echo "│                                                                     │"
    echo "│   ┌─────────────────────────────────────────────────────────────┐ │"
    echo "│   │                     io_uring event loop                      │ │"
    echo "│   │              (high-performance async I/O)                    │ │"
    echo "│   └─────────────────────────────────────────────────────────────┘ │"
    echo "│                                                                     │"
    echo "└─────────────────────────────────────────────────────────────────────┘"
    echo ""

    echo -e "${BOLD}Key Components:${NC}"
    echo "  • CLI: Command-line interface for management"
    echo "  • Daemon: Central process managing all runtimes"
    echo "  • Runtime Manager: Thread-safe registry of instances"
    echo "  • Event Loop: io_uring-based async I/O"
    echo "  • Lua Context: Scripting and callbacks"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Troubleshooting
troubleshooting() {
    show_header
    echo -e "${BOLD}${YELLOW}═══ Troubleshooting ═══${NC}\n"

    echo -e "${BOLD}Problem: Commands return \"Connection refused\"${NC}"
    echo -e "  ${GREEN}Solution:${NC} Start the daemon first"
    echo -e "  ${CYAN}socketley daemon &${NC}"
    echo ""

    echo -e "${BOLD}Problem: \"Runtime not found\"${NC}"
    echo -e "  ${GREEN}Solution:${NC} Check runtime exists"
    echo -e "  ${CYAN}socketley ls${NC}"
    echo ""

    echo -e "${BOLD}Problem: Port already in use${NC}"
    echo -e "  ${GREEN}Solution:${NC} Use different port or stop existing service"
    echo -e "  ${CYAN}socketley create server api -p 9001 -s${NC}"
    echo ""

    echo -e "${BOLD}Problem: Proxy returns 404${NC}"
    echo -e "  ${GREEN}Solution:${NC} Include proxy name in path"
    echo -e "  ${CYAN}curl localhost:8080/proxy-name/api/endpoint${NC}"
    echo ""

    echo -e "${BOLD}Problem: Lua callbacks not firing${NC}"
    echo -e "  ${GREEN}Solution:${NC} Ensure --lua flag is used or Lua in config"
    echo -e "  ${CYAN}socketley create server api -p 9000 --lua config.lua -s${NC}"
    echo ""

    echo -e "${BOLD}View logs:${NC}"
    echo -e "  ${CYAN}socketley create server api -p 9000 --log /tmp/api.log -s${NC}"
    echo -e "  ${CYAN}tail -f /tmp/api.log${NC}"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Installation & Packaging
installation_help() {
    show_header
    echo -e "${BOLD}${YELLOW}=== Installation & Packaging ===${NC}\n"

    echo -e "${BOLD}Development Mode (no install required):${NC}"
    echo -e "  Run from build directory. State stored in:"
    echo -e "  ${CYAN}~/.local/share/socketley/runtimes/${NC}  (runtime configs)"
    echo -e "  ${CYAN}/tmp/socketley.sock${NC}                 (IPC socket)"
    echo -e "  ${CYAN}~/.config/socketley/config.lua${NC}      (daemon config)"
    echo ""

    echo -e "${BOLD}System Install:${NC}"
    echo -e "  ${CYAN}sudo bash packaging/install.sh${NC}"
    echo -e "  ${CYAN}sudo systemctl start socketley${NC}"
    echo ""
    echo -e "  Installs to /usr/bin, creates systemd service, socketley user."
    echo -e "  State stored in:"
    echo -e "  ${CYAN}/var/lib/socketley/runtimes/${NC}  (runtime configs)"
    echo -e "  ${CYAN}/run/socketley/socketley.sock${NC} (IPC socket)"
    echo -e "  ${CYAN}/etc/socketley/config.lua${NC}     (daemon config)"
    echo ""

    echo -e "${BOLD}Build Debian Package:${NC}"
    echo -e "  ${CYAN}bash packaging/build-deb.sh 1.0.0${NC}"
    echo -e "  ${CYAN}sudo dpkg -i socketley_1.0.0_amd64.deb${NC}"
    echo ""

    echo -e "${BOLD}Daemon Configuration (config.lua):${NC}"
    echo -e "  ${CYAN}config = {"
    echo -e "    log_level = \"info\",       -- debug, info, warn, error"
    echo -e "    metrics_port = 9100        -- Prometheus metrics endpoint"
    echo -e "  }${NC}"
    echo -e "  When metrics_port is set, GET /metrics returns Prometheus format."
    echo ""

    echo -e "${BOLD}State Persistence:${NC}"
    echo -e "  Runtimes are saved as JSON files and survive daemon restarts."
    echo -e "  Runtimes that were running are auto-started on daemon startup."
    echo -e "  (Like Docker with restart-always policy)"
    echo ""

    echo -e "${BOLD}Uninstall:${NC}"
    echo -e "  ${CYAN}sudo bash packaging/uninstall.sh${NC}"
    echo ""

    read -p "Press Enter to continue..."
    main_menu
}

# Start the interactive help
main_menu
