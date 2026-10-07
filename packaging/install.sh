#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/bin/Release/socketley"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "error: release binary not found at $BINARY"
    echo "build first: cd make && make config=release_x64 -j\$(nproc)"
    exit 1
fi

# Create system user and the group that reaches its socket.
#
# The group is created explicitly rather than left to useradd's default,
# because it is no longer only the daemon's own group: the IPC socket is
# 0660 socketley:socketley, so membership of `socketley` is exactly the
# set of people who can run socketley commands against the system daemon.
# Whether useradd makes a matching group depends on USERGROUPS_ENAB, which
# differs between distributions, and "who may administer this daemon" is
# not a thing to leave to /etc/login.defs.
if ! getent group socketley >/dev/null 2>&1; then
    groupadd --system socketley
fi

# The highest system uid that no account has and no running process holds: a container's processes share the host's
# uid numbers, and MariaDB's, PostgreSQL's and Redis's images all run as 999, which useradd would hand out first.
free_system_uid() {
    taken=" $(getent passwd | cut -d: -f3 | tr '\n' ' ') $(awk '/^Uid:/ { print $3 }' /proc/[0-9]*/status 2>/dev/null | tr '\n' ' ') "
    u=999
    while [ "$u" -ge 100 ]; do
        case "$taken" in *" $u "*) u=$((u - 1)) ;; *) echo "$u"; return ;; esac
    done
}

if ! id -u socketley >/dev/null 2>&1; then
    uid=$(free_system_uid)
    useradd --system ${uid:+--uid "$uid"} --no-create-home --shell /usr/sbin/nologin \
            --gid socketley socketley
fi

# Install binary
install -Dm755 "$BINARY" /usr/bin/socketley

# Install man page
if [ -f "$PROJECT_ROOT/man/socketley.1" ]; then
    install -Dm644 "$PROJECT_ROOT/man/socketley.1" /usr/share/man/man1/socketley.1
    mandb -q 2>/dev/null || true
fi

# Install help script
install -Dm755 "$PROJECT_ROOT/man/socketley-help.sh" /usr/share/socketley/socketley-help.sh

# Install systemd service
install -Dm644 "$SCRIPT_DIR/socketley.service" /usr/lib/systemd/system/socketley.service

# Create state directories
# 0750, not 0755: the files in here are the runtime records, and each one
# carries that runtime's --master-pw in plaintext along with the paths of its
# TLS and mTLS private keys.  The daemon writes them 0600, which is what
# actually protects the contents; this stops a user who is not in the socketley
# group from even listing which runtimes exist.  Members of that group are the
# operators — the same set the IPC socket admits.
install -dm750 -o socketley -g socketley /var/lib/socketley/runtimes
install -dm755 -o socketley -g socketley /run/socketley
install -dm755 /etc/socketley

# Enable and start service
systemctl daemon-reload
systemctl enable socketley.service

echo "socketley installed successfully"
echo "  start:   systemctl start socketley"
echo "  status:  systemctl status socketley"
echo "  logs:    journalctl -u socketley -f"
echo ""
echo "  The daemon's IPC socket is 0660 socketley:socketley. Every socketley"
echo "  command goes through it, and a runtime's --lua script runs with the"
echo "  daemon's privileges, so reaching it is an administrative right:"
echo "    usermod -aG socketley <user>     (the user must log in again)"
