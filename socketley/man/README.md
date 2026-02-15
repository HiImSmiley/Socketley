# Socketley Manual Pages

## Installation

Copy the man page to your system's man directory:

```bash
sudo cp socketley.1 /usr/local/share/man/man1/
sudo mandb
```

## Viewing

After installation:
```bash
man socketley
```

Or view directly without installation:
```bash
man ./socketley.1
```

## Quick Reference

| Command | Description |
|---------|-------------|
| `socketley daemon` | Start the daemon |
| `socketley create <type> <name>` | Create runtime |
| `socketley start <name>` | Start runtime |
| `socketley stop <name>` | Stop runtime |
| `socketley remove <name>` | Remove runtime |
| `socketley ls` | List all runtimes |
| `socketley ps` | List running runtimes |
| `socketley --config <file>` | Load Lua config |

## Runtime Types

- **server** - Accept connections, broadcast messages
- **client** - Connect to server, send/receive messages
- **proxy** - HTTP/TCP reverse proxy with load balancing
- **cache** - Key-value store with persistence

## Common Flags

| Flag | Description |
|------|-------------|
| `-p <port>` | Set port |
| `-s` | Start immediately |
| `--test` | Dry run |
| `--log <file>` | Log state changes |
| `-w <file>` | Write messages to file |
| `--lua <script>` | Attach Lua config |
