# Cache Examples

Key-value caching with optional persistence and access control.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### Basic Cache
In-memory key-value store.

### Persistent Cache
Cache with file-based persistence across restarts.

### Cache Modes
Access control for cache operations:

```bash
# Read-only cache (GET, SIZE only)
socketley create cache lookup -p 9000 --mode readonly -s

# Read-write cache (GET, SET, DEL, SIZE - default)
socketley create cache store -p 9001 --mode readwrite -s

# Admin cache (all commands including FLUSH, LOAD)
socketley create cache admin -p 9002 --mode admin -s
```

### Cache Integration
Using cache with server/client via Lua.

## Key Concepts

### Cache Operations
- `get(key)` - Retrieve value
- `set(key, value)` - Store key-value pair
- `del(key)` - Delete key

### Cache Modes
| Mode | Allowed Commands |
|------|------------------|
| `readonly` | GET, SIZE |
| `readwrite` | GET, SET, DEL, SIZE (default) |
| `admin` | All commands including FLUSH, LOAD |

### Persistence Format
Binary format: `[key_len][key][val_len][value]...`

- Loaded automatically on startup
- Saved automatically on shutdown
- Efficient binary encoding
