-- Cache DB-Backend Example
-- Demonstrates read-through (on_miss) and write-behind (on_write) patterns.
--
-- Attach with:
--   socketley create cache mydb -p 9000 --lua db-backend.lua -s
--
-- Install DB drivers (pick one):
--   luarocks install luasql-mysql     (MySQL / MariaDB)
--   luarocks install luasql-postgres  (PostgreSQL)
--   luarocks install lsqlite3         (SQLite — embedded, no server needed)
--
-- Schema (MySQL / Postgres):
--   CREATE TABLE cache_kv (key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP DEFAULT now());

local BACKEND = "sqlite"   -- "mysql", "postgres", or "sqlite"
local TTL_SECONDS = 300    -- default TTL for DB-fetched values (0 = no expiry)
local WRITE_BEHIND = true  -- true  = buffer writes and flush every tick_ms (recommended)
                           -- false = write-through (adds DB latency to every SET)
tick_ms = 2000             -- flush pending writes to DB every 2 seconds

local db
local pending_writes = {}  -- key → value (write-behind buffer)

function on_start()
    if BACKEND == "mysql" then
        local luasql = require("luasql.mysql")
        local env = luasql.mysql()
        db = env:connect("mydb", "user", "password", "127.0.0.1", 3306)
    elseif BACKEND == "postgres" then
        local luasql = require("luasql.postgres")
        local env = luasql.postgres()
        db = env:connect("host=127.0.0.1 dbname=mydb user=app password=secret")
    elseif BACKEND == "sqlite" then
        local sqlite = require("lsqlite3")
        db = sqlite.open("/tmp/cache.db")
        db:exec("CREATE TABLE IF NOT EXISTS cache_kv (key TEXT PRIMARY KEY, value TEXT)")
    end
    socketley.log("DB backend ready: " .. BACKEND)
end

-- Called on cache GET miss. Return (value, optional_ttl_seconds) or nil.
-- If a non-nil, non-empty value is returned, it is inserted into the cache
-- with the given TTL and returned to the client transparently.
function on_miss(key)
    if not db then return nil end
    local value = nil
    if BACKEND == "sqlite" then
        for row in db:nrows("SELECT value FROM cache_kv WHERE key = " ..
                            db:quote(key)) do
            value = row.value
        end
    else
        local cur = db:execute("SELECT value FROM cache_kv WHERE key = '" ..
                               db:escape(key) .. "'")
        local row = cur:fetch({}, "a")
        if row then value = row.value end
        cur:close()
    end
    if value then
        return value, TTL_SECONDS  -- value + TTL in seconds (0 = no expiry)
    end
    return nil
end

-- Called after every successful SET / SETEX / PSETEX / SETNX.
-- ttl is the expiry in seconds (0 if no TTL was given).
--
-- WRITE-BEHIND (default): buffer in Lua, flush to DB in on_tick.
--   SET returns instantly to the client; DB sync is batched.
--   Trade-off: up to tick_ms of writes are in-cache-only before DB sync.
--
-- WRITE-THROUGH (WRITE_BEHIND = false): DB write happens inline with SET.
--   Each SET adds DB latency to the client response.
--   At 1 ms/write this saturates at ~1000 writes/s on a single thread.
function on_write(key, value, ttl)
    if WRITE_BEHIND then
        pending_writes[key] = value  -- buffer; flushed in on_tick
        return
    end
    db_upsert(key, value)
end

-- Flush buffered writes to DB (called every tick_ms).
function on_tick(dt)
    if not db or not next(pending_writes) then return end
    for key, value in pairs(pending_writes) do
        db_upsert(key, value)
    end
    pending_writes = {}
end

local function db_upsert(key, value)
    if not db then return end
    if BACKEND == "sqlite" then
        db:exec("INSERT OR REPLACE INTO cache_kv(key, value) VALUES(" ..
                db:quote(key) .. ", " .. db:quote(value) .. ")")
    else
        db:execute("INSERT INTO cache_kv(key, value) VALUES('" ..
                   db:escape(key) .. "','" .. db:escape(value) ..
                   "') ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
    end
end

-- Called after DEL. Remove the key from the DB too.
function on_delete(key)
    if not db then return end
    if BACKEND == "sqlite" then
        db:exec("DELETE FROM cache_kv WHERE key = " .. db:quote(key))
    else
        db:execute("DELETE FROM cache_kv WHERE key = '" .. db:escape(key) .. "'")
    end
    -- Also remove from pending write buffer if present
    pending_writes[key] = nil
end

-- Called when a key expires due to TTL sweep.
-- For write-through caches: expiry in cache doesn't necessarily mean delete in DB.
-- Un-comment on_delete(key) below if you want expiry to also remove from DB.
function on_expire(key)
    socketley.log("expired: " .. key)
    -- on_delete(key)  -- un-comment to propagate expiry to DB
end

function on_stop()
    -- Flush any remaining pending writes before shutdown
    if db and next(pending_writes) then
        for key, value in pairs(pending_writes) do
            db_upsert(key, value)
        end
        pending_writes = {}
    end
    if db then db:close() end
end
