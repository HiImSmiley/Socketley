'use strict';
const path = require('path');
const native = require(process.env.SOCKETLEY_NODE_ADDON || path.join(__dirname, 'build', 'Release', 'socketley.node'));

function schemaOf(input) {
  if (!input) return null;
  if (input.type !== undefined || input.properties !== undefined) return JSON.stringify(input);
  const properties = {};
  for (const [name, type] of Object.entries(input)) properties[name] = { type };
  return JSON.stringify({ type: 'object', properties, required: Object.keys(input) });
}

class Runtime {
  constructor(engine, handle) {
    this.engine = engine;
    this.ptr = handle;
    this.keepAlive = null;
  }

  start() {
    native.runtimeStart(this.ptr);
    // A serving runtime keeps the program alive, as a listening server does.
    this.keepAlive = this.keepAlive || setInterval(() => {}, 2 ** 31 - 1);
    return this;
  }

  stop() {
    clearInterval(this.keepAlive);
    this.keepAlive = null;
    return native.runtimeStop(this.ptr);
  }

  stats() {
    return native.runtimeStats(this.ptr);
  }

  /** 'connect' and 'disconnect' give (connection), 'message' gives (connection, Buffer). */
  on(event, handler) {
    native.on(this.ptr, event, handler);
    return this;
  }

  /** One command of a cache runtime, in its text protocol. */
  command(line) {
    return native.cacheCommand(this.ptr, line).trimEnd();
  }

  /** The prefix and all under it, on a web runtime, go to handler(request) before any file does. */
  handle(prefix, handler) {
    native.webHandler(this.ptr, prefix, (request, method, path, query, headerText, body) => {
      const headers = {};
      for (const line of headerText.split('\n')) {
        const at = line.indexOf(':');
        if (at > 0) headers[line.slice(0, at).toLowerCase()] = line.slice(at + 1).trim();
      }
      const finish = (a) => {
        const { status = 200, headers: out = {}, body: text = '' } = typeof a === 'string' ? { body: a } : (a || {});
        const lines = Object.entries(out).map(([k, v]) => `${k}: ${v}`);
        if (!Object.keys(out).some((k) => k.toLowerCase() === 'content-type')) lines.push('Content-Type: text/plain; charset=utf-8');
        native.webReply(request, status, lines.join('\n'), Buffer.from(text));
      };
      Promise.resolve()
        .then(() => handler({ method, path, query, headers, body }))
        .then(finish, (e) => finish({ status: 500, body: String((e && e.message) || e) }));
    });
    return this;
  }

  /** Sends a line on a connection. */
  send(connection, data) {
    return native.send(this.ptr, connection, Buffer.from(data));
  }

  tool(name, options, handler) {
    const run = (call, argsJson, caller) => {
      Promise.resolve()
        .then(() => handler(JSON.parse(argsJson), caller))
        .then(
          (v) => native.mcpReply(call, typeof v === 'string' ? v : JSON.stringify(v ?? null), false),
          (e) => native.mcpReply(call, String((e && e.message) || e), true),
        );
    };
    native.mcpTool(this.ptr, name, (options && options.description) || '', schemaOf(options && options.input), run);
    return this;
  }

  close() {
    if (!this.ptr) return;
    clearInterval(this.keepAlive);
    this.keepAlive = null;
    native.runtimeFree(this.ptr);
    this.ptr = null;
    this.engine.runtimes.delete(this);
  }
}

class Engine {
  constructor() {
    this.ptr = native.engineNew();
    this.runtimes = new Set();
  }

  runtime(type, name, flags) {
    const r = new Runtime(this, native.runtimeCreate(this.ptr, type, name, flags || ''));
    this.runtimes.add(r);
    return r;
  }

  close() {
    if (!this.ptr) return;
    for (const r of [...this.runtimes]) r.close();
    native.engineFree(this.ptr);
    this.ptr = null;
  }
}

module.exports = { Engine, Runtime, version: native.version() };
