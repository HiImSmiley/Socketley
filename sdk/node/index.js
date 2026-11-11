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
    this.handle = handle;
    this.keepAlive = null;
  }

  start() {
    native.runtimeStart(this.handle);
    // A serving runtime keeps the program alive, as a listening server does.
    this.keepAlive = this.keepAlive || setInterval(() => {}, 2 ** 31 - 1);
    return this;
  }

  stop() {
    clearInterval(this.keepAlive);
    this.keepAlive = null;
    return native.runtimeStop(this.handle);
  }

  stats() {
    return native.runtimeStats(this.handle);
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
    native.mcpTool(this.handle, name, (options && options.description) || '', schemaOf(options && options.input), run);
    return this;
  }

  close() {
    if (!this.handle) return;
    clearInterval(this.keepAlive);
    this.keepAlive = null;
    native.runtimeFree(this.handle);
    this.handle = null;
    this.engine.runtimes.delete(this);
  }
}

class Engine {
  constructor() {
    this.handle = native.engineNew();
    this.runtimes = new Set();
  }

  runtime(type, name, flags) {
    const r = new Runtime(this, native.runtimeCreate(this.handle, type, name, flags || ''));
    this.runtimes.add(r);
    return r;
  }

  close() {
    if (!this.handle) return;
    for (const r of [...this.runtimes]) r.close();
    native.engineFree(this.handle);
    this.handle = null;
  }
}

module.exports = { Engine, Runtime, version: native.version() };
