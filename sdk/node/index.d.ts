export type JsonSchema = Record<string, unknown>;

export interface ToolOptions {
  description?: string;
  /** A JSON Schema, or the short form { name: "string", count: "number" } of required fields. */
  input?: JsonSchema | Record<string, string>;
}

/** What a tool returns is the text the model reads; an object is sent as JSON, and a throw is a failure of the tool. */
export type ToolHandler = (args: any, caller: string) => unknown | Promise<unknown>;

export interface WebRequest {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: Buffer;
}

export type WebAnswer = string | { status?: number; headers?: Record<string, string>; body?: string | Buffer };

export class Runtime {
  /** Throws why it did not start. */
  start(): this;
  stop(): boolean;
  stats(): string;
  on(event: 'connect' | 'disconnect', handler: (connection: number) => void): this;
  on(event: 'message', handler: (connection: number, data: Buffer) => void): this;
  send(connection: number, data: string | Buffer): boolean;
  /** One command of a cache runtime, in its text protocol. */
  command(line: string): string;
  /** The prefix and all under it, on a web runtime, go to handler before any file does. A throw is a 500. */
  handle(prefix: string, handler: (request: WebRequest) => WebAnswer | Promise<WebAnswer>): this;
  /** An MCP tool, on a runtime of type "mcp". */
  tool(name: string, options: ToolOptions, handler: ToolHandler): this;
  close(): void;
}

/** One thread with one io_uring ring, on which its runtimes run. */
export class Engine {
  constructor();
  /** A runtime of a type with the flags `socketley create` takes; it is not started. */
  runtime(type: string, name: string, flags?: string): Runtime;
  /** Stops every runtime on it and ends its thread. */
  close(): void;
}

export const version: string;
