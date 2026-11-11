/* socketley/capi.h — The C interface: any runtime in your own process, from any language that can call C.
 *
 * An engine is one thread with one io_uring ring; the runtimes created on it share them.  A program may have several
 * engines.  The engine takes no signal of the program's, writes nothing to stdout, and answers with return values.
 *
 * Calls may come from any thread, and block until the engine has done them.  A callback runs on the engine's thread,
 * so it must return quickly; work that takes time is handed to a thread of the program's, which answers from there.
 *
 * A function that takes `char** err` sets it, when not NULL, to a text the caller gives to skl_free when it fails.
 */
#ifndef SOCKETLEY_CAPI_H
#define SOCKETLEY_CAPI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SKL_API __attribute__((visibility("default")))

typedef struct skl_engine skl_engine;
typedef struct skl_runtime skl_runtime;
typedef struct skl_mcp_call skl_mcp_call;

/* The version of socketley this was built from; the text is not to be freed. */
SKL_API const char* skl_version(void);
/* Frees a text this interface returned. */
SKL_API void skl_free(char* text);

/* NULL when the kernel has no io_uring to give. */
SKL_API skl_engine* skl_engine_new(char** err);
/* Stops every runtime on it and ends its thread; not to be called from a callback.  Its runtime handles are then only
 * good for skl_runtime_free. */
SKL_API void skl_engine_free(skl_engine* engine);

/* A runtime of a type and with the flags `socketley create` takes: skl_runtime_create(e, "web", "site", "-p 8080
 * --root /srv/site", &err).  NULL when the type is unknown, the name taken or a flag refused.  It is not started. */
SKL_API skl_runtime* skl_runtime_create(skl_engine* engine, const char* type, const char* name, const char* flags,
                                        char** err);
/* 0 when it runs; -1 and the reason when it does not. */
SKL_API int skl_runtime_start(skl_runtime* runtime, char** err);
/* 0 when it stopped, -1 when it was not running. */
SKL_API int skl_runtime_stop(skl_runtime* runtime);
/* The runtime's figures, one `name:value` a line, for skl_free; NULL once it is gone. */
SKL_API char* skl_runtime_stats(skl_runtime* runtime);
/* Stops the runtime, removes it and frees the handle. */
SKL_API void skl_runtime_free(skl_runtime* runtime);

/* What an MCP client's tools/call runs.  `args_json` and `caller` (the key's name, empty for none) last only for the
 * call.  The tool answers with skl_mcp_reply exactly once, in the callback or later from any thread. */
typedef void (*skl_mcp_tool_fn)(void* user, skl_mcp_call* call, const char* args_json, const char* caller);

/* A tool on a runtime of type "mcp", before or after it starts; `input_schema_json` is a JSON Schema object, NULL for
 * none.  A tool of the same name is replaced.  0, or -1 and the reason. */
SKL_API int skl_mcp_tool(skl_runtime* runtime, const char* name, const char* description,
                         const char* input_schema_json, skl_mcp_tool_fn fn, void* user, char** err);
/* The tool's answer: text for the model, and is_error non-zero when the tool failed. */
SKL_API void skl_mcp_reply(skl_mcp_call* call, const char* text, int is_error);

/* A connection of a server runtime, a number never given to another; a client runtime's connections are one stream,
 * always 1. */
typedef unsigned long long skl_connection;
typedef void (*skl_connection_fn)(void* user, skl_connection connection);
typedef void (*skl_message_fn)(void* user, skl_connection connection, const char* data, size_t length);

/* Callbacks of a runtime of type "server" or "client", set before it starts, one of each.  0, or -1 and the reason. */
SKL_API int skl_on_connect(skl_runtime* runtime, skl_connection_fn fn, void* user, char** err);
SKL_API int skl_on_disconnect(skl_runtime* runtime, skl_connection_fn fn, void* user, char** err);
SKL_API int skl_on_message(skl_runtime* runtime, skl_message_fn fn, void* user, char** err);

/* Sends a line on a connection, from any thread; a connection gone by then is not an error.  -1 once the runtime or the
 * engine has ended. */
SKL_API int skl_send(skl_runtime* runtime, skl_connection connection, const char* data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
