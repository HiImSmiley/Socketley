/* The Node binding of socketley/capi.h: index.js is its interface. */
#include <node_api.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <socketley/capi.h>

static void throw_taken(napi_env env, char* err)
{
    napi_throw_error(env, NULL, err ? err : "refused, without a reason");
    skl_free(err);
}

/* A JS string as a malloc'd C string. */
static char* text_of(napi_env env, napi_value v)
{
    size_t n = 0;
    if (napi_get_value_string_utf8(env, v, NULL, 0, &n) != napi_ok)
        return NULL;
    char* s = malloc(n + 1);
    if (s)
        napi_get_value_string_utf8(env, v, s, n + 1, &n);
    return s;
}

static void* pointer_of(napi_env env, napi_value v)
{
    void* p = NULL;
    napi_get_value_external(env, v, &p);
    return p;
}

static napi_value external(napi_env env, void* p)
{
    napi_value v;
    napi_create_external(env, p, NULL, NULL, &v);
    return v;
}

#define ARGS(n)                     \
    size_t argc = n;                \
    napi_value argv[n];             \
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL)

static napi_value version(napi_env env, napi_callback_info info)
{
    (void)info;
    napi_value v;
    napi_create_string_utf8(env, skl_version(), NAPI_AUTO_LENGTH, &v);
    return v;
}

static napi_value engine_new(napi_env env, napi_callback_info info)
{
    (void)info;
    char* err = NULL;
    skl_engine* e = skl_engine_new(&err);
    if (!e)
    {
        throw_taken(env, err);
        return NULL;
    }
    return external(env, e);
}

static napi_value engine_free(napi_env env, napi_callback_info info)
{
    ARGS(1);
    skl_engine_free(pointer_of(env, argv[0]));
    return NULL;
}

static napi_value runtime_create(napi_env env, napi_callback_info info)
{
    ARGS(4);
    char* type = text_of(env, argv[1]);
    char* name = text_of(env, argv[2]);
    char* flags = text_of(env, argv[3]);
    char* err = NULL;
    skl_runtime* r = skl_runtime_create(pointer_of(env, argv[0]), type, name, flags, &err);
    free(type);
    free(name);
    free(flags);
    if (!r)
    {
        throw_taken(env, err);
        return NULL;
    }
    return external(env, r);
}

static napi_value runtime_start(napi_env env, napi_callback_info info)
{
    ARGS(1);
    char* err = NULL;
    if (skl_runtime_start(pointer_of(env, argv[0]), &err) != 0)
        throw_taken(env, err);
    return NULL;
}

static napi_value runtime_stop(napi_env env, napi_callback_info info)
{
    ARGS(1);
    napi_value v;
    napi_get_boolean(env, skl_runtime_stop(pointer_of(env, argv[0])) == 0, &v);
    return v;
}

static napi_value runtime_stats(napi_env env, napi_callback_info info)
{
    ARGS(1);
    char* text = skl_runtime_stats(pointer_of(env, argv[0]));
    napi_value v;
    napi_create_string_utf8(env, text ? text : "", NAPI_AUTO_LENGTH, &v);
    skl_free(text);
    return v;
}

/* Tools: a call arrives on the engine's thread and JavaScript runs on its own, so the call crosses by a threadsafe
 * function.  A tool's function lives as long as the addon: a runtime has no way to take one back. */
struct pending
{
    skl_mcp_call* call;
    char* args;
    char* caller;
};

static void call_js(napi_env env, napi_value js, void* context, void* data)
{
    (void)context;
    struct pending* p = data;
    if (env)
    {
        napi_value undefined, argv[3];
        napi_get_undefined(env, &undefined);
        argv[0] = external(env, p->call);
        napi_create_string_utf8(env, p->args, NAPI_AUTO_LENGTH, &argv[1]);
        napi_create_string_utf8(env, p->caller, NAPI_AUTO_LENGTH, &argv[2]);
        napi_call_function(env, undefined, js, 3, argv, NULL);
    }
    else
    {
        skl_mcp_reply(p->call, "the program is ending", 1);
    }
    free(p->args);
    free(p->caller);
    free(p);
}

static void on_tool(void* user, skl_mcp_call* call, const char* args, const char* caller)
{
    struct pending* p = malloc(sizeof *p);
    if (!p)
    {
        skl_mcp_reply(call, "out of memory", 1);
        return;
    }
    p->call = call;
    p->args = strdup(args);
    p->caller = strdup(caller);
    if (napi_call_threadsafe_function(user, p, napi_tsfn_nonblocking) != napi_ok)
    {
        skl_mcp_reply(call, "the program is ending", 1);
        free(p->args);
        free(p->caller);
        free(p);
    }
}

static napi_value mcp_tool(napi_env env, napi_callback_info info)
{
    ARGS(5);
    napi_value resource;
    napi_create_string_utf8(env, "socketley.tool", NAPI_AUTO_LENGTH, &resource);
    napi_threadsafe_function fn;
    if (napi_create_threadsafe_function(env, argv[4], NULL, resource, 0, 1, NULL, NULL, NULL, call_js, &fn) != napi_ok)
    {
        napi_throw_error(env, NULL, "could not make a threadsafe function");
        return NULL;
    }
    /* A tool alone does not keep the program alive; a started runtime does, in index.js. */
    napi_unref_threadsafe_function(env, fn);

    napi_valuetype schema_type;
    napi_typeof(env, argv[3], &schema_type);
    char* name = text_of(env, argv[1]);
    char* description = text_of(env, argv[2]);
    char* schema = schema_type == napi_string ? text_of(env, argv[3]) : NULL;
    char* err = NULL;
    const int rc = skl_mcp_tool(pointer_of(env, argv[0]), name, description, schema, on_tool, fn, &err);
    free(name);
    free(description);
    free(schema);
    if (rc != 0)
    {
        napi_release_threadsafe_function(fn, napi_tsfn_abort);
        throw_taken(env, err);
    }
    return NULL;
}

static napi_value mcp_reply(napi_env env, napi_callback_info info)
{
    ARGS(3);
    char* text = text_of(env, argv[1]);
    bool failed = false;
    napi_get_value_bool(env, argv[2], &failed);
    skl_mcp_reply(pointer_of(env, argv[0]), text, failed);
    free(text);
    return NULL;
}

/* Events of a server or client runtime, carried across as a tool's calls are. */
struct event
{
    skl_connection connection;
    char* data;
    size_t length;
    bool has_data;
};

static void event_js(napi_env env, napi_value js, void* context, void* data)
{
    (void)context;
    struct event* e = data;
    if (env)
    {
        napi_value undefined, argv[2];
        napi_get_undefined(env, &undefined);
        napi_create_double(env, (double)e->connection, &argv[0]);
        if (e->has_data)
            napi_create_buffer_copy(env, e->length, e->data ? e->data : "", NULL, &argv[1]);
        napi_call_function(env, undefined, js, e->has_data ? 2 : 1, argv, NULL);
    }
    free(e->data);
    free(e);
}

static void push(void* tsfn, skl_connection connection, const char* data, size_t length, bool has_data)
{
    struct event* e = calloc(1, sizeof *e);
    if (!e)
        return;
    e->connection = connection;
    e->length = length;
    e->has_data = has_data;
    if (has_data && length && (e->data = malloc(length)))
        memcpy(e->data, data, length);
    if (napi_call_threadsafe_function(tsfn, e, napi_tsfn_nonblocking) != napi_ok)
    {
        free(e->data);
        free(e);
    }
}

static void on_conn(void* user, skl_connection c) { push(user, c, NULL, 0, false); }
static void on_msg(void* user, skl_connection c, const char* d, size_t n) { push(user, c, d, n, true); }

static napi_value on(napi_env env, napi_callback_info info)
{
    ARGS(3);
    char* event = text_of(env, argv[1]);
    napi_value resource;
    napi_create_string_utf8(env, "socketley.event", NAPI_AUTO_LENGTH, &resource);
    napi_threadsafe_function fn;
    if (napi_create_threadsafe_function(env, argv[2], NULL, resource, 0, 1, NULL, NULL, NULL, event_js, &fn) != napi_ok)
    {
        free(event);
        napi_throw_error(env, NULL, "could not make a threadsafe function");
        return NULL;
    }
    napi_unref_threadsafe_function(env, fn);
    skl_runtime* r = pointer_of(env, argv[0]);
    char* err = NULL;
    int rc = -1;
    if (strcmp(event, "connect") == 0)
        rc = skl_on_connect(r, on_conn, fn, &err);
    else if (strcmp(event, "disconnect") == 0)
        rc = skl_on_disconnect(r, on_conn, fn, &err);
    else if (strcmp(event, "message") == 0)
        rc = skl_on_message(r, on_msg, fn, &err);
    else
        err = strdup("the events are connect, disconnect and message");
    free(event);
    if (rc != 0)
    {
        napi_release_threadsafe_function(fn, napi_tsfn_abort);
        throw_taken(env, err);
    }
    return NULL;
}

static napi_value send_line(napi_env env, napi_callback_info info)
{
    ARGS(3);
    double connection = 0;
    napi_get_value_double(env, argv[1], &connection);
    void* data = NULL;
    size_t length = 0;
    napi_get_buffer_info(env, argv[2], &data, &length);
    napi_value v;
    napi_get_boolean(env, skl_send(pointer_of(env, argv[0]), (skl_connection)connection, data, length) == 0, &v);
    return v;
}

static napi_value runtime_free(napi_env env, napi_callback_info info)
{
    ARGS(1);
    skl_runtime_free(pointer_of(env, argv[0]));
    return NULL;
}

NAPI_MODULE_INIT()
{
    const struct
    {
        const char* name;
        napi_callback fn;
    } all[] = {
        {"version", version},           {"engineNew", engine_new},       {"engineFree", engine_free},
        {"runtimeCreate", runtime_create}, {"runtimeStart", runtime_start}, {"runtimeStop", runtime_stop},
        {"runtimeStats", runtime_stats},   {"runtimeFree", runtime_free},   {"mcpTool", mcp_tool},
        {"mcpReply", mcp_reply},           {"on", on},                      {"send", send_line},
    };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; ++i)
    {
        napi_value f;
        napi_create_function(env, all[i].name, NAPI_AUTO_LENGTH, all[i].fn, NULL, &f);
        napi_set_named_property(env, exports, all[i].name, f);
    }
    return exports;
}
