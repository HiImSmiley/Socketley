#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <sys/un.h>

#include "../shared/event_loop_definitions.h"
#include "../cli/arg_parser.h"

class event_loop;
class runtime_manager;
class state_persistence;

struct ipc_connection
{
    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string write_buf;
    std::string partial;

    bool interactive = false;
    std::string interactive_name;
};

class daemon_handler : public io_handler
{
public:
    daemon_handler(runtime_manager& manager, event_loop& loop);
    ~daemon_handler() override;

    bool setup();
    void teardown();
    void on_cqe(struct io_uring_cqe* cqe) override;

    void set_state_persistence(state_persistence* sp);

    static std::string socket_path;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);

    // Returns -1 if names resolved OK (caller should continue), otherwise the exit code to return.
    // conn == nullptr → stdout errors, conn != nullptr → conn->write_buf errors.
    int check_empty_names(const std::vector<std::string>& names,
        const parsed_args& pa, const char* verb, ipc_connection* conn) const;

    int process_command(ipc_connection* conn, std::string_view line);
    int cmd_create(const parsed_args& pa);
    int cmd_start(ipc_connection* conn, const parsed_args& pa);
    int cmd_stop(ipc_connection* conn, const parsed_args& pa);
    int cmd_remove(ipc_connection* conn, const parsed_args& pa);
    int cmd_ls(ipc_connection* conn, const parsed_args& pa);
    int cmd_ps(ipc_connection* conn, const parsed_args& pa);
    int cmd_send(const parsed_args& pa);
    int cmd_edit(const parsed_args& pa);
    int cmd_dump(ipc_connection* conn, const parsed_args& pa);
    int cmd_import(ipc_connection* conn, const parsed_args& pa);
    int cmd_action(ipc_connection* conn, const parsed_args& pa);
    int cmd_stats(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload_lua(ipc_connection* conn, const parsed_args& pa);
    int cmd_owner(ipc_connection* conn, const parsed_args& pa);

    std::vector<std::string> resolve_names(const parsed_args& pa, size_t start = 1) const;

    void send_response(ipc_connection* conn, int exit_code);

    runtime_manager& m_manager;
    event_loop& m_loop;

    int m_listen_fd;
    struct sockaddr_un m_accept_addr;
    socklen_t m_accept_addrlen;
    io_request m_accept_req;

    std::unordered_map<int, std::unique_ptr<ipc_connection>> m_clients;

    state_persistence* m_persistence = nullptr;
};
