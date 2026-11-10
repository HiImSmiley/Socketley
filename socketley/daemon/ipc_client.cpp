#include "ipc_client.h"
#include "daemon_handler.h"

int ipc_send(std::string_view command, std::string& data)
{
    return socketley::daemon_request(daemon_handler::socket_path, command, data);
}

int ipc_report_failure(int rc)
{
    return socketley::daemon_request_failure(daemon_handler::socket_path, rc);
}
