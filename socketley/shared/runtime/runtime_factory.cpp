#include "runtime_factory.h"
#include "runtime_instance.h"
#include "type_registry.h"
#include "../../runtime/cache/cache_instance.h"
#include "../../runtime/server/server_instance.h"
#include "../../runtime/client/client_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../runtime/storage/storage_instance.h"
#include "../../runtime/dns/dns_instance.h"
#include "../../runtime/sync/sync_instance.h"
#include "../../runtime/idp/idp_instance.h"
#include "../../runtime/tunnel/tunnel_instance.h"
#include "../../runtime/db/db_instance.h"
#include "../../runtime/mqtt/mqtt_instance.h"
#include "../../runtime/mail/mail_instance.h"
#include "../../runtime/metrics/metrics_instance.h"
#include "../../runtime/mcp/mcp_instance.h"
#include "../../runtime/web/web_instance.h"

std::unique_ptr<runtime_instance> create_runtime(runtime_type type, std::string_view name)
{
    switch (type)
    {
        case runtime_cache:
            return std::make_unique<cache_instance>(name);
        case runtime_server:
            return std::make_unique<server_instance>(name);
        case runtime_client:
            return std::make_unique<client_instance>(name);
        case runtime_proxy:
            return std::make_unique<proxy_instance>(name);
        case runtime_storage:
            return std::make_unique<storage_instance>(name);
        case runtime_dns:
            return std::make_unique<dns_instance>(name);
        case runtime_sync:
            return std::make_unique<sync_instance>(name);
        case runtime_idp:
            return std::make_unique<idp_instance>(name);
        case runtime_db:
            return std::make_unique<db_instance>(name);
        case runtime_mqtt:
            return std::make_unique<mqtt_instance>(name);
        case runtime_mail:
            return std::make_unique<mail_instance>(name);
        case runtime_tunnel:
            return std::make_unique<tunnel_instance>(name);
        case runtime_metrics:
            return std::make_unique<metrics_instance>(name);
        case runtime_mcp:
            return std::make_unique<mcp_instance>(name);
        case runtime_web:
            return std::make_unique<web_instance>(name);
        default:
            return type_registry::make(type, name);
    }
}
