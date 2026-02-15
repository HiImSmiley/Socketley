#include "runtime_factory.h"
#include "runtime_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"

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
        default:
            return nullptr;
    }
}
