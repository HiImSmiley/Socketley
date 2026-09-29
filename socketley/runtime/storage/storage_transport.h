#pragma once
// A shard's requests to its siblings, carried by the worker's request channel.
//
// A sibling is the target `name#index`, which the channel resolves to the
// direct link the shard mesh built and otherwise to the daemon's relay, so a
// crossing is never lost for want of a link.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "shard_node.h"
#include "../../shared/request_channel.h"
#include "../../shared/shard_target.h"

namespace socketley::storage
{

class channel_transport final : public shard_transport, public request_origin
{
public:
    channel_transport(request_channel* channel, std::string name)
        : m_channel(channel), m_name(std::move(name))
    {
    }

    ~channel_transport() override { stop(); }

    channel_transport(const channel_transport&)            = delete;
    channel_transport& operator=(const channel_transport&) = delete;

    // Nothing is told to this transport after this, which the channel is told
    // too because an origin is a bare pointer.  Requests still out are left
    // unanswered: whoever asked is going away with it.
    void stop()
    {
        if (m_channel)
            m_channel->drop_origin(this);
        m_channel = nullptr;
        m_pending.clear();
    }

    void call(uint32_t peer, std::string payload,
              std::function<void(bool, std::string_view)> cb) override
    {
        if (!m_channel)
        {
            cb(false, {});
            return;
        }
        const uint64_t cookie = next_cookie();
        m_pending.emplace(cookie, std::move(cb));
        if (!m_channel->post(this, cookie, shard_target(m_name, peer), payload, request_class::client))
        {
            auto it = m_pending.find(cookie);
            auto fn = std::move(it->second);
            m_pending.erase(it);
            fn(false, {});
        }
    }

    void on_request_reply(uint64_t cookie, request_status status, std::string_view reply) override
    {
        auto it = m_pending.find(cookie);
        if (it == m_pending.end())
            return;
        auto fn = std::move(it->second);
        m_pending.erase(it);
        fn(status == request_status::ok, reply);
    }

    size_t pending() const { return m_pending.size(); }

private:
    // One counter for the process, so a reply meant for a transport that has
    // gone is never taken for the answer to a request of the next one that
    // lands at the same address.
    static uint64_t next_cookie()
    {
        static uint64_t n = 0;
        return ++n;
    }

    request_channel* m_channel;
    std::string      m_name;
    std::unordered_map<uint64_t, std::function<void(bool, std::string_view)>> m_pending;
};

}   // namespace socketley::storage
