#pragma once
// What a script does in an mqtt runtime: on_auth decides who connects, on_publish and on_subscribe decide what
// passes, and on_connect and on_disconnect are told. The deciding ones run on a coroutine, so a hook that asks
// another runtime -- a db through socketley.db, say -- stops itself and the broker goes on; the connection it
// decides for reads nothing more until it answers.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "mqtt_broker.h"

class mqtt_instance;

namespace socketley::mqtt
{

class mqtt_lua
{
public:
    explicit mqtt_lua(mqtt_instance& owner);

    bool wants_auth() const;
    bool wants_publish() const;
    bool wants_subscribe() const;

    // The credentials' verdict handed to on_auth, which may keep it (nil), allow (true) or refuse (false).
    void auth(const auth_ask& ask, bool verified, bool allowed, const std::string& username,
              std::function<void(bool)> done);
    // true or nil lets it pass, false refuses it, a table {topic=, payload=, qos=, retain=} replaces it.
    void publish(const client_info& c, const message_ptr& m, std::function<void(publish_verdict)> done);
    void subscribe(const client_info& c, const std::string& filter, uint8_t qos, std::function<void(bool)> done);
    void connected(const client_info& c);
    void disconnected(const client_info& c, std::string_view why);

private:
    mqtt_instance& m_owner;
};

}   // namespace socketley::mqtt
