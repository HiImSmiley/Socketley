#include "shard_node.h"

#include <memory>
#include <vector>

#include "s3_names.h"
#include "shard_wire.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

shard_node::shard_node(object_store& store, shard_transport& transport)
    : m_store(store), m_transport(transport), m_alive(std::make_shared<bool>(true))
{
    m_store.set_peers(this);
}

shard_node::~shard_node()
{
    stop();
}

void shard_node::stop()
{
    *m_alive = false;
    m_store.set_peers(nullptr);
}

void shard_node::each_peer(const std::function<std::string(uint32_t)>& make,
                           std::function<void(uint32_t, bool, std::string_view)> one,
                           std::function<void()> done)
{
    struct state
    {
        size_t pending{0};
        std::function<void(uint32_t, bool, std::string_view)> one;
        std::function<void()> done;
    };
    auto s  = std::make_shared<state>();
    s->one  = std::move(one);
    s->done = std::move(done);

    std::vector<uint32_t> peers;
    for (uint32_t j = 0; j < m_store.shards(); ++j)
        if (j != m_store.shard())
            peers.push_back(j);
    if (peers.empty())
    {
        s->done();
        return;
    }
    s->pending = peers.size();

    auto alive = m_alive;
    for (const uint32_t j : peers)
    {
        m_transport.call(j, make(j), [this, alive, s, j](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            if (!ok)
                ++m_c.peer_failures;
            s->one(j, ok, reply);
            if (--s->pending == 0)
                s->done();
        });
    }
}

// ─── Keys ───────────────────────────────────────────────────────────────────

void shard_node::commit(uint32_t owner, commit_request req, std::function<void(put_result)> cb)
{
    ++m_c.commits_out;
    auto alive = m_alive;
    m_transport.call(owner, wire::encode_commit(req), [this, alive, cb](bool ok, std::string_view reply)
    {
        if (!*alive)
            return;
        st s = st::io_error;
        if (!ok || !wire::decode_status(reply, s))
        {
            ++m_c.peer_failures;
            s = st::io_error;
        }
        cb({s, {}});
    });
}

void shard_node::remove(uint32_t owner, std::string bucket, std::string key,
                        std::function<void(st, bool)> cb)
{
    ++m_c.removes_out;
    auto alive = m_alive;
    m_transport.call(owner, wire::encode_remove(bucket, key), [this, alive, cb](bool ok, std::string_view reply)
    {
        if (!*alive)
            return;
        st s = st::io_error;
        bool existed = false;
        if (!ok || !wire::decode_removed(reply, s, existed))
        {
            ++m_c.peer_failures;
            s = st::io_error;
            existed = false;
        }
        cb(s, existed);
    });
}

// ─── Buckets ────────────────────────────────────────────────────────────────

void shard_node::create_bucket(std::string name, std::function<void(st)> cb)
{
    if (m_store.shard() == 0)
    {
        run_create(std::move(name), [cb](st s, int64_t) { cb(s); });
        return;
    }
    if (!valid_bucket_name(name))
    {
        cb(st::invalid_bucket_name);
        return;
    }
    if (m_store.has_bucket(name))
    {
        cb(st::bucket_exists);
        return;
    }
    ++m_c.bucket_ops;
    auto alive = m_alive;
    m_transport.call(0, wire::encode_bucket(wire::op::bucket_create, name),
        [this, alive, name, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            int64_t ms = 0;
            if (!ok || !wire::decode_created(reply, s, ms))
            {
                ++m_c.peer_failures;
                cb(st::io_error);
                return;
            }
            // Shard 0 told this shard of the bucket before it answered, and if
            // that notice was lost the answer carries what is needed to take it up.
            if ((s == st::ok || s == st::bucket_exists) && !m_store.has_bucket(name))
            {
                m_store.adopt_bucket(name, ms, [cb, s](st a) { cb(a == st::ok ? s : a); });
                return;
            }
            cb(s);
        });
}

void shard_node::run_create(std::string name, std::function<void(st, int64_t)> cb)
{
    ++m_c.bucket_ops;
    auto alive = m_alive;
    m_store.create_bucket(name, [this, alive, name, cb](st s)
    {
        if (!*alive)
            return;
        // A bucket that is there already is told again, which costs nothing and
        // repairs a shard that was missed.
        if (s != st::ok && s != st::bucket_exists)
        {
            cb(s, 0);
            return;
        }
        const int64_t ms = m_store.bucket_created_ms(name);
        each_peer([name, ms](uint32_t) { return wire::encode_bucket(wire::op::bucket_adopt, name, ms); },
                  [name](uint32_t peer, bool ok, std::string_view reply)
                  {
                      st a = st::io_error;
                      if (!ok || !wire::decode_status(reply, a) || a != st::ok)
                          LOG_WARN(("storage: shard " + std::to_string(peer) + " did not take up the bucket " +
                                    name + "; it does when it next starts").c_str());
                  },
                  [cb, s, ms]() { cb(s, ms); });
    });
}

void shard_node::delete_bucket(std::string name, std::function<void(st)> cb)
{
    if (m_store.shard() == 0)
    {
        run_drop(std::move(name), std::move(cb));
        return;
    }
    if (!m_store.has_bucket(name))
    {
        cb(st::no_such_bucket);
        return;
    }
    ++m_c.bucket_ops;
    auto alive = m_alive;
    m_transport.call(0, wire::encode_bucket(wire::op::bucket_delete, name),
        [this, alive, name, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            if (!ok || !wire::decode_status(reply, s))
            {
                ++m_c.peer_failures;
                s = st::io_error;
            }
            // Shard 0 told this shard to let go before it answered, and if that
            // was lost the bucket is let go of now, since it has moved.
            if (s == st::ok)
                m_store.drop_forget(name);
            cb(s);
        });
}

void shard_node::run_drop(std::string name, std::function<void(st)> cb)
{
    ++m_c.bucket_ops;
    if (const st s = m_store.drop_check(name); s != st::ok)
    {
        cb(s);
        return;
    }

    struct state
    {
        std::vector<uint32_t> prepared;
        st                    refusal{st::ok};
    };
    auto ds    = std::make_shared<state>();
    auto alive = m_alive;

    // Every shard that agreed is told the drop is off, and this one is reopened.
    auto abort_all = [this, alive, name, ds]()
    {
        m_store.drop_abort(name);
        for (const uint32_t j : ds->prepared)
            m_transport.call(j, wire::encode_bucket(wire::op::drop_abort, name), [](bool, std::string_view) {});
    };

    each_peer([name](uint32_t) { return wire::encode_bucket(wire::op::drop_prepare, name); },
              [ds](uint32_t peer, bool ok, std::string_view reply)
              {
                  st ps = st::io_error;
                  if (!ok || !wire::decode_status(reply, ps))
                      ps = st::io_error;
                  if (ps == st::ok)
                      ds->prepared.push_back(peer);
                  else if (ds->refusal == st::ok)
                      ds->refusal = ps;
              },
              [this, alive, name, cb, ds, abort_all]()
              {
                  if (!*alive)
                      return;
                  if (ds->refusal != st::ok)
                  {
                      abort_all();
                      cb(ds->refusal);
                      return;
                  }
                  m_store.drop_rename(name, [this, alive, name, cb, ds, abort_all](st r)
                  {
                      if (!*alive)
                          return;
                      if (r != st::ok)
                      {
                          // The store reopened this shard's own bucket.
                          for (const uint32_t j : ds->prepared)
                              m_transport.call(j, wire::encode_bucket(wire::op::drop_abort, name),
                                               [](bool, std::string_view) {});
                          cb(r);
                          return;
                      }
                      each_peer([name](uint32_t) { return wire::encode_bucket(wire::op::drop_forget, name); },
                                [](uint32_t, bool, std::string_view) {},
                                [cb]() { cb(st::ok); });
                  });
              });
}

// ─── Listing ────────────────────────────────────────────────────────────────

void shard_node::list(std::string_view bucket, const list_query& q, std::function<void(st, list_page)> cb)
{
    list_page mine;
    const st s = m_store.list(bucket, q, mine);
    if (s != st::ok || m_store.shards() <= 1 || q.max_keys == 0)
    {
        cb(s, std::move(mine));
        return;
    }

    ++m_c.list_fanouts;
    struct gather
    {
        std::vector<list_page> pages;
        st                     failed{st::ok};
    };
    auto g = std::make_shared<gather>();
    g->pages.push_back(std::move(mine));
    const size_t max_keys = q.max_keys;
    const std::string payload = wire::encode_list(bucket, q);

    each_peer([payload](uint32_t) { return payload; },
              [g](uint32_t, bool ok, std::string_view reply)
              {
                  st ps = st::io_error;
                  list_page p;
                  if (!ok || !wire::decode_page(reply, ps, p))
                      ps = st::io_error;
                  if (ps != st::ok)
                  {
                      if (g->failed == st::ok)
                          g->failed = ps;
                      return;
                  }
                  g->pages.push_back(std::move(p));
              },
              [g, max_keys, cb]()
              {
                  // A shard that could not answer would make the listing quietly
                  // short, so the whole request fails instead.
                  if (g->failed != st::ok)
                  {
                      cb(g->failed, {});
                      return;
                  }
                  cb(st::ok, wire::merge_pages(g->pages, max_keys));
              });
}

// ─── Answering a sibling ────────────────────────────────────────────────────

void shard_node::serve(std::string_view payload, std::function<void(bool, std::string)> reply)
{
    wire::op o{};
    if (!wire::request_op(payload, o))
    {
        reply(false, {});
        return;
    }

    switch (o)
    {
        case wire::op::commit:
        {
            commit_request req;
            if (!wire::decode_commit(payload, req))
            {
                reply(false, {});
                return;
            }
            ++m_c.commits_in;
            m_store.commit_local(std::move(req),
                [reply](put_result r) { reply(true, wire::encode_status(r.status)); });
            return;
        }
        case wire::op::remove:
        {
            std::string bucket, key;
            if (!wire::decode_remove(payload, bucket, key))
            {
                reply(false, {});
                return;
            }
            ++m_c.removes_in;
            m_store.remove_local(bucket, key,
                [reply](st s, bool existed) { reply(true, wire::encode_removed(s, existed)); });
            return;
        }
        case wire::op::list:
        {
            std::string bucket;
            list_query q;
            if (!wire::decode_list(payload, bucket, q))
            {
                reply(false, {});
                return;
            }
            list_page page;
            const st s = m_store.list(bucket, q, page);
            if (s == st::ok)
                wire::limit_page(page);
            ++m_c.list_pages_served;
            reply(true, wire::encode_page(s, page));
            return;
        }
        default:
            break;
    }

    std::string name;
    int64_t     ms = 0;
    if (!wire::decode_bucket(payload, name, ms))
    {
        reply(false, {});
        return;
    }
    switch (o)
    {
        case wire::op::bucket_create:
            if (m_store.shard() != 0)
            {
                reply(false, {});
                return;
            }
            run_create(std::move(name), [reply](st s, int64_t created) { reply(true, wire::encode_created(s, created)); });
            return;
        case wire::op::bucket_delete:
            if (m_store.shard() != 0)
            {
                reply(false, {});
                return;
            }
            run_drop(std::move(name), [reply](st s) { reply(true, wire::encode_status(s)); });
            return;
        case wire::op::bucket_adopt:
            m_store.adopt_bucket(std::move(name), ms, [reply](st s) { reply(true, wire::encode_status(s)); });
            return;
        case wire::op::drop_prepare:
            reply(true, wire::encode_status(m_store.drop_check(name)));
            return;
        case wire::op::drop_abort:
            m_store.drop_abort(name);
            reply(true, wire::encode_status(st::ok));
            return;
        case wire::op::drop_forget:
            m_store.drop_forget(name);
            reply(true, wire::encode_status(st::ok));
            return;
        default:
            break;
    }
    reply(false, {});
}

}   // namespace socketley::storage
