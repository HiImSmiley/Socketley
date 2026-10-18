#include "../../shared/util/byte_codec.h"
#include "shard_node.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <vector>

#include <unistd.h>

#include "s3_names.h"
#include "shard_owner.h"
#include "shard_wire.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/settings.h"

namespace socketley::storage
{

shard_node::shard_node(object_store& store, shard_transport& transport)
    : m_store(store), m_transport(transport), m_alive(std::make_shared<bool>(true))
{
    m_store.set_peers(this);
    if (const char* e = settings::text("SOCKETLEY_STORAGE_DOC_FAULT"))
        m_doc_fault = e;
    // Begun past any number an earlier run of shard 0 handed out, so a late word from it is never taken for a new change.
    m_doc_seq = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::system_clock::now().time_since_epoch()).count());
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
                           std::function<void()> done, uint64_t mask)
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
        if (j != m_store.shard() && (mask >> j & 1u))
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
        put_result r;
        if (!ok || !wire::decode_committed(reply, r))
        {
            ++m_c.peer_failures;
            r = put_result{st::io_error, {}};
        }
        cb(std::move(r));
    });
}

void shard_node::remove(uint32_t owner, std::string bucket, std::string key, std::string version_id, bool bypass,
                        change_origin who, std::function<void(remove_result)> cb, delete_condition cond)
{
    ++m_c.removes_out;
    auto alive = m_alive;
    m_transport.call(owner, wire::encode_remove(bucket, key, version_id, bypass, who, cond),
                     [this, alive, cb](bool ok, std::string_view reply)
    {
        if (!*alive)
            return;
        remove_result r;
        if (!ok || !wire::decode_removed(reply, r))
        {
            ++m_c.peer_failures;
            r = remove_result{st::io_error};
        }
        cb(std::move(r));
    });
}

void shard_node::change_header(uint32_t owner, std::string bucket, std::string key, std::string version_id,
                               header_change change, std::function<void(st, std::string)> cb)
{
    ++m_c.tags_out;
    auto alive = m_alive;
    m_transport.call(owner, wire::encode_set_tags(bucket, key, version_id, change.value,
                                                  static_cast<uint8_t>(change.what), change.bypass, change.who),
                     [this, alive, cb](bool ok, std::string_view reply)
    {
        if (!*alive)
            return;
        st s = st::io_error;
        std::string id;
        if (!ok || !wire::decode_tagged(reply, s, id))
        {
            ++m_c.peer_failures;
            s = st::io_error;
        }
        cb(s, std::move(id));
    });
}

void shard_node::invalidate(std::string bucket, std::string key, std::function<void()> done)
{
    if (m_store.shards() <= 1)
    {
        done();
        return;
    }
    // Until every sibling has answered this shard's start, one may hold a copy it never asked about.
    const uint64_t held = m_holders_known ? m_holders[object_slot(bucket, key)] : ~uint64_t{0};
    const uint64_t mask = held & ~(m_store.shard() < 64 ? uint64_t{1} << m_store.shard() : uint64_t{0}) &
                          (m_store.shards() >= 64 ? ~uint64_t{0} : (uint64_t{1} << m_store.shards()) - 1);
    if (mask == 0)
    {
        done();
        return;
    }
    m_c.hot_drops_out += static_cast<uint64_t>(std::popcount(mask));
    // A sibling that is gone holds nothing when it comes back, so it is not waited for.
    const std::string payload = wire::encode_hot_drop(bucket, key);
    each_peer([payload](uint32_t) { return payload; }, [](uint32_t, bool, std::string_view) {}, std::move(done), mask);
}

void shard_node::hold(uint32_t owner, std::string bucket, std::string key, const object_meta& read,
                      std::function<void(bool)> cb)
{
    ++m_c.hot_holds_out;
    if (m_hold_q.size() < m_store.shards())
    {
        m_hold_q.resize(m_store.shards());
        m_hold_cb.resize(m_store.shards());
    }
    m_hold_q[owner].push_back({std::move(bucket), std::move(key), read});
    m_hold_cb[owner].push_back(std::move(cb));
}

void shard_node::flush_holds()
{
    for (uint32_t owner = 0; owner < m_hold_q.size(); ++owner)
    {
        auto& q = m_hold_q[owner];
        if (q.empty())
            continue;
        auto alive = m_alive;
        for (size_t at = 0; at < q.size(); at += wire::max_holds)
        {
            const size_t n = std::min(wire::max_holds, q.size() - at);
            auto cbs = std::make_shared<std::vector<std::function<void(bool)>>>(
                std::make_move_iterator(m_hold_cb[owner].begin() + static_cast<ptrdiff_t>(at)),
                std::make_move_iterator(m_hold_cb[owner].begin() + static_cast<ptrdiff_t>(at + n)));
            m_transport.call(owner, wire::encode_hot_hold(m_store.shard(), q.data() + at, n),
                [this, alive, cbs](bool ok, std::string_view reply)
                {
                    if (!*alive)
                        return;
                    std::vector<uint8_t> held;
                    if (!ok || !wire::decode_held(reply, held) || held.size() != cbs->size())
                    {
                        ++m_c.peer_failures;
                        held.assign(cbs->size(), 0);
                    }
                    for (size_t i = 0; i < cbs->size(); ++i)
                        (*cbs)[i](held[i] != 0);
                });
        }
        q.clear();
        m_hold_cb[owner].clear();
    }
}

void shard_node::announce_start(std::function<void(bool)> done)
{
    auto all   = std::make_shared<bool>(true);
    auto alive = m_alive;
    each_peer([this](uint32_t) { return wire::encode_hot_owner_started(m_store.shard()); },
              [all](uint32_t, bool ok, std::string_view) { *all = *all && ok; },
              [this, alive, all, done = std::move(done)]()
              {
                  if (*alive && *all)
                      trust_holders();
                  done(*all);
              });
}

// ─── Buckets ────────────────────────────────────────────────────────────────

std::function<void(st)> shard_node::told(bool quiet, char kind, const std::string& bucket, const std::string& owner,
                                         uint8_t doc, const std::string& xml, std::function<void(st)> cb)
{
    if (quiet || !m_bucket_listener)
        return cb;
    return [this, alive = m_alive, kind, bucket, owner, doc, xml, cb = std::move(cb)](st s)
    {
        if (!*alive || s != st::ok)
        {
            cb(s);
            return;
        }
        m_bucket_listener(kind, bucket, owner, doc, xml, [cb]() { cb(st::ok); });
    };
}

void shard_node::create_bucket(std::string name, std::string owner, std::function<void(st)> cb, bool quiet)
{
    cb = told(quiet, 'c', name, owner, 0, {}, std::move(cb));
    if (m_store.shard() == 0)
    {
        run_create(std::move(name), std::move(owner), [cb](st s, int64_t) { cb(s); });
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
    m_transport.call(0, wire::encode_bucket(wire::op::bucket_create, name, 0, owner),
        [this, alive, name, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            int64_t ms = 0;
            std::string made_for;
            if (!ok || !wire::decode_created(reply, s, ms, &made_for))
            {
                ++m_c.peer_failures;
                cb(st::io_error);
                return;
            }
            // Shard 0 told this shard of the bucket before it answered, and if
            // that notice was lost the answer carries what is needed to take it up.
            if ((s == st::ok || s == st::bucket_exists) && !m_store.has_bucket(name))
            {
                m_store.adopt_bucket(name, ms, std::move(made_for), [cb, s](st a) { cb(a == st::ok ? s : a); });
                return;
            }
            cb(s);
        });
}

void shard_node::run_create(std::string name, std::string owner, std::function<void(st, int64_t)> cb)
{
    ++m_c.bucket_ops;
    auto alive = m_alive;
    m_store.create_bucket(name, std::move(owner), [this, alive, name, cb](st s)
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
        // The owner it has, which for a bucket that was there already is not the one this request asked for.
        const std::string owner(m_store.bucket_owner(name));
        each_peer([name, ms, owner](uint32_t) { return wire::encode_bucket(wire::op::bucket_adopt, name, ms, owner); },
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

void shard_node::delete_bucket(std::string name, std::function<void(st)> cb, bool quiet)
{
    cb = told(quiet, 'r', name, {}, 0, {}, std::move(cb));
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
    // Judged once the bucket's removing uploads are forgotten and no answered change holds a lane for its events.
    auto alive   = m_alive;
    auto settled = [this, alive, name, cb]()
    {
        if (!*alive)
            return;
        m_store.after_settled(name, [this, alive, name, cb]()
        {
            if (*alive)
                run_drop_settled(name, cb);
        });
    };
    if (m_mpu)
    {
        m_mpu->after_removals(name, settled);
        return;
    }
    settled();
}

void shard_node::run_drop_settled(std::string name, std::function<void(st)> cb)
{
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

// ─── Configuration documents ────────────────────────────────────────────────

namespace
{

std::string doc_label(bucket_doc kind)
{
    switch (kind)
    {
        case bucket_doc::cors:      return "CORS configuration";
        case bucket_doc::lifecycle: return "lifecycle configuration";
        case bucket_doc::policy:    return "policy";
        case bucket_doc::versioning: return "versioning configuration";
        case bucket_doc::encryption: return "encryption configuration";
        case bucket_doc::tagging:    return "tag set";
        case bucket_doc::object_lock: return "object lock configuration";
        case bucket_doc::notification: return "notification configuration";
        case bucket_doc::replication: return "replication configuration";
        case bucket_doc::quota:       return "quota";
        case bucket_doc::website:     return "website configuration";
        case bucket_doc::public_access: return "public access block";
        case bucket_doc::logging:     return "logging configuration";
        case bucket_doc::ownership:   return "ownership controls";
        case bucket_doc::acl:         return "access control list";
    }
    return "configuration";
}

}   // namespace

void shard_node::set_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb, bool quiet)
{
    cb = told(quiet, 'd', name, {}, static_cast<uint8_t>(kind), xml, std::move(cb));
    if (m_store.shard() == 0)
    {
        run_doc(kind, std::move(name), std::move(xml), std::move(cb));
        return;
    }
    if (!m_store.has_bucket(name))
    {
        cb(st::no_such_bucket);
        return;
    }
    ++m_c.bucket_ops;
    // This shard takes the change up when shard 0 tells it, which is before shard 0 answers.
    auto alive = m_alive;
    m_transport.call(0, wire::encode_doc(wire::op::doc_put, kind, name, xml),
        [this, alive, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            if (!ok || !wire::decode_status(reply, s))
            {
                ++m_c.peer_failures;
                s = st::io_error;
            }
            cb(s);
        });
}

void shard_node::run_doc(bucket_doc kind, std::string name, std::string xml, std::function<void(st)> cb)
{
    ++m_c.bucket_ops;
    auto alive = m_alive;
    auto run = [this, alive, kind, name, xml = std::move(xml), cb = std::move(cb)]()
    {
        // Judged here, in the order shard 0 makes the bucket's changes, so two that conflict cannot both pass.
        if (const st c = m_store.doc_conflict(kind, name, xml); c != st::ok)
        {
            cb(c);
            doc_next(name);
            return;
        }
        // The change is a file beside the document until every shard has promised to serve nothing of the bucket
        // without first learning how it ended, so no shard that missed the outcome can go on with the old one.
        m_store.stage_doc(kind, name, xml, [this, alive, kind, name, xml, cb](st s)
        {
            if (!*alive)
                return;
            if (s != st::ok)
            {
                cb(s);
                doc_next(name);
                return;
            }
            const uint64_t seq = ++m_doc_seq;
            auto all = std::make_shared<bool>(true);
            each_peer([kind, name, seq](uint32_t) { return wire::encode_doc(wire::op::doc_prepare, kind, name, {}, seq); },
                      [all](uint32_t, bool ok, std::string_view reply)
                      {
                          st a = st::io_error;
                          *all = *all && ok && wire::decode_status(reply, a) && a == st::ok;
                      },
                      [this, alive, kind, name, xml, cb, seq, all]()
                      {
                          if (!*alive)
                              return;
                          if (!*all)
                          {
                              LOG_WARN(("storage: a shard could not be reached, so the " + doc_label(kind) + " of " +
                                        name + " is left as it was").c_str());
                              abandon_doc(kind, name, seq, [cb]() { cb(st::unavailable); });
                              return;
                          }
                          m_store.commit_doc(kind, name, xml, [this, alive, kind, name, xml, cb, seq](bool visible, st c)
                          {
                              if (!*alive)
                                  return;
                              if (!visible)
                              {
                                  tell_abandoned(kind, name, seq);
                                  cb(c);
                                  doc_next(name);
                                  return;
                              }
                              // A shard this misses is still waiting, and settles from the file before it serves the bucket.
                              each_peer([kind, name, xml, seq](uint32_t)
                                        { return wire::encode_doc(wire::op::doc_adopt, kind, name, xml, seq); },
                                        [kind, name](uint32_t peer, bool ok, std::string_view)
                                        {
                                            if (!ok)
                                                LOG_WARN(("storage: shard " + std::to_string(peer) + " was not told the " +
                                                          doc_label(kind) + " of " + name +
                                                          "; it reads it from the file before it serves the bucket")
                                                             .c_str());
                                        },
                                        [this, alive, name, cb, c]()
                                        {
                                            if (!*alive)
                                                return;
                                            cb(c);
                                            doc_next(name);
                                        });
                          });
                      });
        });
    };
    auto [it, fresh] = m_doc_lanes.try_emplace(name);
    if (fresh)
        run();
    else
        it->second.push_back(std::move(run));
}

void shard_node::abandon_doc(bucket_doc kind, std::string name, uint64_t seq, std::function<void()> then)
{
    auto alive = m_alive;
    m_store.abandon_doc(kind, name, [this, alive, kind, name, seq, then]()
    {
        if (!*alive)
            return;
        tell_abandoned(kind, name, seq);
        then();
        doc_next(name);
    });
}

void shard_node::tell_abandoned(bucket_doc kind, const std::string& name, uint64_t seq)
{
    // Not waited for: a shard this misses settles from the file, which no longer has the change.
    const std::string payload = wire::encode_doc(wire::op::doc_abort, kind, name, {}, seq);
    for (uint32_t j = 0; j < m_store.shards(); ++j)
        if (j != m_store.shard())
            m_transport.call(j, payload, [](bool, std::string_view) {});
}

bool shard_node::doc_fault(std::string_view phase) const
{
    return !m_doc_fault.empty() &&
           ::access((m_doc_fault + "/" + std::to_string(m_store.shard()) + "." + std::string(phase)).c_str(), F_OK) == 0;
}

void shard_node::doc_next(const std::string& name)
{
    auto it = m_doc_lanes.find(name);
    if (it == m_doc_lanes.end())
        return;
    if (it->second.empty())
    {
        m_doc_lanes.erase(it);
        return;
    }
    auto run = std::move(it->second.front());
    it->second.pop_front();
    run();
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
                  cb(st::ok, wire::merge_pages(std::move(g->pages), max_keys));
              });
}

void shard_node::list_versions(std::string_view bucket, const version_query& q,
                               std::function<void(st, version_page)> cb)
{
    version_page mine;
    const st s = m_store.list_versions(bucket, q, mine);
    if (s != st::ok || m_store.shards() <= 1 || q.max_keys == 0)
    {
        cb(s, std::move(mine));
        return;
    }
    ++m_c.list_fanouts;
    struct gather
    {
        std::vector<version_page> pages;
        st                        failed{st::ok};
    };
    auto g = std::make_shared<gather>();
    g->pages.push_back(std::move(mine));
    const size_t max_keys = q.max_keys;
    const std::string payload = wire::encode_list_versions(bucket, q);
    each_peer([payload](uint32_t) { return payload; },
              [g](uint32_t, bool ok, std::string_view reply)
              {
                  st ps = st::io_error;
                  version_page p;
                  if (!ok || !wire::decode_version_page(reply, ps, p))
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
                  // A shard that could not answer would make the listing quietly short.
                  if (g->failed != st::ok)
                  {
                      cb(g->failed, {});
                      return;
                  }
                  cb(st::ok, wire::merge_version_pages(std::move(g->pages), max_keys));
              });
}

// ─── Multipart ──────────────────────────────────────────────────────────────

const mpu_upload* shard_node::mpu_find(const std::string& bucket, const std::string& key,
                                       const std::string& id) const
{
    if (!m_mpu)
        return nullptr;
    const mpu_upload* up = m_mpu->find(bucket, id);
    return (!up || up->key != key || up->state == mpu_state::removing) ? nullptr : up;
}

void shard_node::mpu_create(std::string bucket, std::string key, object_meta meta, checksum_algo algo,
                            std::function<void(st, std::string)> cb)
{
    if (!m_mpu)
    {
        cb(st::io_error, {});
        return;
    }
    if (m_store.owns(bucket, key))
    {
        m_mpu->create(std::move(bucket), std::move(key), std::move(meta), algo, std::move(cb));
        return;
    }
    ++m_c.mpu_out;
    auto alive = m_alive;
    const uint32_t owner = m_store.owner_of(bucket, key);
    m_transport.call(owner, wire::encode_mpu_create(bucket, key, meta, algo),
        [this, alive, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            std::string id;
            if (!ok || !wire::decode_mpu_created(reply, s, id))
            {
                ++m_c.peer_failures;
                cb(st::io_error, {});
                return;
            }
            cb(s, std::move(id));
        });
}

void shard_node::mpu_begin(std::string bucket, std::string key, std::string id, uint32_t number, uint64_t expected,
                           bool known, std::function<void(st, checksum_algo, part_place)> cb)
{
    if (!m_mpu)
    {
        cb(st::io_error, checksum_algo::none, {});
        return;
    }
    if (m_store.owns(bucket, key))
    {
        checksum_algo algo = checksum_algo::none;
        part_place place;
        const st s = mpu_find(bucket, key, id) ? m_mpu->begin_part(bucket, id, number, expected, known, algo, place)
                                               : st::no_such_key;
        cb(s, algo, std::move(place));
        return;
    }
    ++m_c.mpu_out;
    auto alive = m_alive;
    wire::mpu_ref ref{bucket, key, id, number, 0, known, expected};
    m_transport.call(m_store.owner_of(bucket, key), wire::encode_mpu_ref(wire::op::mpu_begin, ref),
        [this, alive, bucket, id, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            checksum_algo algo = checksum_algo::none;
            part_place place;
            if (!ok || !wire::decode_mpu_begin(reply, s, algo, place))
            {
                ++m_c.peer_failures;
                cb(st::io_error, checksum_algo::none, {});
                return;
            }
            if (place.off)
                place.path = m_mpu->data_path(bucket, id);
            cb(s, algo, std::move(place));
        });
}

put_op::committer shard_node::mpu_part_committer(std::string bucket, std::string key, std::string id,
                                                 uint32_t number)
{
    if (!m_mpu)
        return {};
    if (m_store.owns(bucket, key))
        return m_mpu->part_committer(std::move(bucket), std::move(id), number);

    // The finished body is a file in the shared tmp directory, so the owner is sent
    // its name and what it says about it and renames it into the upload.
    const uint32_t owner = m_store.owner_of(bucket, key);
    return [this, alive = m_alive, owner, id = std::move(id), number](commit_request req,
                                                                     std::function<void(put_result)> done)
    {
        if (!*alive)
            return;
        ++m_c.mpu_out;
        const std::string bucket_name = req.bucket;
        const std::string tmp         = req.tmp_name;
        const object_meta meta        = req.meta;
        m_transport.call(owner, wire::encode_mpu_part(req, id, number),
            [this, alive, bucket_name, tmp, meta, done](bool ok, std::string_view reply)
            {
                if (!*alive)
                    return;
                st s = st::io_error;
                if (!ok || !wire::decode_status(reply, s))
                {
                    ++m_c.peer_failures;
                    s = st::io_error;
                }
                // A body that did not become a part is nobody's, and a name the
                // owner already renamed is not there to remove.
                if (s != st::ok)
                    m_store.remove_tmp(bucket_name, tmp);
                done({s, meta});
            });
    };
}

void shard_node::mpu_complete(std::string bucket, std::string key, std::string id,
                              std::vector<complete_part> parts, std::function<void()> progress,
                              std::function<void(complete_result)> cb, complete_binder bind, put_condition cond,
                              change_origin who)
{
    if (!m_mpu)
    {
        complete_result r;
        r.error = make_error("InternalError");
        cb(std::move(r));
        return;
    }
    if (m_store.owns(bucket, key))
    {
        if (!mpu_find(bucket, key, id))
        {
            complete_result r;
            r.error = make_error("NoSuchUpload");
            cb(std::move(r));
            return;
        }
        m_mpu->complete(std::move(bucket), std::move(id), std::move(parts), std::move(progress), std::move(cb),
                        std::move(bind), std::move(cond), std::move(who));
        return;
    }

    // The owner validates the list and seals the upload; this shard reads the parts,
    // writes the object and has it committed through the owner of the key, which is
    // the owner of the upload too, and the owner is then told how it ended.  Nothing
    // long is asked of the owner over the link.
    ++m_c.mpu_out;
    auto alive = m_alive;
    const uint32_t owner = m_store.owner_of(bucket, key);
    wire::mpu_ref ref{bucket, key, id, 0, 0, false};
    m_transport.call(owner, wire::encode_mpu_prepare(ref, parts),
        [this, alive, owner, bucket, key, id, progress = std::move(progress), cb,
         bind = std::move(bind), cond = std::move(cond), who = std::move(who)](bool ok, std::string_view reply) mutable
        {
            if (!*alive)
                return;
            s3_error err;
            assemble_plan plan;
            if (!ok || !wire::decode_mpu_plan(reply, err, plan))
            {
                ++m_c.peer_failures;
                complete_result r;
                r.error = make_error("InternalError");
                cb(std::move(r));
                return;
            }
            if (!err.code.empty())
            {
                complete_result r;
                r.error = std::move(err);
                cb(std::move(r));
                return;
            }
            m_mpu->assemble_plan_object(std::move(plan), std::move(progress),
                [this, alive, owner, bucket, key, id, cb](complete_result res)
                {
                    if (!*alive)
                        return;
                    wire::mpu_ref fin{bucket, key, id, 0, 0, res.error.code.empty()};
                    ++m_c.mpu_out;
                    // The client hears once the owner has, so no request it sends next finds the upload sealed.
                    m_transport.call(owner, wire::encode_mpu_ref(wire::op::mpu_finish, fin),
                                     [this, alive, cb, res = std::move(res)](bool fok, std::string_view) mutable
                                     {
                                         if (!*alive)
                                             return;
                                         if (!fok)
                                             ++m_c.peer_failures;
                                         cb(std::move(res));
                                     });
                }, std::move(bind), std::move(cond), std::move(who));
        });
}

void shard_node::mpu_abort(std::string bucket, std::string key, std::string id, std::function<void(bool)> cb)
{
    if (!m_mpu)
    {
        cb(false);
        return;
    }
    if (m_store.owns(bucket, key))
    {
        if (!mpu_find(bucket, key, id) || !m_mpu->abort(bucket, id, [cb]() { cb(true); }))
            cb(false);
        return;
    }
    ++m_c.mpu_out;
    auto alive = m_alive;
    wire::mpu_ref ref{bucket, key, id, 0, 0, false};
    m_transport.call(m_store.owner_of(bucket, key), wire::encode_mpu_ref(wire::op::mpu_abort, ref),
        [this, alive, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            st s = st::io_error;
            if (!ok || !wire::decode_status(reply, s))
                ++m_c.peer_failures;
            cb(ok && s == st::ok);
        });
}

void shard_node::mpu_parts(std::string bucket, std::string key, std::string id, uint32_t marker,
                           uint32_t max_parts, std::function<void(parts_page)> cb)
{
    if (!m_mpu)
    {
        parts_page pg;
        pg.status = st::io_error;
        cb(std::move(pg));
        return;
    }
    if (m_store.owns(bucket, key))
    {
        cb(m_mpu->list_parts(bucket, id, key, marker, max_parts));
        return;
    }
    ++m_c.mpu_out;
    auto alive = m_alive;
    wire::mpu_ref ref{bucket, key, id, marker, max_parts, false};
    m_transport.call(m_store.owner_of(bucket, key), wire::encode_mpu_ref(wire::op::mpu_parts, ref),
        [this, alive, cb](bool ok, std::string_view reply)
        {
            if (!*alive)
                return;
            parts_page pg;
            if (!ok || !wire::decode_parts_page(reply, pg))
            {
                ++m_c.peer_failures;
                pg = parts_page{};
                pg.status = st::io_error;
            }
            cb(std::move(pg));
        });
}

void shard_node::mpu_list(std::string bucket, std::function<void(st, std::vector<wire::upload_stub>)> cb)
{
    struct gather
    {
        std::vector<wire::upload_stub> all;
        st failed{st::ok};
    };
    auto g = std::make_shared<gather>();
    if (m_mpu)
        for (const mpu_upload* u : m_mpu->uploads_of(bucket))
            g->all.push_back({u->key, u->id, u->initiated_ms, std::string(storage_class_of(u->meta))});
    m_c.mpu_out += m_store.shards() - 1;
    each_peer([bucket](uint32_t) { return wire::encode_bucket(wire::op::mpu_list, bucket); },
              [g](uint32_t, bool ok, std::string_view reply)
              {
                  st ps = st::io_error;
                  std::vector<wire::upload_stub> part;
                  bytes::reader r(reply);
                  uint8_t b = 0;
                  if (ok && r.u8(b) && b == static_cast<uint8_t>(st::ok) &&
                      wire::decode_upload_list(reply.substr(1), part))
                      ps = st::ok;
                  if (ps != st::ok)
                  {
                      if (g->failed == st::ok)
                          g->failed = ps;
                      return;
                  }
                  for (auto& u : part)
                      g->all.push_back(std::move(u));
              },
              [g, cb]()
              {
                  // A shard that could not answer would make the listing quietly short.
                  cb(g->failed, g->failed == st::ok ? std::move(g->all) : std::vector<wire::upload_stub>{});
              });
}

// ─── Answering a sibling ────────────────────────────────────────────────────

void shard_node::serve_mpu(wire::op o, std::string_view payload, std::function<void(bool, std::string)> reply)
{
    if (!m_mpu)
    {
        reply(false, {});
        return;
    }
    ++m_c.mpu_in;
    switch (o)
    {
        case wire::op::mpu_create:
        {
            std::string bucket, key;
            object_meta meta;
            checksum_algo algo = checksum_algo::none;
            if (!wire::decode_mpu_create(payload, bucket, key, meta, algo) || !m_store.owns(bucket, key))
            {
                reply(false, {});
                return;
            }
            m_mpu->create(std::move(bucket), std::move(key), std::move(meta), algo,
                          [reply](st s, std::string id) { reply(true, wire::encode_mpu_created(s, id)); });
            return;
        }
        case wire::op::mpu_begin:
        {
            wire::mpu_ref r;
            if (!wire::decode_mpu_ref(payload, o, r))
            {
                reply(false, {});
                return;
            }
            checksum_algo algo = checksum_algo::none;
            part_place place;
            const st s = mpu_find(r.bucket, r.key, r.id)
                             ? m_mpu->begin_part(r.bucket, r.id, r.a, r.size, r.flag, algo, place)
                             : st::no_such_key;
            reply(true, wire::encode_mpu_begin(s, algo, place));
            return;
        }
        case wire::op::mpu_part:
        {
            commit_request req;
            std::string id;
            uint32_t number = 0;
            if (!wire::decode_mpu_part(payload, req, id, number))
            {
                reply(false, {});
                return;
            }
            auto commit = m_mpu->part_committer(req.bucket, id, number);
            commit(std::move(req), [reply](put_result r) { reply(true, wire::encode_status(r.status)); });
            return;
        }
        case wire::op::mpu_prepare:
        {
            wire::mpu_ref r;
            std::vector<complete_part> parts;
            if (!wire::decode_mpu_prepare(payload, r, parts))
            {
                reply(false, {});
                return;
            }
            if (!mpu_find(r.bucket, r.key, r.id))
            {
                reply(true, wire::encode_mpu_plan(make_error("NoSuchUpload"), {}));
                return;
            }
            m_mpu->prepare_complete(r.bucket, r.id, std::move(parts),
                [reply](s3_error err, assemble_plan plan) { reply(true, wire::encode_mpu_plan(err, plan)); },
                true);
            return;
        }
        case wire::op::mpu_finish:
        {
            wire::mpu_ref r;
            if (!wire::decode_mpu_ref(payload, o, r))
            {
                reply(false, {});
                return;
            }
            m_mpu->finish_complete(r.bucket, r.id, r.flag);
            reply(true, wire::encode_status(st::ok));
            return;
        }
        case wire::op::mpu_abort:
        {
            wire::mpu_ref r;
            if (!wire::decode_mpu_ref(payload, o, r))
            {
                reply(false, {});
                return;
            }
            if (!mpu_find(r.bucket, r.key, r.id) || !m_mpu->abort(r.bucket, r.id, [reply]() { reply(true, wire::encode_status(st::ok)); }))
                reply(true, wire::encode_status(st::no_such_key));
            return;
        }
        case wire::op::mpu_parts:
        {
            wire::mpu_ref r;
            if (!wire::decode_mpu_ref(payload, o, r))
            {
                reply(false, {});
                return;
            }
            reply(true, wire::encode_parts_page(m_mpu->list_parts(r.bucket, r.id, r.key, r.a, r.b)));
            return;
        }
        case wire::op::mpu_list:
        {
            std::string bucket;
            int64_t ms = 0;
            if (!wire::decode_bucket(payload, bucket, ms))
            {
                reply(false, {});
                return;
            }
            std::vector<wire::upload_stub> all;
            for (const mpu_upload* u : m_mpu->uploads_of(bucket))
                all.push_back({u->key, u->id, u->initiated_ms, std::string(storage_class_of(u->meta))});
            reply(true, wire::encode_status(st::ok) + wire::encode_upload_list(all));
            return;
        }
        default:
            break;
    }
    reply(false, {});
}

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
                [reply](put_result r) { reply(true, wire::encode_committed(r)); });
            return;
        }
        case wire::op::remove:
        {
            std::string bucket, key, version_id;
            bool bypass = false;
            change_origin who;
            delete_condition cond;
            if (!wire::decode_remove(payload, bucket, key, &version_id, &bypass, &who, &cond))
            {
                reply(false, {});
                return;
            }
            ++m_c.removes_in;
            m_store.remove_version_local(bucket, key, std::move(version_id),
                [reply](remove_result r) { reply(true, wire::encode_removed(r)); }, {}, bypass,
                change_cause::remove, std::move(who), std::move(cond));
            return;
        }
        case wire::op::set_tags:
        {
            std::string bucket, key, version_id;
            header_change change;
            uint8_t what = 0;
            if (!wire::decode_set_tags(payload, bucket, key, version_id, change.value, &what, &change.bypass,
                                       &change.who) ||
                what > static_cast<uint8_t>(header_change::kind::acl))
            {
                reply(false, {});
                return;
            }
            change.what = static_cast<header_change::kind>(what);
            ++m_c.tags_in;
            m_store.change_header_local(bucket, key, std::move(version_id), std::move(change),
                                        [reply](st s, std::string id) { reply(true, wire::encode_tagged(s, id)); });
            return;
        }
        case wire::op::list_versions:
        {
            std::string bucket;
            version_query q;
            if (!wire::decode_list_versions(payload, bucket, q))
            {
                reply(false, {});
                return;
            }
            version_page page;
            const st s = m_store.list_versions(bucket, q, page);
            ++m_c.list_pages_served;
            reply(true, wire::encode_version_page(s, page));
            return;
        }
        case wire::op::hot_drop:
        {
            std::string bucket, key;
            if (!wire::decode_hot_drop(payload, bucket, key))
            {
                reply(false, {});
                return;
            }
            ++m_c.hot_drops_in;
            m_store.hot_invalidate(bucket, key);
            reply(true, wire::encode_status(st::ok));
            return;
        }
        case wire::op::hot_hold:
        {
            uint32_t from = 0;
            std::vector<wire::hold_entry> asked;
            if (!wire::decode_hot_hold(payload, from, asked) || from >= m_store.shards() || from == m_store.shard())
            {
                reply(false, {});
                return;
            }
            m_c.hot_holds_in += asked.size();
            std::vector<uint8_t> held(asked.size(), 0);
            for (size_t i = 0; i < asked.size(); ++i)
            {
                const wire::hold_entry& e = asked[i];
                // Only the version the index names may be kept, and the change that replaces it will drop it.
                const object_meta* cur = m_store.owns(e.bucket, e.key) ? m_store.find(e.bucket, e.key) : nullptr;
                if (!cur || !(*cur == e.meta))
                    continue;
                // A sibling past the 64 a mask can name is counted as any of them, which tells all and misses none.
                m_holders[object_slot(e.bucket, e.key)] |= from < 64 ? uint64_t{1} << from : ~uint64_t{0};
                held[i] = 1;
            }
            reply(true, wire::encode_held(held));
            return;
        }
        case wire::op::hot_owner_started:
        {
            uint32_t shard = 0;
            if (!wire::decode_hot_owner_started(payload, shard))
            {
                reply(false, {});
                return;
            }
            m_store.hot_forget_owner(shard);
            reply(true, wire::encode_status(st::ok));
            return;
        }
        case wire::op::doc_put:
        case wire::op::doc_prepare:
        case wire::op::doc_adopt:
        case wire::op::doc_abort:
        {
            bucket_doc kind{};
            std::string bucket, xml;
            uint64_t seq = 0;
            if (!wire::decode_doc(payload, o, kind, bucket, xml, seq) || (o == wire::op::doc_put) != (m_store.shard() == 0))
            {
                reply(false, {});
                return;
            }
            if (o == wire::op::doc_put)
            {
                run_doc(kind, std::move(bucket), std::move(xml), [reply](st s) { reply(true, wire::encode_status(s)); });
                return;
            }
            // A test hook: a message of this phase is lost on its way to this shard while the hook's file exists.
            if (doc_fault(o == wire::op::doc_prepare ? "prepare" : o == wire::op::doc_adopt ? "commit" : "abort"))
            {
                reply(false, {});
                return;
            }
            if (o == wire::op::doc_prepare)
                reply(true, wire::encode_status(m_store.doubt_doc(kind, bucket, seq)));
            else
            {
                m_store.decided_doc(kind, bucket, seq, o == wire::op::doc_adopt ? &xml : nullptr);
                reply(true, wire::encode_status(st::ok));
            }
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
            wire::page_writer page;
            const st s = m_store.list_walk(bucket, q, page);
            ++m_c.list_pages_served;
            reply(true, page.finish(s));
            return;
        }
        default:
            break;
    }

    if (o >= wire::op::mpu_create)
    {
        serve_mpu(o, payload, std::move(reply));
        return;
    }

    std::string name;
    int64_t     ms = 0;
    std::string owner;
    if (!wire::decode_bucket(payload, name, ms, &owner))
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
        {
            // The reply's copy is taken before the call, whose arguments C++ may build in either order.
            auto answer = [this, name, reply](st s, int64_t created)
            { reply(true, wire::encode_created(s, created, m_store.bucket_owner(name))); };
            run_create(std::move(name), std::move(owner), std::move(answer));
            return;
        }
        case wire::op::bucket_delete:
            if (m_store.shard() != 0)
            {
                reply(false, {});
                return;
            }
            run_drop(std::move(name), [reply](st s) { reply(true, wire::encode_status(s)); });
            return;
        case wire::op::bucket_adopt:
            m_store.adopt_bucket(std::move(name), ms, std::move(owner), [reply](st s) { reply(true, wire::encode_status(s)); });
            return;
        case wire::op::drop_prepare:
        {
            auto judge = [this, name, reply]()
            {
                m_store.after_settled(name, [this, name, reply]()
                                      { reply(true, wire::encode_status(m_store.drop_check(name))); });
            };
            if (!m_mpu)
            {
                judge();
                return;
            }
            auto alive = m_alive;
            m_mpu->after_removals(name, [alive, judge]()
            {
                if (*alive)
                    judge();
            });
            return;
        }
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
