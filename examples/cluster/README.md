# Cluster examples

Cluster mode lets several **daemons** discover each other through a shared
directory. Each publishes its runtime state there every two seconds and scans
for peers, so a proxy's `@group` backend can resolve to a runtime living on
another daemon.

It is off by default: `socketley daemon --name <name> --cluster <dir>`. The name
is required first — a daemon with no identity has nothing to publish under.

| File | What it is |
|---|---|
| `docker-compose.yml` | Three daemons in three containers, sharing a volume. This is the real shape |
| `01-local-cluster.sh` | The same topology **simulated** on one machine |

## Why the local script is a simulation and not the real thing

Three daemons in one filesystem namespace need three socket paths, so every
command in `01-local-cluster.sh` carries its own `SOCKETLEY_SOCKET`. A real
cluster member is a container or a host: it has a namespace to itself, runs on
the default socket, and none of that plumbing exists.

The script says so at the top too. It is worth reading before you copy anything
out of it into something real — the socket juggling is an artefact of running
three daemons on one box, not a thing cluster mode requires.

## What discovery does and does not do

It resolves `@group` backends across daemons, and `socketley.cluster.*` answers
from the same view. It is **not** a consensus protocol: there is no leader, no
quorum, and a peer that stops publishing simply ages out. Two daemons that
cannot see the shared directory are two independent daemons, and neither will
say so.
