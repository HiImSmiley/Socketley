#pragma once
// How long a process that has been told to stop may take about it, owned by
// the worker, which bounds its own exit with alarm(2) because the daemon that
// would otherwise enforce it may be what died.  A step that is long and is
// progress -- a cache writing its dump -- widens the bound rather than being
// cut off by it; null outside a worker, where nothing bounds the exit.
namespace socketley
{
inline void (*widen_exit_bound)(unsigned seconds) = nullptr;

// Long enough for a dump of several gigabytes: 1.5 GB measured at 4.35 s from
// `stop` to exit, against the 5 s every other exit is given.
inline constexpr unsigned dump_exit_bound_sec = 300;
}
