#pragma once
// The proxy running as its own process.
//
// Entered by `socketley proxy-worker`, which is not a user-facing command: the
// daemon forks and execs itself with it, having already put the control socket
// on a known descriptor.  Running it by hand does nothing useful, which is why
// it is not in the help text.
//
// What it does is small on purpose.  It owns one proxy_instance and one
// event_loop, and it does what the control socket tells it: take a config,
// take an endpoint table, start, stop, and report what it is doing.  It has no
// runtime_manager, no state directory and no view of any other runtime — the
// whole of what it knows about the rest of the daemon is the host-and-port
// table it is handed.

// Runs the worker until the control socket closes or a shutdown frame arrives.
// `control_fd` is the socket the daemon kept the other end of.  Returns a
// process exit code: 0 on a clean shutdown, 2 on a fatal setup failure.
int proxy_worker_main(int control_fd);
