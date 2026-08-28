#pragma once
// The proxy running as its own process, entered by the non-user-facing
// `socketley proxy-worker`, owning one proxy_instance and one event_loop and
// knowing nothing of the rest of the daemon but the endpoint table it is
// handed.

// Runs the worker until the control socket closes or a shutdown frame arrives,
// returning 0 on a clean shutdown and 2 on a fatal setup failure.
int proxy_worker_main(int control_fd);
