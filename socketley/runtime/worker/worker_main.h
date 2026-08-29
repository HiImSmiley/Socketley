#pragma once
// A runtime running as its own process, entered by the non-user-facing
// `socketley proxy-worker` or a custom worker binary, owning one
// runtime_instance and one event_loop and knowing nothing of the rest of the
// daemon but the frames on its control socket -- the type comes from the
// config frame, which is why this file is not under proxy/ any more.

// Runs the worker until the control socket closes or a shutdown frame arrives,
// returning 0 on a clean shutdown and 2 on a fatal setup failure.
int worker_main(int control_fd);
