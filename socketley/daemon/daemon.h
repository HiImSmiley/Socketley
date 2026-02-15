#pragma once

class event_loop;
class runtime_manager;

int daemon_start(runtime_manager& manager, event_loop& loop);
