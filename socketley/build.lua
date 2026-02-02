project("socketley")
	kind "ConsoleApp"
	
	links {
        "runtime_server",
        "runtime_client",
        "runtime_proxy",
        "runtime_cache"
    }