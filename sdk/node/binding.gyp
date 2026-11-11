{
  "variables": { "skl_lib": "<!(echo ${SOCKETLEY_LIB_DIR:-})" },
  "targets": [{
    "target_name": "socketley",
    "sources": ["src/addon.c"],
    "include_dirs": ["../include/linux"],
    "conditions": [
      ["skl_lib != ''", { "libraries": ["-L<(skl_lib)", "-lsocketley", "-Wl,-rpath,<(skl_lib)"] },
                        { "libraries": ["-lsocketley"] }]
    ]
  }]
}
