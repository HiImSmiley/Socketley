// Finds libsocketley.so: SOCKETLEY_LIB_DIR for a build from a checkout, the system's library path otherwise.
fn main() {
    println!("cargo:rerun-if-env-changed=SOCKETLEY_LIB_DIR");
    if let Ok(dir) = std::env::var("SOCKETLEY_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    }
    println!("cargo:rustc-link-lib=dylib=socketley");
}
