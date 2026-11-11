// A website whose /api is this program: `cargo run --example web_app -- 8080 /srv/site`.
use std::{env, thread, time::Duration};

fn main() -> Result<(), socketley::Error> {
    let port = env::args().nth(1).unwrap_or_else(|| "8080".into());
    let root = env::args().nth(2).unwrap_or_else(|| ".".into());
    let root = std::fs::canonicalize(&root).map_err(|e| socketley::Error(format!("{root}: {e}")))?.display().to_string();
    let engine = socketley::Engine::new()?;
    let kv = engine.runtime("cache", "kv", &format!("-p {}", port.parse::<u32>().unwrap_or(8080) + 1))?;
    kv.start()?;
    kv.command("set hits 0")?;
    let kv = std::sync::Arc::new(kv);

    let mut site = engine.runtime("web", "site", &format!("-p {port} --root {root}"))?;
    let counter = kv.clone();
    site.handle("/api", move |req| {
        let hits = counter.command("incr hits").unwrap_or_default();
        let body = format!("{} {} {} hits {} body {}", req.method, req.path, req.query, hits, String::from_utf8_lossy(&req.body));
        req.reply(200, "Content-Type: text/plain\nX-From: rust", body.as_bytes());
    })?;
    site.handle("/slow", |req| {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            req.reply(202, "Content-Type: text/plain", b"later");
        });
    })?;
    site.handle("/forgets", |_req| {})?;
    site.start()?;
    println!("READY");
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
