// A TCP server inside this program: `cargo run --example echo_server -- 9700`, then `nc 127.0.0.1 9700`.
use std::sync::Arc;
use std::{env, thread, time::Duration};

fn main() -> Result<(), socketley::Error> {
    let port = env::args().nth(1).unwrap_or_else(|| "9700".into());
    let engine = socketley::Engine::new()?;
    let mut server = engine.runtime("server", "echo", &format!("-p {port} --mode in"))?;
    server.on_connect(|c| println!("OPEN {}", c > 0))?;
    server.on_disconnect(|c| println!("GONE {}", c > 0))?;

    // A closure reaches the runtime through a handle made after it, here a slot filled once it exists.
    let slot: Arc<std::sync::OnceLock<Arc<socketley::Runtime>>> = Arc::new(std::sync::OnceLock::new());
    let from_message = slot.clone();
    server.on_message(move |c, data| {
        let line = format!("echo: {}", String::from_utf8_lossy(data));
        if let Some(rt) = from_message.get() {
            let rt = rt.clone();
            thread::spawn(move || {
                rt.send(c, line.as_bytes());
            });
        }
    })?;

    server.start()?;
    let server = Arc::new(server);
    let _ = slot.set(server.clone());
    println!("READY");
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
