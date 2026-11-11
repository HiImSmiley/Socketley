// An MCP server inside this program: `cargo run --example mcp_tool -- 9600`, then
//   claude mcp add --transport http demo http://127.0.0.1:9600/mcp
use std::{env, thread, time::Duration};

fn main() -> Result<(), socketley::Error> {
    let port = env::args().nth(1).unwrap_or_else(|| "9600".into());
    let engine = socketley::Engine::new()?;
    let mut tools = engine.runtime("mcp", "tools", &format!("-p {port} --anonymous"))?;

    // Answers at once, on the engine's thread.
    tools.tool("echo", "Gives its arguments back.", None, |call| {
        let text = format!("args {}", call.args());
        call.reply(&text);
    })?;

    // Work that takes time goes to a thread of the program's.
    tools.tool("later", "Answers from another thread.", None, |call| {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            call.reply("from a thread");
        });
    })?;

    tools.tool("failing", "Fails.", None, |call| call.fail("it broke"))?;
    tools.tool("silent", "Forgets to answer.", None, |_call| {})?;

    tools.start()?;
    println!("READY {}", socketley::version());
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
