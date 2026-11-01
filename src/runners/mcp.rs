use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};

pub fn serve(
    name: &str,
    max_message: usize,
    tools: Value,
    mut call: impl FnMut(&str, Value) -> Result<Value>,
) -> Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let count = (&mut input)
            .take((max_message + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        if count > max_message {
            bail!("MCP request exceeds limit");
        }
        let message: Value = serde_json::from_slice(&line)?;
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => {
                json!({"protocolVersion":message.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2025-03-26"),"capabilities":{"tools":{}},"serverInfo":{"name":name,"version":env!("CARGO_PKG_VERSION")}})
            }
            Some("ping") => json!({}),
            Some("tools/list") => json!({"tools":tools}),
            Some("tools/call") => {
                let outcome = (|| {
                    let tool = message
                        .pointer("/params/name")
                        .and_then(Value::as_str)
                        .context("missing tool name")?;
                    let arguments = message
                        .pointer("/params/arguments")
                        .cloned()
                        .context("missing arguments")?;
                    call(tool, arguments)
                })();
                match outcome {
                    Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}]}),
                    Err(error) => {
                        json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]})
                    }
                }
            }
            _ => {
                writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})
                )?;
                stdout.flush()?;
                continue;
            }
        };
        writeln!(
            stdout,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"result":result})
        )?;
        stdout.flush()?;
    }
    Ok(())
}
