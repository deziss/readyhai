use super::types::Captured;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TAIL_KEEP: usize = 4096;

pub(crate) fn drain_capped<R: Read + Send + 'static>(
    mut r: R,
    cap: usize,
) -> std::sync::mpsc::Receiver<(Vec<u8>, Vec<u8>, bool)> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut head, mut tail, mut truncated) = (Vec::new(), Vec::new(), false);
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = cap.saturating_sub(head.len());
            head.extend_from_slice(&buf[..n.min(room)]);
            if n > room {
                truncated = true;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > TAIL_KEEP * 2 {
                let cut = tail.len() - TAIL_KEEP;
                tail.drain(..cut);
            }
        }
        let cut = tail.len().saturating_sub(TAIL_KEEP);
        tail.drain(..cut);
        let _ = tx.send((head, tail, truncated));
    });
    rx
}

/// Run a command with a hard wall-clock limit and bounded output. stdin is null (or `input`),
/// stdout and stderr are always piped: a child never inherits the parent's stdout, which matters
/// for the MCP server whose stdout carries only JSON-RPC. On timeout the child is killed.
pub fn run_capped(
    cmd: &mut Command,
    timeout: Duration,
    cap: usize,
    input: Option<&[u8]>,
) -> std::io::Result<Captured> {
    use std::io::Write;
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let rx_out = drain_capped(child.stdout.take().expect("piped"), cap);
    let rx_err = drain_capped(child.stderr.take().expect("piped"), cap);
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if let Some(s) = child.try_wait()? {
            break (Some(s), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(15));
    };
    // A grandchild may keep the pipe open after the child died: do not wait for it forever.
    let grace = Duration::from_secs(2);
    let (stdout, stdout_tail, t1) = rx_out.recv_timeout(grace).unwrap_or_default();
    let (stderr, _, t2) = rx_err.recv_timeout(grace).unwrap_or_default();
    Ok(Captured {
        status,
        stdout,
        stdout_tail,
        stderr,
        truncated: t1 || t2,
        timed_out,
    })
}
