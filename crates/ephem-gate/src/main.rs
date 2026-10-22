#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("ephem-gate requires Linux: no insecure portability mode is provided");

mod resources;
mod root_manifest;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use nix::libc;
use resources::{RequestCgroup, ResourceRoot};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::Semaphore,
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};

#[derive(Parser, Debug)]
#[command(about = "Fail-closed, read-only, fresh-execution gate. No database commit support.")]
struct Config {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    jail: PathBuf,
    #[arg(long)]
    root: PathBuf,
    /// Trusted closed-world public-root policy. This is not secret-content detection.
    #[arg(long)]
    root_manifest: Option<PathBuf>,
    #[arg(skip)]
    root_policy: Option<root_manifest::RootManifest>,
    #[arg(long)]
    worker: String,
    /// Empty, root-owned cgroup-v2 subtree with cpu, memory and pids enabled.
    #[arg(long)]
    cgroup_root: PathBuf,
    #[arg(long, default_value_t = 134217728, value_parser = clap::value_parser!(u64).range(16777216..=17179869184))]
    memory_max: u64,
    #[arg(long, default_value_t = 100000, value_parser = clap::value_parser!(u64).range(1000..=1000000))]
    cpu_quota_us: u64,
    #[arg(long, default_value_t = 100000, value_parser = clap::value_parser!(u64).range(1000..=1000000))]
    cpu_period_us: u64,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(10..=60000))]
    deadline_ms: u64,
    #[arg(long, default_value_t = 1048576)]
    max_input: usize,
    #[arg(long, default_value_t = 1048576)]
    max_output: usize,
    #[arg(long, default_value_t = 4)]
    max_inflight: usize,
    /// Fixed script path inside the rootfs. Enables bounded CGI response parsing.
    #[arg(long)]
    cgi_script: Option<String>,
    #[arg(last = true)]
    args: Vec<String>,
}

#[derive(Debug)]
struct Request {
    body: Vec<u8>,
    content_type: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct JailReceipt {
    ephem_jail: u32,
    worker_pid: i32,
    exit_code: i32,
    signal: i32,
    landlock_abi: i32,
}

struct Output {
    bytes: Vec<u8>,
    digest: String,
    receipt: JailReceipt,
    status: u16,
    content_type: String,
}

/// A pidfd refers to the owned, unreaped launcher, never a recycled numeric PID.
struct KillGuard(Option<OwnedFd>);
impl KillGuard {
    fn new(pid: u32) -> Result<Self> {
        // SAFETY: pid is the child returned by Command; flags=0; no pointer arguments.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        ensure!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        // SAFETY: successful pidfd_open returned a new descriptor owned by this guard.
        Ok(Self(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })))
    }
    fn disarm(&mut self) {
        self.0.take();
    }
}
impl Drop for KillGuard {
    fn drop(&mut self) {
        if let Some(fd) = &self.0 {
            // SAFETY: valid owned pidfd, SIGKILL, null siginfo and flags=0. The
            // launcher's child's PDEATHSIG also destroys the request namespace.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }
}

fn memfd() -> Result<File> {
    let name = CString::new("ephem-response")?;
    // SAFETY: CString is valid for the call; flags request a private CLOEXEC file.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    ensure!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    // SAFETY: the new descriptor has exactly one owner, this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

async fn collect_output<R: AsyncRead + Unpin>(mut pipe: R, limit: usize) -> Result<(File, String)> {
    let mut staging = memfd()?;
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        let n = pipe.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n).context("output length overflow")?;
        ensure!(count <= limit, "output limit exceeded");
        staging.write_all(&chunk[..n])?;
        hash.update(&chunk[..n]);
    }
    // Worker never receives this descriptor or a mapping. Seal only after pipe EOF.
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: owned memfd, valid fcntl command and integer seal flags.
    ensure!(
        unsafe { libc::fcntl(staging.as_raw_fd(), libc::F_ADD_SEALS, seals) } == 0,
        "cannot seal response: {}",
        std::io::Error::last_os_error()
    );
    staging.seek(SeekFrom::Start(0))?;
    Ok((staging, format!("{:x}", hash.finalize())))
}

async fn bounded_bytes<R: AsyncRead + Unpin>(pipe: R, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    pipe.take((limit + 1) as u64).read_to_end(&mut buf).await?;
    ensure!(buf.len() <= limit, "receipt overflow");
    Ok(buf)
}

async fn read_request(stream: &mut UnixStream, max_input: usize) -> Result<Request> {
    // Read headers without over-reading arbitrary request bodies. This local
    // ingress protocol deliberately supports one Content-Length request only.
    let mut header = Vec::with_capacity(1024);
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < 16384, "header limit");
        header.push(stream.read_u8().await?);
    }
    let header = std::str::from_utf8(&header)?;
    ensure!(header.is_ascii(), "non-ASCII headers");
    let mut lines = header.split("\r\n");
    ensure!(
        lines.next() == Some("POST /run HTTP/1.1"),
        "unsupported request line"
    );
    let mut length = None;
    let mut content_type = None;
    let mut host = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':').context("malformed header")?;
        ensure!(
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "bad header name"
        );
        ensure!(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "bad header value"
        );
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                ensure!(
                    length.is_none()
                        && !value.is_empty()
                        && value.bytes().all(|b| b.is_ascii_digit()),
                    "invalid length"
                );
                length = Some(value.parse::<usize>()?);
            }
            "transfer-encoding" | "expect" | "upgrade" | "trailer" => bail!("unsupported framing"),
            "host" => {
                ensure!(!host && !value.is_empty(), "invalid host");
                host = true;
            }
            "content-type" => {
                ensure!(
                    content_type.is_none() && value.len() <= 256,
                    "invalid content type"
                );
                content_type = Some(value.to_string());
            }
            _ => {}
        }
    }
    ensure!(host, "host required");
    let length = length.context("content length required")?;
    ensure!(length <= max_input, "input limit exceeded");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(Request {
        body,
        content_type: content_type.unwrap_or_else(|| "application/octet-stream".into()),
    })
}

fn cgi_response(raw: Vec<u8>) -> Result<(u16, String, Vec<u8>)> {
    let end = raw
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|x| x == b"\n\n").map(|i| (i, 2)))
        .context("missing CGI header terminator")?;
    ensure!(end.0 <= 16384, "CGI header limit");
    let header = std::str::from_utf8(&raw[..end.0])?;
    let mut status = None;
    let mut content_type = None;
    for line in header.lines() {
        let (key, value) = line.split_once(':').context("bad CGI header")?;
        let value = value.trim();
        ensure!(
            value.bytes().all(|b| (32..127).contains(&b)),
            "bad CGI header value"
        );
        match key.to_ascii_lowercase().as_str() {
            "status" => {
                ensure!(status.is_none(), "duplicate CGI status");
                let code = value
                    .split_whitespace()
                    .next()
                    .context("empty CGI status")?
                    .parse::<u16>()?;
                ensure!(
                    (200..=599).contains(&code) && code != 204 && code != 304,
                    "unsupported CGI status"
                );
                status = Some(code);
            }
            "content-type" => {
                ensure!(content_type.is_none(), "duplicate CGI content type");
                content_type = Some(value.to_string());
            }
            // PHP's default identification header is discarded deliberately.
            "x-powered-by" => {}
            _ => bail!("CGI response header unsupported by read-only profile"),
        }
    }
    Ok((
        status.unwrap_or(200),
        content_type.context("CGI Content-Type required")?,
        raw[end.0 + end.1..].to_vec(),
    ))
}

async fn execute_scoped(
    cfg: &Config,
    request: Request,
    deadline: Instant,
    scope: &RequestCgroup<'_>,
) -> Result<Output> {
    let mut command = Command::new(&cfg.jail);
    command
        .arg("--root")
        .arg(&cfg.root)
        .arg("--worker")
        .arg(&cfg.worker)
        .arg("--")
        .args(&cfg.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("TMPDIR", "/tmp")
        .env("EPHEM_GATE_PID", std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(script) = &cfg.cgi_script {
        command
            .env("GATEWAY_INTERFACE", "CGI/1.1")
            .env("REQUEST_METHOD", "POST")
            .env("REQUEST_URI", "/run")
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .env("SERVER_NAME", "localhost")
            .env("SERVER_PORT", "80")
            .env("REDIRECT_STATUS", "200")
            .env("SCRIPT_FILENAME", script)
            .env("SCRIPT_NAME", "/run")
            .env("CONTENT_LENGTH", request.body.len().to_string())
            .env("CONTENT_TYPE", &request.content_type);
    }
    let attach_fd = scope.attach_fd();
    // SAFETY: the closure performs only the async-signal-safe write syscall and
    // constructs an io::Error on failure. The scope owns this CLOEXEC fd until
    // spawn completes. Writing 0 attaches only this forked launcher, before exec.
    unsafe {
        command.pre_exec(move || loop {
            let written = libc::write(attach_fd, b"0\n".as_ptr().cast(), 2);
            if written == 2 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if written < 0 && error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if written < 0 {
                error
            } else {
                std::io::Error::from_raw_os_error(libc::EIO)
            });
        });
    }
    let mut child = command.spawn().context("spawn launcher")?;
    let mut guard = KillGuard::new(child.id().context("missing child pid")?)?;
    let mut input = child.stdin.take().context("missing stdin")?;
    let output = child.stdout.take().context("missing stdout")?;
    let receipt = child.stderr.take().context("missing receipt")?;
    let work = async {
        let send = async move {
            input.write_all(&request.body).await?;
            input.shutdown().await?;
            // ChildStdin's pipe can outlive poll_shutdown. Transfer ownership
            // into this future and close it before waiting for worker EOF.
            drop(input);
            Ok::<_, anyhow::Error>(())
        };
        let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
        tokio::try_join!(
            send,
            collect_output(output, cfg.max_output),
            bounded_bytes(receipt, 4096),
            wait
        )
    };
    let result = timeout_at(deadline, work).await;
    let (_, (mut staging, _staging_digest), receipt_bytes, status) = match result {
        Ok(Ok(value)) => value,
        failure => {
            // Kill launcher via pidfd. Its PID1 child has PDEATHSIG=SIGKILL.
            drop(guard);
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(2), child.wait()).await;
            return match failure {
                Err(_) => Err(anyhow::anyhow!("request deadline")),
                Ok(Err(e)) => Err(e),
                Ok(Ok(_)) => unreachable!(),
            };
        }
    };
    guard.disarm();
    ensure!(status.success(), "launcher rejected execution");
    let receipt: JailReceipt =
        serde_json::from_slice(&receipt_bytes).context("invalid trusted receipt")?;
    ensure!(
        receipt.ephem_jail == 1
            && receipt.worker_pid > 1
            && receipt.exit_code == 0
            && receipt.signal == 0
            && receipt.landlock_abi >= 3,
        "unclean worker receipt"
    );
    let mut bytes = Vec::new();
    staging.read_to_end(&mut bytes)?;
    let (status, content_type, bytes) = if cfg.cgi_script.is_some() {
        cgi_response(bytes)?
    } else {
        (200, "application/octet-stream".into(), bytes)
    };
    ensure!(
        Instant::now() < deadline,
        "verification exceeded request deadline"
    );
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok(Output {
        bytes,
        digest,
        receipt,
        status,
        content_type,
    })
}

async fn execute(
    cfg: &Config,
    resources: &ResourceRoot,
    request: Request,
    deadline: Instant,
) -> Result<Output> {
    // Check before cgroup creation/spawn. The root administrator and immutable
    // provisioning remain trusted; request bytes cannot select policy paths.
    if let Some(policy) = &cfg.root_policy {
        policy
            .validate(&cfg.root)
            .context("root manifest refused request")?;
    }
    ensure!(
        Instant::now() < deadline,
        "root verification exceeded request deadline"
    );
    let mut scope = resources.create()?;
    let result = execute_scoped(cfg, request, deadline, &scope).await;
    // Both success and failure destroy the owned cgroup. No response is released
    // before the cgroup is empty, removed, and its OOM counters checked.
    let cleanup = scope.finish().await;
    let output = result?;
    cleanup?;
    ensure!(
        Instant::now() < deadline,
        "disposal exceeded request deadline"
    );
    Ok(output)
}

async fn respond(
    stream: &mut UnixStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "CGI Response",
    };
    let header = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n{extra}\r\n", body.len());
    timeout(Duration::from_secs(2), async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await
    })
    .await??;
    Ok(())
}

async fn handle(
    mut stream: UnixStream,
    cfg: Arc<Config>,
    resources: Arc<ResourceRoot>,
    request_id: u64,
    accepted: Instant,
) {
    let deadline = accepted + Duration::from_millis(cfg.deadline_ms);
    let request = match timeout_at(deadline, read_request(&mut stream, cfg.max_input)).await {
        Ok(Ok(r)) => r,
        _ => {
            let _ = respond(&mut stream, 400, "text/plain", b"request rejected\n", "").await;
            return;
        }
    };
    let result = execute(&cfg, &resources, request, deadline).await;
    match result {
        Ok(out) => {
            let elapsed = accepted.elapsed().as_secs_f64() * 1000.0;
            let mut extra = format!("X-Ephem-Worker-Pid: {}\r\nX-Ephem-Output-Sha256: {}\r\nX-Ephem-Elapsed-Ms: {elapsed:.6}\r\n", out.receipt.worker_pid, out.digest);
            if let Some(policy) = &cfg.root_policy {
                extra.push_str(&format!(
                    "X-Ephem-Root-Manifest-Sha256: {}\r\n",
                    policy.digest()
                ));
            }
            // Fixed metadata only. No worker stderr, input, URI, or output in logs.
            eprintln!(
                "{}",
                serde_json::json!({"request":request_id,"accepted":true,"worker_pid":out.receipt.worker_pid,"bytes":out.bytes.len(),"elapsed_ms":elapsed})
            );
            let _ = respond(
                &mut stream,
                out.status,
                &out.content_type,
                &out.bytes,
                &extra,
            )
            .await;
        }
        Err(_) => {
            eprintln!(
                "{}",
                serde_json::json!({"request":request_id,"accepted":false})
            );
            let _ = respond(&mut stream, 500, "text/plain", b"execution rejected\n", "").await;
        }
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.dev() == self.device && meta.ino() == self.inode && meta.file_type().is_socket()
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::parse();
    resources::secure_host_memory()?;
    let resources = Arc::new(ResourceRoot::open(
        &cfg.cgroup_root,
        cfg.memory_max,
        cfg.cpu_quota_us,
        cfg.cpu_period_us,
    )?);
    ensure!(
        cfg.max_inflight > 0 && cfg.max_inflight <= 128,
        "max-inflight must be 1..128"
    );
    ensure!(
        cfg.max_input <= 16 * 1024 * 1024 && cfg.max_output <= 16 * 1024 * 1024,
        "buffer caps must be <=16MiB"
    );
    ensure!(
        cfg.worker.starts_with('/') && cfg.worker != "/",
        "worker must be an absolute in-jail path"
    );
    ensure!(
        cfg.jail.is_absolute() && cfg.root.is_absolute() && cfg.socket.is_absolute(),
        "host paths must be absolute"
    );
    // Mandatory for the explicit public-root profile, before any socket bind.
    if let Some(path) = &cfg.root_manifest {
        cfg.root_policy = Some(root_manifest::RootManifest::load(
            path,
            &cfg.root,
            &cfg.worker,
        )?);
    }
    let parent = cfg.socket.parent().context("socket parent")?;
    let meta = fs::symlink_metadata(parent)?;
    // Restrict the local authority boundary; do not unlink an existing socket.
    // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0,
        "socket directory must be owned and not group/world writable"
    );
    ensure!(
        fs::symlink_metadata(&cfg.socket).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "socket path already exists or cannot be inspected"
    );
    let listener = UnixListener::bind(&cfg.socket)?;
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o600))?;
    let socket_meta = fs::symlink_metadata(&cfg.socket)?;
    let _socket_guard = SocketGuard {
        path: cfg.socket.clone(),
        device: socket_meta.dev(),
        inode: socket_meta.ino(),
    };
    let slots = Arc::new(Semaphore::new(cfg.max_inflight));
    let cfg = Arc::new(cfg);
    let ids = AtomicU64::new(1);
    let mut jobs = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!(
        "{}",
        serde_json::json!({"ready":true,"profile": if cfg.root_policy.is_some() { "public-root-fresh-exec-v1" } else { "read-only-fresh-exec-v1" }})
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            Some(_) = jobs.join_next(), if !jobs.is_empty() => {},
            incoming = listener.accept() => {
                let (mut stream, _) = incoming?;
                let accepted = Instant::now();
                match slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let cfg = cfg.clone();
                        let resources = resources.clone();
                        let id = ids.fetch_add(1, Ordering::Relaxed);
                        jobs.spawn(async move { let _permit = permit; handle(stream, cfg, resources, id, accepted).await; });
                    }
                    Err(_) => {
                        // No unbounded task queue for clients that refuse to read.
                        drop(stream.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
                        let _ = stream.shutdown().await;
                    }
                }
            }
        }
    }
    // Active requests already have absolute deadlines and retain their owned
    // launchers until disposal. Graceful shutdown drains without starting new work.
    drop(listener);
    while jobs.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_root_is_mandatory_and_limits_have_bounded_defaults() {
        let args = [
            "ephem-gate",
            "--socket",
            "/run/ephem/gate.sock",
            "--jail",
            "/usr/local/bin/ephem-jail",
            "--root",
            "/srv/ephem/rootfs",
            "--worker",
            "/worker",
        ];
        assert!(Config::try_parse_from(args).is_err());
        let cfg = Config::try_parse_from(
            args.into_iter()
                .chain(["--cgroup-root", "/sys/fs/cgroup/ephem/requests"]),
        )
        .unwrap();
        assert_eq!(cfg.memory_max, 134217728);
        assert_eq!(cfg.cpu_quota_us, 100000);
        assert_eq!(cfg.cpu_period_us, 100000);
    }

    #[test]
    fn cgi_preserves_binary_body_and_status() {
        let raw = b"Status: 201 Created\r\nContent-Type: application/octet-stream\r\nX-Powered-By: PHP\r\n\r\na\0\xff".to_vec();
        let (status, content_type, body) = cgi_response(raw).unwrap();
        assert_eq!(status, 201);
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(body, b"a\0\xff");
    }

    #[test]
    fn cgi_rejects_unapproved_and_ambiguous_headers() {
        for raw in [
            "Content-Type: text/plain\r\nContent-Length: 7\r\n\r\ncontent",
            "Content-Type: text/plain\r\nSet-Cookie: sid=value\r\n\r\ncontent",
            "Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\ncontent",
            "Content-Type: text/plain\r\nStatus: 200 OK\r\nStatus: 500 Error\r\n\r\ncontent",
            "Content-Type: text/plain\r\nStatus: 204 No Content\r\n\r\ncontent",
            "X-Anything: test\r\n\r\ncontent",
            "Content-Type: text/plain\r\n folded\r\n\r\ncontent",
        ] {
            assert!(
                cgi_response(raw.as_bytes().to_vec()).is_err(),
                "accepted {raw:?}"
            );
        }
    }
}
