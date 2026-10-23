#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(target_os = "linux"))]
compile_error!("ephem-stateful requires Linux");

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use ephem_attestation::transaction_gate::{
    GateLimits, GateOutcome, SqliteStateBackend, StateBackend, TransactionGate, WorkerReceipt,
};
use ephem_warm_pool::{PoolConfig, WarmPool, WorkerStatus};
use std::{
    ffi::{CStr, CString},
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, net::UnixListener, sync::mpsc};

type Boot = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int;
type Run =
    unsafe extern "C" fn(*const u8, usize, libc::c_int, *mut *const u8, *mut usize) -> libc::c_int;
type Fault = unsafe extern "C" fn() -> libc::c_int;
static PHP_RUN: OnceLock<Run> = OnceLock::new();
static PHP_FAULT: OnceLock<Fault> = OnceLock::new();

#[derive(Parser)]
#[command(
    about = "Linux warmed PHP embed + sealed single-backend state gate; bounded experimental runtime"
)]
struct Config {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(
        long,
        required_unless_present = "postgres_dsn_file",
        conflicts_with = "postgres_dsn_file"
    )]
    database: Option<PathBuf>,
    /// Private Unix-socket PostgreSQL DSN, read after the worker baseline forks.
    #[arg(long, conflicts_with = "database")]
    postgres_dsn_file: Option<PathBuf>,
    #[arg(long)]
    adapter: PathBuf,
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long, default_value = "/app/application.php")]
    application: String,
    #[arg(long, default_value_t = 1000)]
    deadline_ms: u64,
    #[arg(long)]
    receipts: PathBuf,
    /// Enables deliberate crash injection through the lab-only X-Ephem-Fault header.
    #[arg(long)]
    allow_fault_injection: bool,
}

fn load_php(config: &Config) -> Result<()> {
    let path = CString::new(config.adapter.as_os_str().as_encoded_bytes())?;
    // SAFETY: path is NUL terminated; only the explicitly selected local adapter is loaded.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        // SAFETY: dlerror returns a valid thread-local NUL-terminated diagnostic or null.
        let error = unsafe { libc::dlerror() };
        let message = if error.is_null() {
            "unknown loader error".into()
        } else {
            // SAFETY: non-null dlerror result remains valid until another loader operation.
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        bail!("load PHP adapter: {message}");
    }
    // SAFETY: handle is live; literal symbols are NUL terminated. The adapter ABI is fixed by embed.c.
    let boot = unsafe { libc::dlsym(handle, c"ephem_php_boot".as_ptr()) };
    // SAFETY: same live handle and fixed C ABI as above.
    let run = unsafe { libc::dlsym(handle, c"ephem_php_run".as_ptr()) };
    // SAFETY: same live handle; function is called only for explicit lab fault injection.
    let fault = unsafe { libc::dlsym(handle, c"ephem_php_segfault".as_ptr()) };
    ensure!(
        !boot.is_null() && !run.is_null() && !fault.is_null(),
        "adapter ABI mismatch"
    );
    // SAFETY: all non-null symbols were compiled with the exact signatures defined above.
    let boot: Boot = unsafe { std::mem::transmute(boot) };
    // SAFETY: exact ephem_php_run C declaration and permanent (never dlclosed) library handle.
    PHP_RUN
        .set(unsafe { std::mem::transmute::<*mut libc::c_void, Run>(run) })
        .map_err(|_| anyhow::anyhow!("PHP already initialized"))?;
    // SAFETY: exact ephem_php_segfault C declaration, with permanent library lifetime.
    PHP_FAULT
        .set(unsafe { std::mem::transmute::<*mut libc::c_void, Fault>(fault) })
        .map_err(|_| anyhow::anyhow!("PHP fault hook already initialized"))?;
    let bootstrap = CString::new(config.bootstrap.as_os_str().as_encoded_bytes())?;
    let application = CString::new(config.application.as_bytes())?;
    // SAFETY: both input strings outlive the call; initialization is on the sole OS thread.
    ensure!(
        unsafe { boot(bootstrap.as_ptr(), application.as_ptr()) } == 0,
        "PHP initialization failed"
    );
    Ok(())
}

fn php_worker(input: &[u8], state_fd: RawFd) -> Vec<u8> {
    let mut output = std::ptr::null();
    let mut len = 0;
    let Some(run) = PHP_RUN.get() else {
        return Vec::new();
    };
    // The first byte is a trusted supervisor lab fault selector, not PHP source.
    let (&fault, input) = input.split_first().unwrap_or((&0, &[]));
    // SAFETY: input is a live slice, output arguments are writable; callback runs single-threaded.
    let result = unsafe { run(input.as_ptr(), input.len(), state_fd, &mut output, &mut len) };
    if result != 0 || len > 1_048_576 || (len != 0 && output.is_null()) {
        // SAFETY: abort only this disposable child without running inherited parent destructors.
        unsafe { libc::_exit(70) }
    }
    match fault {
        1 => {
            // SAFETY: explicit lab-only C probe deliberately accesses a PROT_NONE mapping.
            if let Some(crash) = PHP_FAULT.get() {
                unsafe {
                    crash();
                }
            }
            // SAFETY: if the fault probe failed, nonzero exit still prevents a commit.
            unsafe { libc::_exit(71) }
        }
        2 => {
            // SAFETY: scalar syscall arguments; this must be killed by the installed seccomp filter.
            unsafe {
                libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                libc::_exit(72)
            }
        }
        3 => {
            // SAFETY: nonzero disposable worker exit tests transaction burn.
            unsafe { libc::_exit(73) }
        }
        4 => loop {
            std::hint::spin_loop();
        },
        5 => {
            let _ = ephem_warm_pool::state_exchange(state_fd, b"*1\r\n$4\r\nEXEC\r\n", 1024);
            // An ignored gate error must still latch a burn in the trusted parent.
        }
        _ => {}
    }
    if len == 0 {
        Vec::new()
    } else {
        // SAFETY: successful adapter call returns an allocation valid until child exit; length was bounded.
        unsafe { std::slice::from_raw_parts(output, len) }.to_vec()
    }
}

fn read_http(client: &mut UnixStream, max: usize, expires: Instant) -> Result<(Vec<u8>, u8)> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        ensure!(headers.len() < 16384, "HTTP header limit");
        client.set_read_timeout(Some(
            expires
                .checked_duration_since(Instant::now())
                .context("HTTP receipt deadline")?,
        ))?;
        let mut byte = [0];
        client.read_exact(&mut byte)?;
        headers.push(byte[0]);
    }
    let text = std::str::from_utf8(&headers)?;
    let mut lines = text.split("\r\n");
    ensure!(
        lines.next() == Some("POST /run HTTP/1.1"),
        "unsupported HTTP request"
    );
    let (mut length, mut host, mut fault) = (None, false, None);
    for line in lines.filter(|s| !s.is_empty()) {
        let (key, value) = line.split_once(':').context("invalid HTTP header")?;
        ensure!(
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "invalid header name"
        );
        ensure!(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "invalid header value"
        );
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                ensure!(
                    length.is_none()
                        && !value.is_empty()
                        && value.bytes().all(|b| b.is_ascii_digit()),
                    "invalid Content-Length"
                );
                length = Some(value.parse::<usize>()?);
            }
            "host" => {
                ensure!(!host && !value.is_empty(), "invalid Host");
                host = true;
            }
            "x-ephem-fault" => {
                ensure!(fault.is_none(), "duplicate fault selector");
                fault = Some(match value {
                    "segv" => 1,
                    "syscall" => 2,
                    "exit" => 3,
                    "timeout" => 4,
                    "verifier" => 5,
                    _ => bail!("unknown fault"),
                });
            }
            "transfer-encoding" | "expect" | "upgrade" | "trailer" => {
                bail!("unsupported HTTP framing")
            }
            _ => {}
        }
    }
    ensure!(host, "Host required");
    let length = length.context("Content-Length required")?;
    ensure!(length <= max, "HTTP body limit");
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        client.set_read_timeout(Some(
            expires
                .checked_duration_since(Instant::now())
                .context("HTTP body deadline")?,
        ))?;
        let size = client.read(&mut body[offset..])?;
        ensure!(size > 0, "HTTP body disconnected");
        offset += size;
    }
    Ok((body, fault.unwrap_or(0)))
}

fn peer_alive(client: &UnixStream) -> bool {
    let mut byte = [0u8];
    // SAFETY: valid borrowed stream and one-byte writable buffer; PEEK never consumes data.
    let rc = unsafe {
        libc::recv(
            client.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
}

fn serve_request(
    client: &mut UnixStream,
    pool: &mut WarmPool,
    gate: &TransactionGate,
    backend: &dyn StateBackend,
    request_id: u64,
    config: &Config,
    accepted: Instant,
) -> (GateOutcome, serde_json::Value) {
    let started = Instant::now();
    let mut details = serde_json::json!({"request_id": request_id});
    let mut run = || -> Result<GateOutcome> {
        let deadline = Duration::from_millis(config.deadline_ms);
        let expires = accepted
            .checked_add(deadline)
            .context("deadline overflow")?;
        client.set_read_timeout(Some(deadline))?;
        client.set_write_timeout(Some(deadline))?;
        let (body, fault) = read_http(client, 65536, expires)?;
        ensure!(
            fault == 0 || config.allow_fault_injection,
            "fault injection disabled"
        );
        let remaining = expires
            .checked_duration_since(Instant::now())
            .context("request deadline expired")?;
        let mut session = gate.begin(request_id, remaining)?;
        let mut payload = Vec::with_capacity(body.len() + 1);
        payload.push(fault);
        payload.extend_from_slice(&body);
        let worker = pool.execute_with_state(&payload, remaining, |frame| {
            ensure!(
                peer_alive(client),
                "client disconnected or sent unsupported pipelined data"
            );
            Ok(session.execute_resp(frame, backend)?)
        })?;
        details["worker"] = serde_json::to_value(&worker)?;
        details["worker_elapsed_ms"] = serde_json::json!(worker.elapsed.as_secs_f64() * 1000.0);
        session.bind_worker(u32::try_from(worker.worker_pid)?)?;
        if !peer_alive(client) {
            session.burn("client disconnected before commit decision");
        }
        session.set_http_output(&worker.output)?;
        let (exit_code, signal) = match &worker.status {
            WorkerStatus::Exited { code } => (Some(*code), None),
            WorkerStatus::Signaled { signal, .. } => (None, Some(*signal)),
            _ => (None, None),
        };
        let receipt = WorkerReceipt {
            request_id,
            pid: u32::try_from(worker.worker_pid)?,
            exit_code,
            signal,
            timed_out: matches!(worker.status, WorkerStatus::TimedOut),
            containment_violation: signal == Some(libc::SIGSYS),
            ipc_complete: worker.stdout_eof && worker.state_eof && worker.reaped,
        };
        Ok(gate.finish(gate.seal(session)?, receipt, backend))
    };
    let outcome = match run() {
        Ok(outcome) => outcome,
        Err(error) => GateOutcome::burned(format!("{error:#}")),
    };
    details["http_status"] = serde_json::json!(outcome.http_status);
    details["committed_mutations"] = serde_json::json!(outcome.committed_mutations);
    details["commit_status"] = serde_json::json!(outcome.commit_status);
    details["burned_reason"] = serde_json::json!(outcome.burned_reason);
    details["elapsed_ms"] = serde_json::json!(started.elapsed().as_secs_f64() * 1000.0);
    (outcome, details)
}

fn main() -> Result<()> {
    // Re-exec, rather than clearenv alone: original stack environment bytes must
    // not survive into the COW snapshot. No secrets or DB handles exist yet.
    if std::env::vars_os().next().is_some() {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(std::env::current_exe()?)
            .args(std::env::args_os().skip(1))
            .env_clear()
            .exec();
        return Err(error.into());
    }
    let config = Config::parse();
    // SAFETY: initialization is still single-threaded; all private DB, log and
    // Unix-socket objects must be private from their creation, without a chmod race.
    unsafe {
        libc::umask(0o077);
    }
    ensure!(
        (10..=60000).contains(&config.deadline_ms),
        "deadline must be 10..60000ms"
    );
    ensure!(
        !config.socket.exists(),
        "refusing to replace existing socket"
    );
    load_php(&config)?;
    // Warm baseline is forked BEFORE the DB, secret sealing key, logs or listener are opened.
    let pool = WarmPool::start(PoolConfig::new(config.root.clone()), php_worker)?;
    let backend: Box<dyn StateBackend> = if let Some(path) = &config.database {
        Box::new(SqliteStateBackend::open(path)?)
    } else {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let path = config
            .postgres_dsn_file
            .as_ref()
            .context("backend is required")?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.len() <= 65536,
            "DSN file must be a root-owned private regular file <=64KiB"
        );
        let mut dsn = String::new();
        file.read_to_string(&mut dsn)?;
        Box::new(ephem_attestation::transaction_gate::PostgresStateBackend::connect(dsn.trim())?)
    };
    let gate = TransactionGate::new(GateLimits::default())?;
    let receipts = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&config.receipts)?;
    fs::set_permissions(&config.receipts, fs::Permissions::from_mode(0o600))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = UnixListener::bind(&config.socket)?;
        fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600))?;
        let (sender, mut receiver) = mpsc::channel::<(UnixStream, Instant)>(16);
        std::thread::spawn(move || {
            let (mut pool, mut receipts) = (pool, receipts);
            let mut request_id = 0u64;
            while let Some((mut client, accepted)) = receiver.blocking_recv() {
                request_id = match request_id.checked_add(1) {
                    Some(id) => id,
                    None => break,
                };
                let (outcome, details) = serve_request(
                    &mut client,
                    &mut pool,
                    &gate,
                    backend.as_ref(),
                    request_id,
                    &config,
                    accepted,
                );
                // Durable receipts are diagnostic; the SQLite commit has its own durability policy.
                let logged = serde_json::to_writer(&mut receipts, &details).is_ok()
                    && receipts.write_all(b"\n").is_ok();
                let _ = client.write_all(&outcome.response);
                // A diagnostic failure after the DB linearization cannot undo a commit.
                // Preserve its real outcome and stop accepting work in this executor.
                if !logged {
                    break;
                }
            }
        });
        loop {
            let (mut stream, _) = listener.accept().await?;
            let accepted = Instant::now();
            if sender.capacity() == 0 {
                let _ = stream
                    .write_all(&GateOutcome::burned("admission queue full").response)
                    .await;
                continue;
            }
            let stream = stream.into_std()?;
            stream.set_nonblocking(false)?;
            if let Err(error) = sender.try_send((stream, accepted)) {
                let (mut stream, _) = error.into_inner();
                let _ =
                    stream.write_all(&GateOutcome::burned("admission queue unavailable").response);
                ensure!(!sender.is_closed(), "state executor stopped");
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}
