#![deny(unsafe_op_in_unsafe_fn)]
use anyhow::{bail, ensure, Result};
use clap::Parser;
use ephem_warm_pool::{discard_scratch_pages, state_exchange, PoolConfig, WarmPool, WorkerStatus};
use serde_json::json;
use std::{
    os::fd::RawFd,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static COW_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Parser)]
#[command(
    about = "Linux warm native callback lifecycle benchmark. This does not measure web/PHP switching cost."
)]
struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long, default_value_t = 1000)]
    iterations: usize,
    #[arg(long, default_value_t = 100)]
    warmup: usize,
    #[arg(long, default_value_t = 1000)]
    deadline_ms: u64,
    /// Fail the command when measured native lifecycle p95 exceeds this value.
    #[arg(long)]
    require_p95_ms: Option<f64>,
    /// Also exercise real SIGSEGV, seccomp kill, deadline and recovery barriers.
    #[arg(long)]
    lifecycle_check: bool,
}

fn callback(request: &[u8], state_fd: RawFd) -> Vec<u8> {
    match request {
        b"cow" => COW_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_string()
            .into_bytes(),
        b"truncated-state" => {
            let bytes = [0u8, 0, 0, 10, b'x'];
            // SAFETY: five-byte initialized buffer and live inherited state capability;
            // intentionally malformed framing exercises the parent's burn path.
            unsafe {
                libc::write(state_fd, bytes.as_ptr().cast(), bytes.len());
            }
            Vec::new()
        }
        b"segv" => {
            // SAFETY: deliberately restores default and raises SIGSEGV only in
            // this disposable test worker. Rust's stack-overflow handler can
            // return once for a synthetic signal, so default is explicit.
            unsafe {
                libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                libc::raise(libc::SIGSEGV);
            }
            // SAFETY: failing to terminate must never be mistaken for a passing fault test.
            unsafe { libc::_exit(126) }
        }
        b"seccomp" => {
            // SAFETY: intentional prohibited syscall; default-deny filter must kill it.
            unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            }
            // SAFETY: test failure exit if the containment filter unexpectedly allowed socket.
            unsafe { libc::_exit(125) }
        }
        b"signal-broker" => {
            // SAFETY: deliberate adversarial signal attempt against namespace
            // PID1. The terminal filter must kill this worker before delivery.
            unsafe {
                libc::syscall(libc::SYS_tgkill, 1u64, 1u64, libc::SIGALRM);
            }
            // SAFETY: an allowed cross-process signal is a failed containment test.
            unsafe { libc::_exit(122) }
        }
        b"fcntl-signal-broker" => {
            // SAFETY: deliberate attempt to direct asynchronous socket signals
            // to namespace PID1. The fcntl command policy must kill this worker.
            unsafe {
                libc::fcntl(state_fd, libc::F_SETOWN, 1);
            }
            // SAFETY: assigning an asynchronous broker signal owner is a failed test.
            unsafe { libc::_exit(120) }
        }
        b"fcntl-async" => {
            // SAFETY: deliberate asynchronous socket signal activation probe;
            // no owner is assigned and the terminal filter must reject O_ASYNC.
            unsafe {
                libc::fcntl(state_fd, libc::F_SETFL, libc::O_ASYNC);
            }
            // SAFETY: enabling asynchronous signals is a failed containment test.
            unsafe { libc::_exit(119) }
        }
        b"execve" | b"execveat" => {
            let path = c"/bin/true";
            let argv = [path.as_ptr(), std::ptr::null()];
            let environment: [*const libc::c_char; 1] = [std::ptr::null()];
            // SAFETY: all string/argv/env pointers are valid for the call. The
            // immutable empty rootfs need not contain this executable because
            // terminal seccomp must kill the syscall before pathname resolution.
            unsafe {
                if request == b"execve" {
                    libc::syscall(
                        libc::SYS_execve,
                        path.as_ptr(),
                        argv.as_ptr(),
                        environment.as_ptr(),
                    );
                } else {
                    libc::syscall(
                        libc::SYS_execveat,
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        argv.as_ptr(),
                        environment.as_ptr(),
                        0,
                    );
                }
            }
            // SAFETY: reaching this exit proves execution was not killed by policy.
            unsafe { libc::_exit(118) }
        }
        b"signal-high-tgid" | b"signal-high-tid" => {
            // SAFETY: scalar calls read this disposable worker's own identifiers.
            let (mut tgid, mut tid) = unsafe {
                (
                    libc::getpid() as u64,
                    libc::syscall(libc::SYS_gettid) as u64,
                )
            };
            if request == b"signal-high-tgid" {
                tgid |= 1u64 << 32;
            } else {
                tid |= 1u64 << 32;
            }
            // SAFETY: intentionally noncanonical upper argument bits test the
            // 64-bit filter checks; signal zero would otherwise be a harmless probe.
            unsafe {
                libc::syscall(libc::SYS_tgkill, tgid, tid, 0);
            }
            // SAFETY: accepting nonzero upper bits is a failed strict policy test.
            unsafe { libc::_exit(121) }
        }
        b"timeout" => {
            std::thread::sleep(Duration::from_secs(10));
            Vec::new()
        }
        _ => {
            if discard_scratch_pages(4096).is_err() {
                // SAFETY: failure terminates only this request process.
                unsafe { libc::_exit(124) }
            }
            match state_exchange(state_fd, request, 1 << 20) {
                Ok(response) => response,
                Err(_) => {
                    // SAFETY: state disconnect cannot yield an apparently successful exit.
                    unsafe { libc::_exit(123) }
                }
            }
        }
    }
}

fn percentile(sorted: &[f64], percentile: f64) -> f64 {
    sorted[((sorted.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1)]
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.iterations > 0 && args.iterations <= 1_000_000,
        "iterations must be 1..1000000"
    );
    ensure!(
        args.warmup <= 1_000_000 && args.deadline_ms > 0,
        "invalid warmup/deadline"
    );
    if let Some(limit) = args.require_p95_ms {
        ensure!(limit.is_finite() && limit > 0., "invalid p95 limit");
    }
    let mut pool = WarmPool::start(PoolConfig::new(args.root), callback)?;
    let mut lifecycle = Vec::new();
    if args.lifecycle_check {
        let first = pool.execute(b"cow", Duration::from_secs(1))?;
        let second = pool.execute(b"cow", Duration::from_secs(1))?;
        ensure!(
            first.clean_exit()
                && second.clean_exit()
                && first.output == b"0"
                && second.output == b"0"
                && first.worker_pid != second.worker_pid,
            "COW snapshot did not reset private state"
        );
        lifecycle.push(json!({"request":"cow_reset", "receipts":[first,second]}));
        for (request, expected) in [
            (b"segv".as_slice(), libc::SIGSEGV),
            (b"seccomp".as_slice(), libc::SIGSYS),
            (b"signal-broker".as_slice(), libc::SIGSYS),
            (b"fcntl-signal-broker".as_slice(), libc::SIGSYS),
            (b"fcntl-async".as_slice(), libc::SIGSYS),
            (b"execve".as_slice(), libc::SIGSYS),
            (b"execveat".as_slice(), libc::SIGSYS),
            (b"signal-high-tgid".as_slice(), libc::SIGSYS),
            (b"signal-high-tid".as_slice(), libc::SIGSYS),
        ] {
            let receipt = pool.execute(request, Duration::from_secs(1))?;
            ensure!(
                matches!(receipt.status, WorkerStatus::Signaled { signal, .. } if signal == expected)
                    && receipt.reaped
                    && !receipt.clean_exit(),
                "fault lifecycle failure: {receipt:?}"
            );
            let recovery = pool.execute(b"cow", Duration::from_secs(1))?;
            ensure!(
                recovery.clean_exit() && recovery.output == b"0",
                "broker state changed after rejected signal or fault"
            );
            lifecycle.push(json!({"request": String::from_utf8_lossy(request),
                "receipt": receipt, "recovery": recovery}));
        }
        let receipt = pool.execute(b"timeout", Duration::from_millis(10))?;
        ensure!(
            receipt.status == WorkerStatus::TimedOut && receipt.reaped && !receipt.clean_exit(),
            "deadline lifecycle failure: {receipt:?}"
        );
        lifecycle.push(json!({"request":"timeout", "receipt":receipt}));
        let receipt = pool.execute_with_state(b"verifier", Duration::from_secs(1), |_| {
            bail!("deliberate verifier rejection")
        })?;
        ensure!(
            matches!(receipt.status, WorkerStatus::VerifierFailed { .. })
                && receipt.reaped
                && !receipt.clean_exit(),
            "verifier lifecycle failure: {receipt:?}"
        );
        lifecycle.push(json!({"request":"verifier", "receipt":receipt}));
        let receipt = pool.execute(b"truncated-state", Duration::from_secs(1))?;
        ensure!(
            matches!(receipt.status, WorkerStatus::ProtocolFailure { .. })
                && receipt.reaped
                && !receipt.clean_exit(),
            "truncated state lifecycle failure: {receipt:?}"
        );
        lifecycle.push(json!({"request":"truncated-state", "receipt":receipt}));
    }
    let mut milliseconds = Vec::with_capacity(args.iterations);
    for index in 0..args.warmup + args.iterations {
        let receipt = pool.execute_with_state(
            b"native-lifecycle",
            Duration::from_millis(args.deadline_ms),
            |request| Ok(request.to_vec()),
        )?;
        ensure!(
            receipt.clean_exit() && receipt.output == b"native-lifecycle",
            "native lifecycle failed: {receipt:?}"
        );
        if index >= args.warmup {
            milliseconds.push(receipt.elapsed.as_secs_f64() * 1000.);
        }
    }
    milliseconds.sort_by(f64::total_cmp);
    let p50 = percentile(&milliseconds, 0.50);
    let p95 = percentile(&milliseconds, 0.95);
    let p99 = percentile(&milliseconds, 0.99);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "benchmark": "warm_native_fork_state_ipc_output_eof_reap",
            "scope": "Native callback only; dispatch, fork, seccomp, state round trip, private scratch MADV_DONTNEED, output EOF and waitpid receipt. Startup excluded. No web/PHP overhead claim.",
            "iterations":args.iterations,"warmup":args.warmup,
            "p50_ms":p50,"p95_ms":p95,"p99_ms":p99,
            "max_ms":milliseconds.last(),"lifecycle_checks":lifecycle,
            "p95_below_2ms":p95 < 2.0,"samples_ms":milliseconds
        }))?
    );
    if let Some(limit) = args.require_p95_ms {
        ensure!(
            p95 < limit,
            "measured p95 {p95:.4}ms exceeds required {limit:.4}ms"
        );
    }
    Ok(())
}
