#![deny(unsafe_op_in_unsafe_fn)]
//! Linux-only, single-threaded, pre-fork native callback broker.
//!
//! Call `WarmPool::start` before starting threads or loading any database secrets.
//! Only the isolated broker forks. Parent-side Tokio threads never fork. This
//! snapshots native callback state; it does not claim to snapshot PHP or Node.
#[cfg(not(target_os = "linux"))]
compile_error!("ephem-warm-pool requires Linux; no insecure portability fallback");

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;
use std::{
    ffi::CString,
    fs,
    io::{self, Read, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
    time::{Duration, Instant},
};

pub type Worker = fn(&[u8], RawFd) -> Vec<u8>;

#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Dedicated root-owned rootfs, recursively mounted read-only and noexec.
    pub root: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub max_request: usize,
    pub max_output: usize,
    pub max_state_frame: usize,
    pub max_memory_bytes: u64,
    pub max_open_files: u64,
    pub max_cpu_seconds: u64,
}
impl PoolConfig {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            uid: 65534,
            gid: 65534,
            max_request: 1 << 20,
            max_output: 1 << 20,
            max_state_frame: 1 << 20,
            max_memory_bytes: 512 << 20,
            max_open_files: 64,
            max_cpu_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerStatus {
    Exited { code: i32 },
    Signaled { signal: i32, core_dumped: bool },
    TimedOut,
    VerifierFailed { message: String },
    ProtocolFailure { message: String },
}

#[derive(Debug, Serialize)]
pub struct WorkerResult {
    pub output: Vec<u8>,
    pub status: WorkerStatus,
    /// Host PID from the kernel's pidfd fdinfo, not a namespace-local PID.
    pub worker_pid: i32,
    pub stdout_eof: bool,
    pub state_eof: bool,
    pub reaped: bool,
    #[serde(skip)]
    pub elapsed: Duration,
}
impl WorkerResult {
    /// Successful lifecycle observation only; this cannot detect silent memory corruption.
    pub fn clean_exit(&self) -> bool {
        self.status == WorkerStatus::Exited { code: 0 }
            && self.stdout_eof
            && self.state_eof
            && self.reaped
    }
}

/// One sequential lane. Create multiple brokers before starting an async runtime
/// for parallel execution. A failed broker is never silently restarted.
pub struct WarmPool {
    control: UnixStream,
    launcher_pid: libc::pid_t,
    launcher_pidfd: OwnedFd,
    config: PoolConfig,
    healthy: bool,
}

fn os_check(ok: bool, context: &str) -> Result<()> {
    ensure!(ok, "{context}: {}", io::Error::last_os_error());
    Ok(())
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: scalar PID and zero flags; syscall returns a newly owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    os_check(fd >= 0, "pidfd_open")?;
    // SAFETY: successful pidfd_open transfers one new descriptor to OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn signal_pidfd(fd: RawFd, signal: i32) -> Result<()> {
    // SAFETY: caller owns a pidfd; null siginfo and zero flags satisfy the API.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        bail!("pidfd_send_signal: {}", io::Error::last_os_error());
    }
    Ok(())
}

fn wait_child(pid: i32) -> Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: status points to initialized writable storage; pid is our child.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(status);
        }
        if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        bail!("waitpid: {}", io::Error::last_os_error());
    }
}

fn close_other_fds(keep: &[RawFd]) -> Result<()> {
    let mut keep = keep.to_vec();
    keep.sort_unstable();
    keep.dedup();
    let mut start = 0u32;
    for fd in keep.into_iter().filter(|fd| *fd >= 0) {
        let fd = fd as u32;
        if start < fd {
            // SAFETY: close_range takes scalar descriptor bounds; keep fds are excluded.
            os_check(
                unsafe { libc::syscall(libc::SYS_close_range, start, fd - 1, 0) } == 0,
                "close_range",
            )?;
        }
        start = fd + 1;
    }
    // SAFETY: closes all remaining inherited descriptors above the last retained fd.
    os_check(
        unsafe { libc::syscall(libc::SYS_close_range, start, u32::MAX, 0) } == 0,
        "close_range",
    )
}

fn write_frame(stream: &mut UnixStream, data: &[u8]) -> Result<()> {
    let length = u32::try_from(data.len()).context("frame too large")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream, max: usize) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= max, "IPC frame exceeds limit");
    let mut data = vec![0; length];
    stream.read_exact(&mut data)?;
    Ok(data)
}

/// Native worker-side state protocol helper. The fd is the only state capability.
/// The broker did not inherit the backend connection, authentication key or credentials.
pub fn state_exchange(fd: RawFd, request: &[u8], max_response: usize) -> Result<Vec<u8>> {
    // SAFETY: dup borrows a live supplied descriptor and returns an independent owner.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    os_check(duplicate >= 0, "duplicate state fd")?;
    // SAFETY: successful fcntl returned a new owned Unix stream descriptor.
    let mut stream = unsafe { UnixStream::from_raw_fd(duplicate) };
    write_frame(&mut stream, request)?;
    read_frame(&mut stream, max_response)
}

// Ancillary messages are exactly one byte plus three descriptors. Aligned usize
// storage avoids unaligned cmsghdr access on strict-alignment architectures.
fn send_fds(stream: &UnixStream, fds: &[RawFd; 3]) -> Result<()> {
    let mut byte = *b"W";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0usize; 8];
    // SAFETY: zero is a valid initial representation for msghdr.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ancillary.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE computes storage requirements for three RawFd values.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of_val(fds) as u32) } as usize;
    ensure!(
        msg.msg_controllen <= mem::size_of_val(&ancillary),
        "ancillary allocation"
    );
    // SAFETY: aligned ancillary buffer has sufficient CMSG_SPACE and one cmsghdr.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast::<RawFd>(), 3);
        os_check(
            libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) == 1,
            "sendmsg",
        )?;
    }
    Ok(())
}

fn receive_fds(stream: &UnixStream) -> Result<[OwnedFd; 3]> {
    let mut byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0usize; 8];
    // SAFETY: zero initializes all unused optional msghdr members to null.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ancillary.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&ancillary);
    // SAFETY: iov and ancillary buffers are valid writable storage for this call.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    os_check(n >= 0, "recvmsg")?;
    // Own every received fd before checking metadata so malformed input cannot leak it.
    let mut received = Vec::new();
    // SAFETY: the kernel initialized msg_control up to msg_controllen; CMSG_NXTHDR
    // bounds each header. Descriptor payloads are copied as aligned integer values.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let base = libc::CMSG_LEN(0) as usize;
                ensure!((*cmsg).cmsg_len >= base, "bad control message length");
                let bytes = (*cmsg).cmsg_len - base;
                ensure!(
                    bytes.is_multiple_of(mem::size_of::<RawFd>()),
                    "bad rights payload"
                );
                for i in 0..bytes / mem::size_of::<RawFd>() {
                    received.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i),
                    )));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    ensure!(
        n == 1 && byte[0] == b'W' && msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0,
        "invalid worker capability message"
    );
    received.try_into().map_err(|fds: Vec<OwnedFd>| {
        anyhow::anyhow!("expected three capabilities, got {}", fds.len())
    })
}

#[repr(C)]
struct MountAttr {
    set: u64,
    clear: u64,
    propagation: u64,
    userns_fd: u64,
}

fn isolate_baseline(config: &PoolConfig) -> Result<()> {
    let root = CString::new(config.root.as_os_str().as_encoded_bytes())?;
    let slash = c"/";
    // SAFETY: null source/type/data with MS_PRIVATE|MS_REC is the documented
    // propagation operation on a valid NUL-terminated root mount path.
    os_check(
        unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as _,
                std::ptr::null(),
            )
        } == 0,
        "private mounts",
    )?;
    // SAFETY: valid path pointers and documented recursive bind mount arguments.
    os_check(
        unsafe {
            libc::mount(
                root.as_ptr(),
                root.as_ptr(),
                std::ptr::null(),
                (libc::MS_BIND | libc::MS_REC) as _,
                std::ptr::null(),
            )
        } == 0,
        "bind root",
    )?;
    let attr = MountAttr {
        set: 1 | 2 | 4 | 8,
        clear: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: mount_attr layout matches Linux UAPI; pointer remains valid for syscall.
    // AT_RECURSIVE=0x8000 ensures nested mountpoints are read-only too.
    os_check(
        unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                root.as_ptr(),
                0x8000u32,
                &attr,
                mem::size_of::<MountAttr>(),
            )
        } == 0,
        "recursive read-only root",
    )?;
    // SAFETY: valid root path and slash CString; caller runs in a private mount namespace.
    os_check(unsafe { libc::chroot(root.as_ptr()) } == 0, "chroot")?;
    // SAFETY: slash is a static valid NUL-terminated path in the new root.
    os_check(unsafe { libc::chdir(slash.as_ptr()) } == 0, "chdir")?;
    // SAFETY: null groups pointer with length zero clears all supplemental groups.
    os_check(
        unsafe { libc::setgroups(0, std::ptr::null()) } == 0,
        "clear groups",
    )?;
    // SAFETY: all three ids are configured unprivileged ids; no pointers involved.
    os_check(
        unsafe { libc::setresgid(config.gid, config.gid, config.gid) } == 0,
        "setresgid",
    )?;
    // SAFETY: set all user ids, dropping namespace root capabilities with uid 0.
    os_check(
        unsafe { libc::setresuid(config.uid, config.uid, config.uid) } == 0,
        "setresuid",
    )?;
    // SAFETY: scalar prctl command disallows future privilege gains.
    os_check(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "no_new_privs",
    )?;
    // SAFETY: scalar prctl command prevents cross-process reads via ptrace/proc mem.
    os_check(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "nondumpable",
    )?;
    // SAFETY: umask has no pointer arguments and confines all subsequently created files.
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}

fn install_worker_filter() -> Result<()> {
    // Default deny: workers can read their immutable rootfs, compute, use
    // inherited IPC, allocate, measure time and exit. No new sockets or processes.
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("seccomp profile supports x86_64 and aarch64 only");
    // SAFETY: both scalar calls read this single-threaded disposable child's
    // identifiers. Capture them before constructing the immutable seccomp policy.
    let (own_tgid, own_tid) = unsafe {
        (
            libc::getpid() as u32,
            libc::syscall(libc::SYS_gettid) as u32,
        )
    };
    ensure!(
        own_tgid > 1 && own_tid == own_tgid,
        "filter requires a single-threaded worker"
    );
    let allow = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_newfstatat,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_getcwd,
        libc::SYS_getdents64,
        libc::SYS_statx,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_shutdown,
        libc::SYS_ppoll,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getrandom,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_sched_yield,
        libc::SYS_restart_syscall,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_getrlimit,
        libc::SYS_uname,
        libc::SYS_getrusage,
        libc::SYS_times,
        libc::SYS_sysinfo,
    ];
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    let mut instructions = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
    ];
    // openat's flags are seccomp_data.args[2], low 32 bits at offset 32.
    // Writes are denied even before the recursively immutable root mount.
    instructions.extend([
        jump(libc::SYS_openat as u32, 0, 4),
        stmt(0x20, 32),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: (libc::O_WRONLY
                | libc::O_RDWR
                | libc::O_CREAT
                | libc::O_TRUNC
                | libc::O_APPEND
                | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32,
        },
        stmt(0x06, 0x80000000),
        stmt(0x06, 0x7fff0000),
    ]);
    // A worker may raise a signal only in itself. PHP installs signal handlers
    // in namespace PID1, so PID1's default signal immunity is not a sufficient
    // barrier against a same-uid child. Compare both halves of both arguments.
    instructions.extend([
        jump(libc::SYS_tgkill as u32, 0, 10),
        stmt(0x20, 16),
        jump(own_tgid, 0, 7),
        stmt(0x20, 20),
        jump(0, 0, 5),
        stmt(0x20, 24),
        jump(own_tid, 0, 3),
        stmt(0x20, 28),
        jump(0, 0, 1),
        stmt(0x06, 0x7fff0000),
        stmt(0x06, 0x80000000),
    ]);
    // F_SETOWN/F_SETSIG plus O_ASYNC would create another route for a worker
    // to signal namespace PID1 using its inherited socket. Permit descriptor
    // duplication/flags only; socketpairs start without an asynchronous owner.
    let mut fcntl_policy = vec![
        stmt(0x20, 28),
        jump(0, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 24),
    ];
    // F_SETFL may adjust nonblocking mode but must never enable asynchronous
    // signal delivery, even if an inherited descriptor unexpectedly has an owner.
    fcntl_policy.extend([
        jump(libc::F_SETFL as u32, 0, 7),
        stmt(0x20, 36),
        jump(0, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 32),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: libc::O_ASYNC as u32,
        },
        stmt(0x06, 0x80000000),
        stmt(0x06, 0x7fff0000),
    ]);
    for command in [
        libc::F_DUPFD,
        libc::F_DUPFD_CLOEXEC,
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
    ] {
        fcntl_policy.push(jump(command as u32, 0, 1));
        fcntl_policy.push(stmt(0x06, 0x7fff0000));
    }
    fcntl_policy.push(stmt(0x06, 0x80000000));
    instructions.push(jump(
        libc::SYS_fcntl as u32,
        0,
        u8::try_from(fcntl_policy.len())?,
    ));
    instructions.extend(fcntl_policy);
    // The openat branch leaves the accumulator intact for every other syscall.
    // prlimit64 is permitted only for a read of this worker's limits. Allowing
    // arbitrary pid/new_limit would let a worker damage its same-uid baseline.
    instructions.extend([
        jump(libc::SYS_prlimit64 as u32, 0, 10),
        stmt(0x20, 16),
        jump(0, 0, 7),
        stmt(0x20, 20),
        jump(0, 0, 5),
        stmt(0x20, 32),
        jump(0, 0, 3),
        stmt(0x20, 36),
        jump(0, 0, 1),
        stmt(0x06, 0x7fff0000),
        stmt(0x06, 0x80000000),
    ]);
    for syscall in allow {
        instructions.push(jump(syscall as u32, 0, 1));
        instructions.push(stmt(0x06, 0x7fff0000));
    }
    #[cfg(target_arch = "x86_64")]
    for syscall in [
        libc::SYS_poll,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_readlink,
        libc::SYS_access,
    ] {
        instructions.push(jump(syscall as u32, 0, 1));
        instructions.push(stmt(0x06, 0x7fff0000));
    }
    instructions.push(stmt(0x06, 0x80000000));
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len())?,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: valid sock_fprog and stable instruction slice for kernel copy; NNP is set.
    os_check(
        unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &program) } == 0,
        "install terminal seccomp",
    )
}

fn worker_resource_limits(config: &PoolConfig) -> Result<()> {
    for (resource, ceiling) in [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_FSIZE, 0),
        (libc::RLIMIT_AS, config.max_memory_bytes),
        (libc::RLIMIT_NOFILE, config.max_open_files),
        (libc::RLIMIT_CPU, config.max_cpu_seconds),
    ] {
        let limit = libc::rlimit {
            rlim_cur: ceiling as libc::rlim_t,
            rlim_max: ceiling as libc::rlim_t,
        };
        // SAFETY: live initialized rlimit; scalar resource selector is a known UAPI constant.
        os_check(
            unsafe { libc::setrlimit(resource, &limit) } == 0,
            "worker resource limit",
        )?;
    }
    Ok(())
}

fn child_exit(code: i32) -> ! {
    // SAFETY: direct _exit avoids running parent-owned Rust destructors after fork.
    unsafe { libc::_exit(code) }
}

fn broker(
    mut control: UnixStream,
    launcher_identity: OwnedFd,
    config: &PoolConfig,
    worker: Worker,
) -> Result<()> {
    isolate_baseline(config)?;
    // setresuid clears PDEATHSIG. Restore it after the final credential change,
    // then inspect the inherited stable parent identity to close the death race.
    // SAFETY: scalar prctl sets the signal delivered when the launcher disappears.
    os_check(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
        "baseline parent death",
    )?;
    let mut parent_poll = libc::pollfd {
        fd: launcher_identity.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: valid single pollfd; timeout zero only checks the pidfd death state.
    os_check(
        unsafe { libc::poll(&mut parent_poll, 1, 0) } == 0,
        "namespace launcher already died",
    )?;
    // MADV_DONTNEED is valid only on private anonymous scratch, never the warmed
    // interpreter image. Child teardown releases COW pages; there is no false
    // claim that madvise can rewind live process state.
    write_frame(&mut control, b"READY")?;
    loop {
        let request = match read_frame(&mut control, config.max_request) {
            Ok(request) => request,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let (out_parent, mut out_child) = UnixStream::pair()?;
        let (state_parent, state_child) = UnixStream::pair()?;
        // SAFETY: this broker was created before threads and remains single-threaded.
        let pid = unsafe { libc::fork() };
        os_check(pid >= 0, "warm fork")?;
        if pid == 0 {
            let run = || -> Result<()> {
                close_other_fds(&[out_child.as_raw_fd(), state_child.as_raw_fd()])?;
                // SAFETY: set parent death signal; broker is alive while owning control.
                os_check(
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
                    "worker parent death",
                )?;
                // SAFETY: getppid is scalar; namespace init must still be this child's parent.
                ensure!(unsafe { libc::getppid() } == 1, "broker died during fork");
                worker_resource_limits(config)?;
                install_worker_filter()?;
                let response = worker(&request, state_child.as_raw_fd());
                ensure!(response.len() <= config.max_output, "output limit");
                out_child.write_all(&response)?;
                drop(state_child);
                drop(out_child);
                Ok(())
            };
            child_exit(if run().is_ok() { 0 } else { 120 });
        }
        drop(out_child);
        drop(state_child);
        let worker_pidfd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(error) => {
                // SAFETY: pid is an unreaped child created immediately above.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let _ = wait_child(pid);
                return Err(error);
            }
        };
        if let Err(error) = send_fds(
            &control,
            &[
                out_parent.as_raw_fd(),
                state_parent.as_raw_fd(),
                worker_pidfd.as_raw_fd(),
            ],
        ) {
            let _ = signal_pidfd(worker_pidfd.as_raw_fd(), libc::SIGKILL);
            let _ = wait_child(pid);
            return Err(error);
        }
        drop(out_parent);
        drop(state_parent);
        // Retain the zombie until the manager has read host PID from pidfd
        // fdinfo. Reaping first can turn fdinfo's Pid into -1 for fast workers.
        // The manager kills this namespace if this control exchange fails.
        if read_frame(&mut control, 3)? != b"ACK" {
            let _ = signal_pidfd(worker_pidfd.as_raw_fd(), libc::SIGKILL);
            let _ = wait_child(pid);
            bail!("invalid worker identity acknowledgment");
        }
        let status = wait_child(pid)?;
        write_frame(&mut control, &status.to_be_bytes())?;
    }
}

impl WarmPool {
    pub fn start(mut config: PoolConfig, worker: Worker) -> Result<Self> {
        ensure!(
            fs::read_dir("/proc/self/task")?.count() == 1,
            "WarmPool::start must run before any threads, including Tokio"
        );
        // SAFETY: geteuid has no pointer arguments.
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "namespace broker requires root"
        );
        ensure!(
            config.uid != 0 && config.gid != 0,
            "worker uid/gid must be unprivileged"
        );
        ensure!(
            config.max_request > 0
                && config.max_request <= u32::MAX as usize
                && config.max_output > 0
                && config.max_state_frame > 0
                && config.max_state_frame <= u32::MAX as usize,
            "invalid IPC limits"
        );
        ensure!(
            config.max_memory_bytes > 0
                && config.max_open_files >= 16
                && config.max_open_files <= 4096
                && config.max_cpu_seconds > 0,
            "invalid worker resource limits"
        );
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy().to_ascii_uppercase();
            ensure!(
                !(name.starts_with("PG")
                    || name.starts_with("MYSQL")
                    || name.starts_with("REDIS")
                    || name.starts_with("DB_")
                    || name == "DATABASE_URL"),
                "database environment must be absent before snapshot: {name}"
            );
        }
        config.root = fs::canonicalize(&config.root).context("rootfs")?;
        let metadata = fs::metadata(&config.root)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "rootfs must be a root-owned directory without group/other write permission"
        );
        ensure!(
            config.root != std::path::Path::new("/"),
            "dedicated rootfs required"
        );
        let (parent, mut child) = UnixStream::pair()?;
        parent.set_read_timeout(Some(Duration::from_secs(10)))?;
        parent.set_write_timeout(Some(Duration::from_secs(10)))?;
        // SAFETY: getpid reads the current process identifier with no pointer arguments.
        let parent_pid = unsafe { libc::getpid() };
        // SAFETY: verified single-thread process; parent immediately owns launcher identity.
        let pid = unsafe { libc::fork() };
        os_check(pid >= 0, "fork namespace launcher")?;
        if pid == 0 {
            drop(parent);
            let mut setup = || -> Result<()> {
                close_other_fds(&[child.as_raw_fd()])?;
                // SAFETY: scalar prctl and parent PID check cover launcher death race.
                os_check(
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
                    "launcher parent death",
                )?;
                // SAFETY: getppid is scalar; identity check closes the fork/prctl race.
                ensure!(
                    unsafe { libc::getppid() } == parent_pid,
                    "manager died during fork"
                );
                // SAFETY: namespace flags only; affects this launcher and its descendants.
                os_check(
                    unsafe {
                        libc::unshare(
                            libc::CLONE_NEWPID
                                | libc::CLONE_NEWNS
                                | libc::CLONE_NEWNET
                                | libc::CLONE_NEWIPC
                                | libc::CLONE_NEWUTS,
                        )
                    } == 0,
                    "required namespaces",
                )?;
                // SAFETY: getpid is scalar; pidfd_open identifies this live launcher.
                let launcher_identity = pidfd_open(unsafe { libc::getpid() })?;
                // SAFETY: launcher remains single-threaded; child becomes namespace PID 1.
                let init = unsafe { libc::fork() };
                os_check(init >= 0, "fork namespace init")?;
                if init == 0 {
                    // SAFETY: parent-death signal is reset by fork and must be restored.
                    os_check(
                        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0,
                        "broker parent death",
                    )?;
                    let result = broker(child.try_clone()?, launcher_identity, &config, worker);
                    if let Err(error) = &result {
                        let _ = write_frame(&mut child, format!("ERROR:{error:#}").as_bytes());
                    }
                    child_exit(if result.is_ok() { 0 } else { 121 });
                }
                drop(child.try_clone()?);
                let status = wait_child(init)?;
                ensure!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "broker terminated abnormally"
                );
                Ok(())
            };
            let result = setup();
            if let Err(error) = &result {
                let _ = write_frame(&mut child, format!("ERROR:{error:#}").as_bytes());
            }
            child_exit(if result.is_ok() { 0 } else { 122 });
        }
        drop(child);
        let launcher_pidfd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(error) => {
                // SAFETY: pid is this process's unreaped launcher; cannot be reused yet.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let _ = wait_child(pid);
                return Err(error);
            }
        };
        let mut pool = Self {
            control: parent,
            launcher_pid: pid,
            launcher_pidfd,
            config,
            healthy: true,
        };
        let ready = read_frame(&mut pool.control, 4096).context("namespace broker startup")?;
        ensure!(
            ready == b"READY",
            "broker refused startup: {}",
            String::from_utf8_lossy(&ready)
        );
        pool.control.set_read_timeout(None)?;
        pool.control.set_write_timeout(None)?;
        Ok(pool)
    }

    pub fn execute(&mut self, request: &[u8], timeout: Duration) -> Result<WorkerResult> {
        self.execute_with_state(request, timeout, |_| bail!("state capability is disabled"))
    }

    pub fn execute_with_state<F>(
        &mut self,
        request: &[u8],
        timeout: Duration,
        handler: F,
    ) -> Result<WorkerResult>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let result = self.execute_inner(request, timeout, handler);
        if result.is_err() {
            self.healthy = false;
            let _ = signal_pidfd(self.launcher_pidfd.as_raw_fd(), libc::SIGKILL);
        }
        result
    }

    fn execute_inner<F>(
        &mut self,
        request: &[u8],
        timeout: Duration,
        mut handler: F,
    ) -> Result<WorkerResult>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        ensure!(self.healthy, "broker is no longer healthy");
        ensure!(
            request.len() <= self.config.max_request,
            "request limit exceeded"
        );
        ensure!(!timeout.is_zero(), "zero deadline");
        let start = Instant::now();
        let deadline = start.checked_add(timeout).context("deadline overflow")?;
        // Start/control transfer is bounded as well as child execution.
        self.control.set_read_timeout(Some(timeout))?;
        self.control.set_write_timeout(Some(timeout))?;
        if let Err(error) = write_frame(&mut self.control, request) {
            self.healthy = false;
            let _ = signal_pidfd(self.launcher_pidfd.as_raw_fd(), libc::SIGKILL);
            return Err(error.context("dispatch worker"));
        }
        let capabilities = match receive_fds(&self.control) {
            Ok(fds) => fds,
            Err(error) => {
                self.healthy = false;
                let _ = signal_pidfd(self.launcher_pidfd.as_raw_fd(), libc::SIGKILL);
                return Err(error.context("receive worker capabilities"));
            }
        };
        let [out_fd, state_fd, pidfd] = capabilities;
        let host_pid = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t").and_then(|s| s.parse().ok()))
            .context("pidfd has no host PID")?;
        ensure!(host_pid > 0, "worker pidfd identity was already reaped");
        write_frame(&mut self.control, b"ACK").context("acknowledge worker identity")?;
        let mut output = UnixStream::from(out_fd);
        let mut state = UnixStream::from(state_fd);
        output.set_nonblocking(true)?;
        state.set_nonblocking(true)?;
        let mut output_bytes = Vec::new();
        let mut state_bytes = Vec::new();
        let mut pending = Vec::new();
        let mut sent = 0;
        let mut output_eof = false;
        let mut state_eof = false;
        let mut override_status = None;
        let mut killed = false;
        let mut reaped = false;
        let mut observed_status = None;
        let mut status_bytes = Vec::new();
        self.control.set_nonblocking(true)?;
        let cleanup_deadline = deadline
            .checked_add(Duration::from_secs(2))
            .context("deadline overflow")?;
        while !(reaped && output_eof && state_eof) {
            let now = Instant::now();
            if now >= deadline && !killed {
                override_status.get_or_insert(WorkerStatus::TimedOut);
                signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL)?;
                killed = true;
                let _ = state.shutdown(std::net::Shutdown::Both);
            }
            if now >= cleanup_deadline {
                self.healthy = false;
                let _ = signal_pidfd(self.launcher_pidfd.as_raw_fd(), libc::SIGKILL);
                override_status = Some(WorkerStatus::ProtocolFailure {
                    message: "broker failed to reap before cleanup deadline".into(),
                });
                break;
            }
            let mut polls = [
                libc::pollfd {
                    fd: if output_eof { -1 } else { output.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if state_eof { -1 } else { state.as_raw_fd() },
                    events: libc::POLLIN
                        | if sent < pending.len() {
                            libc::POLLOUT
                        } else {
                            0
                        },
                    revents: 0,
                },
                libc::pollfd {
                    fd: if reaped { -1 } else { self.control.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let until = if killed { cleanup_deadline } else { deadline };
            let ms = until
                .saturating_duration_since(now)
                .as_millis()
                .saturating_add(1)
                .min(100) as i32;
            // SAFETY: valid pollfd slice and bounded scalar timeout; kernel writes only revents.
            let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, ms) };
            if rc < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                    message: format!("poll: {}", io::Error::last_os_error()),
                });
            }
            if polls[0].revents != 0 {
                match drain(&mut output, &mut output_bytes, self.config.max_output) {
                    Ok(eof) => output_eof = eof,
                    Err(error) => {
                        override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                            message: error.to_string(),
                        });
                    }
                }
            }
            if polls[1].revents != 0 {
                if polls[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    match drain(
                        &mut state,
                        &mut state_bytes,
                        self.config.max_state_frame + 4,
                    ) {
                        Ok(eof) => state_eof = eof,
                        Err(error) => {
                            override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                                message: error.to_string(),
                            });
                        }
                    }
                }
                if sent == pending.len() && state_bytes.len() >= 4 && override_status.is_none() {
                    let length = u32::from_be_bytes(state_bytes[..4].try_into()?) as usize;
                    if length > self.config.max_state_frame {
                        override_status = Some(WorkerStatus::ProtocolFailure {
                            message: "state frame limit".into(),
                        });
                    } else if state_bytes.len() >= length + 4 {
                        match handler(&state_bytes[4..length + 4]) {
                            Ok(reply) if reply.len() <= self.config.max_state_frame => {
                                pending = (reply.len() as u32).to_be_bytes().to_vec();
                                pending.extend_from_slice(&reply);
                                sent = 0;
                                state_bytes.drain(..length + 4);
                            }
                            Ok(_) => {
                                override_status = Some(WorkerStatus::VerifierFailed {
                                    message: "state reply limit".into(),
                                })
                            }
                            Err(error) => {
                                override_status = Some(WorkerStatus::VerifierFailed {
                                    message: format!("{error:#}"),
                                })
                            }
                        }
                    }
                }
                while sent < pending.len() {
                    match state.write(&pending[sent..]) {
                        Ok(0) => {
                            override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                                message: "state reply disconnected".into(),
                            });
                            break;
                        }
                        Ok(n) => sent += n,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                                message: error.to_string(),
                            });
                            break;
                        }
                    }
                }
                if state_eof && (!state_bytes.is_empty() || sent != pending.len()) {
                    override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                        message: "truncated state exchange".into(),
                    });
                }
            }
            if polls[2].revents != 0 {
                match drain(&mut self.control, &mut status_bytes, 8) {
                    Ok(true) => {
                        self.healthy = false;
                        override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                            message: "broker disconnected".into(),
                        });
                    }
                    Ok(false) => {}
                    Err(error) => {
                        self.healthy = false;
                        override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                            message: error.to_string(),
                        });
                    }
                }
                if status_bytes.len() == 8 {
                    if status_bytes[..4] == 4u32.to_be_bytes() {
                        let status = i32::from_be_bytes(status_bytes[4..].try_into()?);
                        observed_status = Some(decode_status(status)?);
                        reaped = true;
                    } else {
                        override_status.get_or_insert(WorkerStatus::ProtocolFailure {
                            message: "invalid reap receipt".into(),
                        });
                    }
                }
            }
            if override_status.is_some() && !killed {
                signal_pidfd(pidfd.as_raw_fd(), libc::SIGKILL)?;
                killed = true;
                let _ = state.shutdown(std::net::Shutdown::Both);
            }
        }
        self.control.set_nonblocking(false)?;
        self.control.set_read_timeout(None)?;
        self.control.set_write_timeout(None)?;
        if Instant::now() >= deadline {
            override_status.get_or_insert(WorkerStatus::TimedOut);
        }
        let status = override_status
            .or(observed_status)
            .context("missing worker status")?;
        Ok(WorkerResult {
            output: output_bytes,
            status,
            worker_pid: host_pid,
            stdout_eof: output_eof,
            state_eof,
            reaped,
            elapsed: start.elapsed(),
        })
    }
}

fn drain(stream: &mut UnixStream, target: &mut Vec<u8>, max: usize) -> Result<bool> {
    let mut bytes = [0u8; 8192];
    loop {
        match stream.read(&mut bytes) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                ensure!(
                    target.len().checked_add(n).is_some_and(|n| n <= max),
                    "IPC output limit"
                );
                target.extend_from_slice(&bytes[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn decode_status(status: i32) -> Result<WorkerStatus> {
    if libc::WIFEXITED(status) {
        Ok(WorkerStatus::Exited {
            code: libc::WEXITSTATUS(status),
        })
    } else if libc::WIFSIGNALED(status) {
        Ok(WorkerStatus::Signaled {
            signal: libc::WTERMSIG(status),
            core_dumped: libc::WCOREDUMP(status),
        })
    } else {
        bail!("nonterminal wait status")
    }
}

impl Drop for WarmPool {
    fn drop(&mut self) {
        // Killing the launcher kills namespace PID1 via PDEATHSIG; the kernel then
        // destroys every process in that PID namespace. Stable pidfd avoids PID reuse.
        let _ = signal_pidfd(self.launcher_pidfd.as_raw_fd(), libc::SIGKILL);
        let _ = wait_child(self.launcher_pid);
    }
}

/// Optional Tokio bridge. Cancellation does not cancel a request in progress:
/// its dedicated blocking task continues to the mandatory deadline/reap barrier.
/// The caller must retain the ledger session in the closure until this returns.
pub async fn execute_async<F>(
    pool: std::sync::Arc<std::sync::Mutex<WarmPool>>,
    request: Vec<u8>,
    timeout: Duration,
    handler: F,
) -> Result<WorkerResult>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        pool.lock()
            .map_err(|_| anyhow::anyhow!("pool lock poisoned"))?
            .execute_with_state(&request, timeout, handler)
    })
    .await
    .context("worker manager task")?
}

/// Exercises private-page discard correctly: scratch is not the live baseline.
pub fn discard_scratch_pages(bytes: usize) -> Result<()> {
    ensure!(bytes > 0, "scratch size must be positive");
    // SAFETY: anonymous mapping requests private writable storage, fd=-1 offset=0.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    ensure!(
        address != libc::MAP_FAILED,
        "scratch mmap: {}",
        io::Error::last_os_error()
    );
    // SAFETY: mapping is valid and exclusively owned for bytes bytes.
    unsafe {
        std::ptr::write_bytes(address.cast::<u8>(), 0xa5, bytes);
    }
    // SAFETY: whole live anonymous private mapping; DONTNEED discards private pages.
    let rc = unsafe { libc::madvise(address, bytes, libc::MADV_DONTNEED) };
    let error = io::Error::last_os_error();
    // SAFETY: unmaps precisely the live owned mapping after its final use.
    let unmap = unsafe { libc::munmap(address, bytes) };
    ensure!(rc == 0, "scratch madvise: {error}");
    os_check(unmap == 0, "scratch munmap")
}
