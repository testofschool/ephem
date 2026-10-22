//! Mandatory cgroup-v2 request ownership. The gate never enters these cgroups.
use anyhow::{bail, ensure, Context, Result};
use nix::libc;
use std::{
    ffi::{CString, OsStr},
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

pub struct ResourceRoot {
    directory: File,
    memory_max: u64,
    cpu_quota_us: u64,
    cpu_period_us: u64,
}

pub struct RequestCgroup<'a> {
    root: &'a ResourceRoot,
    directory: File,
    attach: File,
    kill: File,
    name: CString,
    removed: bool,
}

fn open_at(directory: &File, name: &OsStr, flags: libc::c_int) -> Result<File> {
    let name = CString::new(name.as_bytes())?;
    // SAFETY: borrowed directory fd and valid, NUL-terminated relative filename.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    ensure!(
        fd >= 0,
        "open cgroup control: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: openat returned a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_control(directory: &File, name: &str) -> Result<String> {
    let mut value = String::new();
    open_at(directory, OsStr::new(name), libc::O_RDONLY)?
        .take(65537)
        .read_to_string(&mut value)?;
    ensure!(value.len() <= 65536, "oversized cgroup control");
    Ok(value)
}

fn write_control(directory: &File, name: &str, value: &str) -> Result<()> {
    open_at(directory, OsStr::new(name), libc::O_WRONLY)?
        .write_all(value.as_bytes())
        .with_context(|| format!("configure {name}"))
}

fn configure(directory: &File, name: &str, value: &str) -> Result<()> {
    write_control(directory, name, value)?;
    ensure!(
        read_control(directory, name)?.trim() == value,
        "cgroup {name} did not retain the configured limit"
    );
    Ok(())
}

fn control_counter(value: &str, key: &str) -> Result<u64> {
    let mut found = None;
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(key) {
            ensure!(found.is_none(), "duplicate cgroup counter");
            found = Some(fields.next().context("missing cgroup counter")?.parse()?);
            ensure!(fields.next().is_none(), "invalid cgroup counter");
        }
    }
    found.context("required cgroup counter absent")
}

/// Narrow host policy: anonymous request buffers and memfd data must not swap,
/// and a piped core handler must never persist a worker's private memory.
pub fn secure_host_memory() -> Result<()> {
    // SAFETY: these identity queries have no memory safety preconditions.
    ensure!(
        unsafe { libc::getuid() == 0 && libc::geteuid() == 0 },
        "gate requires root"
    );
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: zero points to an initialized rlimit; PR_SET_DUMPABLE takes an integer.
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } == 0,
        "cannot disable gate core dumps"
    );
    // SAFETY: documented integer argument to PR_SET_DUMPABLE.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "cannot disable gate dumpability"
    );
    let swaps = fs::read_to_string("/proc/swaps").context("inspect host swap")?;
    ensure!(
        swaps
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("Filename")),
        "unrecognized /proc/swaps format"
    );
    ensure!(
        !swaps.lines().skip(1).any(|line| !line.trim().is_empty()),
        "active host swap is unsupported; use a dedicated no-swap host"
    );
    let core_pattern =
        fs::read_to_string("/proc/sys/kernel/core_pattern").context("inspect host core handler")?;
    ensure!(
        !core_pattern.trim_start().starts_with('|'),
        "piped host core handlers are unsupported"
    );
    Ok(())
}

impl ResourceRoot {
    pub fn open(
        path: &Path,
        memory_max: u64,
        cpu_quota_us: u64,
        cpu_period_us: u64,
    ) -> Result<Self> {
        ensure!(path.is_absolute(), "cgroup root must be absolute");
        let mut ancestor = std::path::PathBuf::new();
        for component in path.components() {
            ensure!(
                matches!(component, Component::RootDir | Component::Normal(_)),
                "cgroup root must be canonical"
            );
            ancestor.push(component.as_os_str());
            let meta = fs::symlink_metadata(&ancestor).context("inspect cgroup ancestry")?;
            ensure!(
                meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0,
                "cgroup ancestry must be root-owned and not group/world writable"
            );
        }
        ensure!(
            fs::canonicalize(path)? == path,
            "cgroup root must be canonical"
        );
        let path_c = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: valid NUL-terminated absolute path with no symlink ancestry.
        let fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        ensure!(
            fd >= 0,
            "open cgroup root: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful open returned a new descriptor owned by this File.
        let directory = unsafe { File::from_raw_fd(fd) };
        // SAFETY: statfs is a plain C structure and fstatfs initializes it.
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid directory descriptor and writable statfs pointer.
        ensure!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } == 0,
            "inspect cgroup filesystem"
        );
        ensure!(
            filesystem.f_type == CGROUP2_SUPER_MAGIC,
            "cgroup root must be on cgroup v2"
        );
        ensure!(
            read_control(&directory, "cgroup.type")?.trim() == "domain",
            "cgroup root must be a domain"
        );
        for control in ["cgroup.controllers", "cgroup.subtree_control"] {
            let available = read_control(&directory, control)?;
            for required in ["memory", "pids", "cpu"] {
                ensure!(
                    available.split_whitespace().any(|item| item == required),
                    "required {required} controller unavailable or disabled in {control}"
                );
            }
        }
        ensure!(
            read_control(&directory, "cgroup.procs")?.trim().is_empty(),
            "cgroup root must contain no processes"
        );
        Ok(Self {
            directory,
            memory_max,
            cpu_quota_us,
            cpu_period_us,
        })
    }

    pub fn create(&self) -> Result<RequestCgroup<'_>> {
        let mut id = NEXT_SCOPE.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).context("request cgroup id exhausted")?;
            match NEXT_SCOPE.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }
        // Exclusive mkdir: an old request's directory is never adopted or killed.
        // SAFETY: getpid has no memory safety preconditions.
        let name = CString::new(format!("request-{}-{id}", unsafe { libc::getpid() }))?;
        // SAFETY: pinned root directory and valid single-component child name.
        ensure!(
            unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } == 0,
            "create request cgroup: {}",
            std::io::Error::last_os_error()
        );
        let result = (|| {
            let directory = open_at(
                &self.directory,
                OsStr::from_bytes(name.as_bytes()),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let attach = open_at(&directory, OsStr::new("cgroup.procs"), libc::O_WRONLY)?;
            let kill = open_at(&directory, OsStr::new("cgroup.kill"), libc::O_WRONLY)?;
            let scope = RequestCgroup {
                root: self,
                directory,
                attach,
                kill,
                name: name.clone(),
                removed: false,
            };
            configure(&scope.directory, "memory.max", &self.memory_max.to_string())?;
            configure(&scope.directory, "memory.swap.max", "0")?;
            configure(&scope.directory, "memory.oom.group", "1")?;
            configure(&scope.directory, "pids.max", "2")?;
            configure(
                &scope.directory,
                "cpu.max",
                &format!("{} {}", self.cpu_quota_us, self.cpu_period_us),
            )?;
            // New cgroups start empty and with fresh counters. Require both controls.
            ensure!(!scope.populated()?, "new request cgroup is populated");
            scope.check_oom()?;
            Ok(scope)
        })();
        if result.is_err() {
            // Nothing has been attached if opening/configuration failed. A scope
            // constructed above additionally runs its owned cleanup on drop.
            // SAFETY: only our exclusively created child under the pinned root.
            unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
        result
    }
}

impl RequestCgroup<'_> {
    pub fn attach_fd(&self) -> RawFd {
        self.attach.as_raw_fd()
    }

    fn populated(&self) -> Result<bool> {
        match control_counter(
            &read_control(&self.directory, "cgroup.events")?,
            "populated",
        )? {
            0 => Ok(false),
            1 => Ok(true),
            _ => bail!("invalid cgroup populated value"),
        }
    }

    fn check_oom(&self) -> Result<()> {
        let events = read_control(&self.directory, "memory.events")?;
        ensure!(
            control_counter(&events, "oom")? == 0 && control_counter(&events, "oom_kill")? == 0,
            "request encountered cgroup OOM"
        );
        Ok(())
    }

    fn kill_owned(&mut self) -> Result<()> {
        // A pre-opened cgroup.kill belongs only to the child created by this gate.
        self.kill.write_all(b"1")?;
        Ok(())
    }

    fn remove_owned(&mut self) -> Result<()> {
        // SAFETY: pinned root fd and the name exclusively created for this request.
        ensure!(
            unsafe {
                libc::unlinkat(
                    self.root.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } == 0,
            "remove empty request cgroup: {}",
            std::io::Error::last_os_error()
        );
        self.removed = true;
        Ok(())
    }

    /// Disposal is completed and OOM counters verified before a response escapes.
    pub async fn finish(&mut self) -> Result<()> {
        self.kill_owned().context("kill request cgroup")?;
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while self.populated()? {
            ensure!(
                Instant::now() < deadline,
                "request cgroup did not become empty"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let accounting = (|| -> Result<(u64, u64, u64)> {
            let events = read_control(&self.directory, "memory.events")?;
            let peak = read_control(&self.directory, "memory.peak")?
                .trim()
                .parse()?;
            Ok((
                control_counter(&events, "oom")?,
                control_counter(&events, "oom_kill")?,
                peak,
            ))
        })();
        self.remove_owned()?;
        let (oom, oom_kill, memory_peak_bytes) = accounting?;
        // Fixed resource accounting only, after confirmed disposal. This allows
        // kernel OOM and cleanup proofs without persisting request fingerprints.
        eprintln!(
            "{}",
            serde_json::json!({
                "resource_scope": self.name.to_string_lossy(),
                "memory_peak_bytes": memory_peak_bytes,
                "oom": oom,
                "oom_kill": oom_kill,
                "disposed": true,
            })
        );
        ensure!(oom == 0 && oom_kill == 0, "request encountered cgroup OOM");
        Ok(())
    }
}

impl Drop for RequestCgroup<'_> {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        // Cancellation and setup failures get the same ownership-scoped kill.
        // This bounded fallback never signals a numeric host PID or the parent.
        let result = (|| -> Result<()> {
            self.kill_owned()?;
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            while self.populated()? {
                ensure!(Instant::now() < deadline, "request cleanup deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            self.remove_owned()
        })();
        if result.is_err() {
            eprintln!("request cgroup cleanup failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_strict_and_required() {
        assert_eq!(
            control_counter("low 0\noom 1\noom_kill 0\n", "oom").unwrap(),
            1
        );
        for value in ["", "oom\n", "oom nope\n", "oom 0 1\n", "oom 0\noom 0\n"] {
            assert!(control_counter(value, "oom").is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn regular_filesystem_and_relative_roots_fail_closed() {
        assert!(ResourceRoot::open(Path::new("relative"), 134217728, 100000, 100000).is_err());
        assert!(ResourceRoot::open(Path::new("/"), 134217728, 100000, 100000).is_err());
    }
}
