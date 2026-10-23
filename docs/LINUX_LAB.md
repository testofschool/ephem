# Isolated Linux lab

This local lab provides real Linux kernel execution on the macOS arm64 host. It is a test environment; it does not establish production readiness or a comparative world ranking.

## Verified environment

The dedicated Lima `ephem` VM uses Apple's VZ backend, 4 virtual CPUs, 4 GiB RAM and a 16 GiB virtual disk. VM state, generated VM-only SSH keys and local logs reside in `.runtime/ephem-lab/lima`; that directory is ignored by Git. No preexisting Docker container or VM was changed. The only new host package is Homebrew Lima 2.2.1; Homebrew also refreshed its own package metadata and portable Ruby runtime.

| Item | Observed value |
| --- | --- |
| Guest | Ubuntu 24.04 arm64 minimal image, release 2026-10-01 |
| Image SHA-256 | `fbf6b15c50c474dc6dee5b3c74da212bb687a2625e877227828e6492d88dc151` |
| Kernel | `6.8.0-146-generic`, aarch64 |
| Landlock | ABI 4 from `landlock_create_ruleset(..., VERSION)` |
| pidfd | `pidfd_open` for the probe process succeeded |
| seccomp | `SECCOMP_GET_ACTION_AVAIL` accepted `KILL_PROCESS` |
| Namespace probe | root-created PID, network, mount, IPC and UTS namespaces succeeded |
| Rust | rustc 1.99.1; cargo 1.99.1 via rustup minimal profile |
| Native tools | GCC 13.3.0; libseccomp development package 2.5.5; Python 3; strace |
| Host mounts | none; Lima plain mode and `mounts: []` |
| Host listeners | VM helper listeners observed on `127.0.0.1:64064` and `127.0.0.1:64065` only |

The guest's original `kernel.apparmor_restrict_unprivileged_userns=1` was briefly set to `0` for an unprivileged namespace probe and restored to `1`. Runtime tests use a privileged launcher and do not require this relaxation. No host sysctl was changed.

The initial `limactl start` command timed out after 10 minutes while waiting for its final running-status event. The guest had already finished cloud-init successfully, accepted direct shell commands and completed the real Linux tests. A fresh `limactl list` still reports the dedicated VM as Running; the sanitized snapshot is `reports/ephem/linux-lima-status-v4.json`. This is an orchestration/readiness-event failure recorded in `start.log`, separate from the executed Linux test outcomes.

Lima plain mode disables ordinary host mounts, dynamic application port forwarding and containerd. The VM can download packages through its user network. Guest root remains trusted; this lab does not claim to isolate a malicious guest kernel from the host. Generated VM SSH keys are local connection machinery and must not be published with evidence.

## Reproduce locally

Install Lima with `brew install lima`. The public-image provisioning configuration is checked in as `packaging/lima-lab.yaml`; its pinned release URL may need a separately audited replacement after Ubuntu removes old images. The local pinned image, VM YAML and helper are in `.runtime/ephem-lab` for this run. The VM was created with:

```sh
LIMA_HOME=/Users/felix/Desktop/php2shell/.runtime/ephem-lab/lima \
  limactl start --tty=false --name=ephem --mount-none \
  .runtime/ephem-lab/ephem.yaml
```

The YAML installs Ubuntu build packages through `apt-get` and disables home mounts, SSH agent forwarding, host SSH public-key loading, containerd and application port forwarding. Rustup was then installed inside the VM using the official HTTPS installer, `--profile minimal --no-modify-path`; the default Ubuntu Rust 1.75 packages remain installed separately. Commands explicitly select the rustup toolchain:

```sh
.runtime/ephem-lab/lab.sh copy Cargo.toml Cargo.lock ephem:/home/felix.guest/ephem-work/
.runtime/ephem-lab/lab.sh copy -r crates bpf packaging tests ephem:/home/felix.guest/ephem-work/
.runtime/ephem-lab/lab.sh shell bash -lc \
  'PATH=/home/felix.guest/.cargo/bin:$PATH cargo build --locked --release -p ephem-gate'
.runtime/ephem-lab/lab.sh shell sudo sh packaging/build-jail.sh
```

The helper's `shell` action uses `/home/felix.guest/ephem-work` as the working directory. `copy` uses Lima SCP/rsync and has no shared host mount. Use `lab.sh copy ephem:/absolute/guest/file /absolute/host/file` to retrieve a specific result. Privileged test commands use `lab.sh shell sudo ...`; the host user is not made root.

For a new checkout, create the task-local state directory and substitute `packaging/lima-lab.yaml` for the local YAML in the creation command. Set `LIMA_HOME` to that checkout's absolute `.runtime/ephem-lab/lima` directory for each `limactl` command, then use `limactl shell --workdir=/home/felix.guest/ephem-work ephem ...` and `limactl copy ...` directly. Install Rust 1.99.1 inside the VM with the official rustup installer and `--default-toolchain 1.99.1 --profile minimal --no-modify-path` to match this run. The provisioning file installs no production application or service.

The initial gate release build succeeded. The first `cargo test --workspace` completed with **0 tests**. After two CGI parser tests were added, `cargo test --locked --workspace` completed with **2 passed, 0 failed**; raw output is in `reports/ephem/linux-rust-tests-v2.*`. These unit tests provide no lifecycle or containment evidence. Those conclusions must come from the separate Linux runtime suite and its recorded source hashes.

## Local evidence

The run keeps `start.log`, `rustup.log`, `gate-build.log`, `gate-test.log`, `capabilities.log`, `final-environment.log` and `vm-metadata.json` under `.runtime/ephem-lab`. Initial capability logs precede the restored AppArmor value; `final-environment.log` records the final setting. Export only intended logs and reports, never the Lima state directory or generated keys.

Operational references: [Lima CLI](https://lima-vm.io/docs/reference/limactl_start/), [Lima plain mode](https://lima-vm.io/docs/config/plain/), [Lima filesystem mounts](https://lima-vm.io/docs/config/mount/), [official Rust installation](https://rust-lang.org/tools/install/).
