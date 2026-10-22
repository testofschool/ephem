# Operate and reproduce ephem

Use a dedicated Linux test VM first. This is an experimental privileged runtime: the gate and launcher run as root, workers share the host kernel, and production qualification remains on hold. The commands below build source, create disposable fixture roots and exercise the actual Linux boundary. They do not activate an existing application or configure public ingress.

## Host and build requirements

Use Linux x86-64 or AArch64 with cgroup v2, `clone3`, pidfds, recursive `mount_setattr`, seccomp user notification and Landlock ABI 3 or later. The operator needs namespace/mount/credential privileges. A restrictive container may refuse these features; refusal is a failed prerequisite, not permission to bypass isolation.

The gate requires readable `/proc/swaps` with no active swap entries and a readable, non-piped `/proc/sys/kernel/core_pattern`. Its cgroup root must be an empty, root-owned domain with `cpu`, `memory` and `pids` controllers available and enabled for children. The gate disables its own dumpability and core limit. The launcher checks the core-handler policy again before jail setup: ordinary exec can reset worker dumpability, and a piped host collector can ignore `RLIMIT_CORE=0`.

Provision the VM without swap. Do not disable production security or diagnostic services to satisfy this prototype. Host administrators must maintain the qualified policy while the gate runs. Hibernation, kernel crash dumps, host compromise and physical RAM recovery are outside this contract.

On an Ubuntu-style fixture VM, install the build tools from a root shell:

```sh
apt-get update
apt-get install -y build-essential linux-libc-dev pkg-config python3 ca-certificates curl
```

Install Rust using the [official rustup installer](https://rustup.rs/) for the account that builds the repository. `rust-toolchain.toml` pins Rust 1.99.1 with the standard library, Cargo, rustfmt and Clippy. Distribution Rust packages may differ from that pin. No Python packages or eBPF/libbpf toolchain are required; the active filter is classic seccomp-BPF compiled with the C launcher.

Place the checkout in a trusted, root-owned path such as `/root/ephem`. All binary, rootfs and socket ancestors used by the wrapper must be root-owned and not writable by group or others. The test harness creates its disposable roots under `/root`; a rootfs under world-writable `/tmp` is intentionally refused.

```sh
cd /root/ephem
rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy
cargo build --release --locked -p ephem-gate
sh packaging/build-jail.sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Build outputs are `target/release/ephem-gate` and `target/ephem-jail`. Rebuild for the target architecture and libc; a binary from a different host is not portable by assumption.

## Prepare the isolated fixture host

Inspect host policy before running the suite:

```sh
cat /proc/swaps
cat /proc/sys/kernel/core_pattern
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

`/proc/swaps` must contain only its header. In this dedicated VM, explicitly enable the controllers that the cgroup helper expects at the hierarchy root:

```sh
printf '+cpu +memory +pids\n' > /sys/fs/cgroup/cgroup.subtree_control
```

If the kernel or VM manager refuses that operation, stop and provision a compatible isolated host. The helper does not enable root controllers or move unrelated processes.

An isolated fixture VM may have a piped core collector by default. An operator who deliberately chooses a temporary fixture-host profile can save that setting, use a local file pattern for the run, and restore it on shell exit:

```sh
# Root shell, dedicated disposable VM, repository working directory.
# Choose a new absolute evidence directory for every attempt.
(
    set -eu
    ephem_saved_core_pattern=$(cat /proc/sys/kernel/core_pattern)
    trap 'printf "%s\n" "$ephem_saved_core_pattern" > /proc/sys/kernel/core_pattern' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    printf 'core\n' > /proc/sys/kernel/core_pattern
    ./scripts/validate-linux.sh /root/ephem-evidence/run-001
)
```

This changes a VM-wide diagnostic setting for the owned fixture run. Do not apply that profile to a shared or production machine. The script itself never changes swap or core sysctls. An uncatchable shell/VM failure cannot execute a restoration trap; retain the original policy in VM provisioning or a snapshot as well.

When the host already meets the policy, run directly as root:

```sh
./scripts/validate-linux.sh /root/ephem-evidence/run-002
```

The report directory must not exist. The script creates a new `/sys/fs/cgroup/ephem-test-PID` subtree, then runs lifecycle, boundary, direct seccomp and negative-preflight checks. It preserves JSON, preregistrations and stdout/stderr. Read the reports and process exit status; source hashes and passing fixture cases establish the stated experiment, not an external security audit or production approval. A failing run must retain its evidence and receive a new directory on retry.

The lifecycle suite uses real Linux workers: it checks fresh processes, identity/FD/capability restrictions, temporary state disposal, rejected execution/output paths, concurrency, a cgroup-memory failure, and the fact that a readable synthetic secret can still leave in an allowed response. The boundary suite separately uses a disposable chroot control and owned process identities. These are named probes, not exhaustive kernel escape testing.

Native macOS cannot run this Linux boundary. Direct lifecycle invocation reports unavailable and exits **77**; that result is not a pass:

```sh
python3 tests/test_ephemeral_lifecycle.py --cgroup-root /sys/fs/cgroup/unused
```

## Run the one-shot demonstration

Keep the same no-swap/non-piped-core host policy for the entire gate lifetime. From the root-owned checkout, prepare new fixture paths and a new cgroup:

```sh
sh packaging/prepare-cgroup.sh /sys/fs/cgroup/ephem-demo
sh tests/ephem/build-rootfs.sh /root/ephem-demo-rootfs
install -d -m 0700 /run/ephem-demo

EPHEM_GATE="$PWD/target/release/ephem-gate" \
EPHEM_JAIL="$PWD/target/ephem-jail" \
EPHEM_ROOT=/root/ephem-demo-rootfs \
EPHEM_WORKER=/worker \
EPHEM_SOCKET=/run/ephem-demo/gate.sock \
EPHEM_CGROUP_ROOT=/sys/fs/cgroup/ephem-demo \
  packaging/entrypoint.sh --deadline-ms 1000 --max-inflight 4
```

From another root shell in the same VM:

```sh
curl --fail --show-error --unix-socket /run/ephem-demo/gate.sock \
  --data-binary 'ECHO hello' http://localhost/run
```

The response body is `hello`. The socket accepts one bounded `POST /run HTTP/1.1` request with Host and Content-Length. It is mode 0600; the caller must satisfy that local permission boundary. There is no public TCP listener or automatic reverse-proxy configuration. An existing socket is refused rather than removed.

The fixture root intentionally contains only synthetic material. A real workload needs a separately curated, secret-free rootfs with its executable and dependencies. The wrapper refuses symlinks and nested mounts in that tree, and cannot make concurrently mutable administrative inputs trustworthy. Mounting the gate/launcher can avoid an application image rebuild, but host preparation, routing, protocol compatibility and operational review still cost work.

## Understand the resource budgets

`packaging/prepare-cgroup.sh` accepts a **new direct child** of `/sys/fs/cgroup`. It refuses an existing subtree. Its demonstration defaults are:

| Boundary | Configured value |
| --- | --- |
| All request launchers/workers in the helper subtree | `memory.max=536870912` (512 MiB) |
| Aggregate worker swap | `memory.swap.max=0` |
| Aggregate tasks | `pids.max=16` |
| Aggregate CPU | `cpu.max=200000 100000` (two CPU equivalents) |
| Each request, gate defaults | 128 MiB memory, no swap, two tasks, one CPU equivalent |

The gate remains outside the request subtree. Its input vectors, response memfds, response copies and runtime memory are not covered by that 512 MiB worker budget. Put the supervisor in a separately bounded service cgroup. For a systemd-managed gate, a starting policy to qualify with the actual workload is:

```ini
[Service]
MemoryMax=256M
MemorySwapMax=0
LimitCORE=0
```

These are configuration recommendations, not measured total memory or a ready-to-install service unit. The supervisor needs separately reviewed privileges and access to the worker subtree. Refer to the governing [systemd resource controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) and [execution limits](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

For an orchestrator-managed deployment, the gate also accepts an arbitrary absolute `--cgroup-root` on cgroup v2. The administrator must provision its root-owned, protected ancestry, an empty domain, available/enabled `cpu`, `memory`, `pids` controllers, and aggregate parent limits. Do not pass the gate's own populated service cgroup as this root. Delegation must respect the no-internal-process rule: keep supervisor processes in a separate leaf from the empty worker-parent domain. The direct-child helper is only one isolated-lab layout; it is not a systemd delegation manager.

Per-request overrides are `--memory-max`, `--cpu-quota-us` and `--cpu-period-us`. Input/output caps default to 1 MiB each and maximum in-flight requests to four. The kernel applies ancestor and child limits together. Raising child limits does not override the helper's aggregate memory, task or CPU ceilings. No combination here proves a complete host resource or availability bound.

## Optional pinned PHP-CGI fixture

The optional smoke path uses the unchanged `examples/php/receiver.php` and an already-built, verified PHP **8.3.36 CGI** binary plus its pinned source archive. It is a frozen compatibility fixture, not a claim that 8.3.36 is the latest production release. The helper neither downloads nor builds PHP. Use the security-supported runtime appropriate to the actual deployment and requalify its compatibility.

To build the exact compatibility fixture from its official source in the dedicated VM,
use new paths. This frozen fixture is not a recommendation for a production version.

```sh
apt-get install -y bison re2c pkg-config
install -d -m 0755 /opt/ephem-sources
curl --fail --location --proto '=https' --tlsv1.2 \
  https://www.php.net/distributions/php-8.3.36.tar.gz \
  --output /opt/ephem-sources/php-8.3.36.tar.gz
sh tests/ephem/build-patched-php.sh \
  /opt/ephem-sources/php-8.3.36.tar.gz \
  /opt/ephem-php-build /opt/ephem-php /opt/ephem-php-build-evidence
```

The build helper verifies the pinned archive SHA-256 before extraction. Phase 3
reused the existing verified build; the complete PHP build was not rerun for this
release. With those inputs present, create a new root and a separate new cgroup:

```sh
python3 scripts/make-php-rootfs.py \
  --php-cgi /opt/ephem-php/bin/php-cgi \
  --app "$PWD/examples/php/receiver.php" \
  --rootfs /root/ephem-php-demo-rootfs
sh packaging/prepare-cgroup.sh /sys/fs/cgroup/ephem-php-demo
python3 tests/ephem/php_cgi_smoke.py \
  --gate "$PWD/target/release/ephem-gate" \
  --jail "$PWD/target/ephem-jail" \
  --rootfs /root/ephem-php-demo-rootfs \
  --app "$PWD/examples/php/receiver.php" \
  --php-cgi /opt/ephem-php/bin/php-cgi \
  --source-tar /opt/ephem-sources/php-8.3.36.tar.gz \
  --cgroup-root /sys/fs/cgroup/ephem-php-demo \
  --report /root/ephem-evidence/php-demo-001.json
```

The scripts check the receiver hash, exact CGI version and pinned source-archive hash. The smoke test uses two sequential and two concurrent tiny multipart uploads, compares exact response bytes/digests, and verifies distinct worker PIDs. General PHP-FPM behavior, sessions, cookies, databases, extension sets and arbitrary frameworks are not qualified by this fixture. The receiver's historical JSON label `patched-php-fpm` does not change the actual CGI SAPI.

## Shutdown, failures and evidence

SIGINT/SIGTERM stops admission and drains accepted work. The configured deadline bounds input and worker waiting; setup, disposal and response delivery have additional bounded work/allowances. It is not a full round-trip or shutdown SLA. Successful output is withheld until clean execution, receipt validation, no cgroup OOM, empty request-group disposal and directory removal. A disposal failure rejects the success path. This does not promise physical erasure, correct computation, data confidentiality from the worker, or immunity to host/kernel compromise.

After stopping the gate, inspect only the cgroup and processes created for this run. An empty helper subtree can be removed with `rmdir /sys/fs/cgroup/ephem-demo`. If it still contains request groups or reports populated tasks, retain evidence and investigate those exact owned identities; do not clear arbitrary host groups or remove paths recursively. Abrupt host/gate death can leave empty administrative cgroup directories for operator cleanup. A stale socket also needs ownership/instance verification before manual removal.

Retain source hashes, build/toolchain identity, binary hashes, host/kernel policy, rootfs manifest, raw reports and failed attempts. Keep logs free of request payloads, credentials and real application memory. Logs and proof reports themselves are intentional administrative persistence. A fresh process and denied direct worker side effects do not mean that every machine state change disappears.
