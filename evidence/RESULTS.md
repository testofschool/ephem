# Executed evidence — 23 October 2026 KST

**Result: the bounded experimental contract passes on the named Linux ARM64 lab.
Production qualification remains HOLD; comparative rank is UNMEASURED.**

This release is a new standalone source snapshot, derived from earlier local
EPHEM work and the supplied archives. Archive provenance and earlier defects are
in [INITIAL_AUDIT.md](../docs/INITIAL_AUDIT.md). No archived executable was run.
The 24 executed runtime/build/test files are frozen in
[source-freeze.json](source-freeze.json). The later evidence verifier and optional
PHP rebuild helper are reproduction tools, outside that pre-run freeze.

## Environment and build

Dedicated Lima VM on macOS ARM64; Ubuntu 24.04, Linux 6.8.0-146-generic AArch64,
4 virtual CPUs and 4 GiB guest RAM. The VM has no shared host-home mount. Rust
1.99.1, Cargo 1.99.1, GCC 13.3.0. The worker jail shares the guest Linux kernel;
the VM is a lab boundary, not a per-request microVM implementation.

Build/lint [explicit command and exit receipts](build-v2/receipt.json), [raw output](build-v2/) and [environment](arm64-v1/environment.txt) record these executed commands:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release
sh packaging/build-jail.sh
```

All returned zero; Rust unit tests: **5 passed, 0 failed**. Initial setup lacked
rustfmt/Clippy; they were installed inside the VM. The first strict lint found a
deprecated atomic method; it was replaced before the frozen runtime experiments.
No failed runtime result was relabeled as passing.

| Executed binary | SHA-256 |
| --- | --- |
| `ephem-gate` | `4eaf7d844cf8791cbce87e359d2c5dba54ad08cfb3622a7af429134950aff2ab` |
| `ephem-jail` | `cfcc923329f8cf23bb94f636fb9a315401240e42db7eed5d6bd88f5c4e574894` |
| Benign static fixture | `d8edead9110c1f016d4fea8de52dd96916e4bb81f46c7bf6125d58c3d5606fa3` |

The same gate/jail hashes appear in the lifecycle and actual-PHP registrations.
The executed binaries were copied back to the host and rehashed: both matched
the receipt above. [The final receipt](build-v2/receipt.json) also records restored
core policy, zero active swap entries and no leftover owned test cgroups.

ARM64 execution does not establish x86-64 support; the public CI runs that
architecture separately and its actual job status is authoritative.

## Final experiment

Run [the documented dedicated-VM procedure](../docs/OPERATIONS.md), which invokes
`sh scripts/validate-linux.sh NEW_ABSOLUTE_REPORT_DIRECTORY`. The final retained
run is [arm64-v2](arm64-v2/); every report path was new. Tests execute real Linux
kernel mechanisms, not a mocked sandbox.

| Check | Literal result | Evidence |
| --- | --- | --- |
| Lifecycle | **12/12**, zero failures/errors/skips; 158 HTTP observations | [lifecycle](arm64-v2/integration/lifecycle.json), [raw stderr](arm64-v2/integration/lifecycle.stderr) |
| Fresh workers | 50 sequential fixture requests, 50 distinct host PIDs; accepted worker already reaped | `fifty_host_worker_pids` and lifecycle assertions |
| Isolation | Namespace PID 1, UID/GID 65534; zero extra FDs/capabilities; private `/tmp`; read-only sentinel unchanged | lifecycle positive controls |
| Failure output | Crash, forbidden socket/fork/exec, deadline, oversized output and memory OOM return no staged canary | lifecycle observations |
| Resource disposal | **151** disposed scopes; actual OOM scope peak **134,217,728 bytes**, `oom=1`, `oom_kill=3`; next echo succeeds | `resource_disposals`, `cgroup_oom_and_disposal_verified=true` |
| Boundary controls | **7/7**: persistent chroot control, fresh sandbox tmp, forged stdout receipt, CGI framing/digest, slow input, launcher death and exact fixture cleanup | [boundaries](arm64-v2/integration/boundaries.json), [raw observations](arm64-v2/integration/boundaries.json.raw.json) |
| Actual seccomp scalar/fd controls | **5/5**, correct denied alternatives | [seccomp](arm64-v2/integration/seccomp.json) |
| Startup refusals | **6/6**: missing/ordinary/relative/absent cgroup, missing/wrong parent identity | [preflight](arm64-v2/integration/preflight.json) |
| Early supervisor death | Launcher stopped before exec; original parent exits; resumed launcher rejects before worker creation | [parent race](arm64-v2/integration/parent-race.json) |
| Piped core collector | Host's default pipe setting rejected before binding | [core refusal](arm64-v2/core-refusal.json) |
| Existing PHP source | **4/4** tiny multipart requests; two sequential, two concurrent, four distinct workers; exact response/hash | [PHP](arm64-v2/php.json), [registration](arm64-v2/php.preregistration.json) |
| Successful response exfiltration control | **Expected vulnerability boundary observed:** readable synthetic secret returned with status 200 | `READSECRET` lifecycle observation |

`oom_kill=3` is the kernel counter for the observed OOM group event; it is not a
claim that three independent requests or three workers were launched. Worker
`memory.peak` excludes the Rust gate and its buffers. Controller settings are
written/read back before launch. CPU quota and PID-limit stress/throughput are
not separately benchmarked by this run.

The PHP fixture uses the unchanged **963-byte** receiver, SHA-256
`c20a7b07a54d2341fca097d4e81e7e9d6ea1bcfda9b08deb62e1c9d4d711e681` before and
after execution, with patched PHP **8.3.36 CGI** and pinned source/dependencies.
The source tarball hash is checked by the smoke script. The pre-existing curated
PHP rootfs was reused; no existing service or image was activated. This measures
one tiny upload shape, not arbitrary PHP-FPM/framework compatibility or zero
deployment effort. The receiver's historical response literal says
`patched-php-fpm`; the actual executable SAPI is CGI.

## Timing observations

50 samples per condition, paired sequentially, no samples removed. Quantiles use
nearest rank `ceil(n*p)`. The raw condition is direct cold fixture execution;
the sandbox condition is a complete Unix HTTP fixture request including output
checks and disposal. These are different paths, not an isolated syscall-cost
measurement, PHP benchmark, competitor comparison or SLA.

| Final arm64-v2 | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Raw cold fixture exec | 0.338966 | 0.482178 | 0.630181 |
| Complete sandbox request | 1.854501 | 2.195174 | 2.245218 |

The earlier [arm64-v1 run](arm64-v1/integration/lifecycle.json) also passed all
12 tests. Its timing overlapped a separate Cargo build and is retained rather
than deleted: raw p95 14.501685 ms and sandbox p95 114.092019 ms. The final v2
experiment started after that build completed, using unchanged frozen source.
The v1 gate hash was `b3290383` (prefix); the final rebuilt v2 gate is identified
above. The different build artifacts are not treated as byte-identical evidence.
This explicit repeat does not establish production performance under load.

## Host policy and unresolved gates

No active guest swap was observed. Active-swap refusal is source-reviewed but
was not tested by enabling swap. The VM's piped `core_pattern` was deliberately
replaced with `core` only for owned fixture runs, then restored. No production
host policy changed. There were no leftover `ephem-*` test cgroups after cleanup.

The review and Linux probes used the same VM/kernel and artifacts. They are
**verified in this lab**, not externally independently reproduced or certified.
The source review found and the release corrected expected-parent startup,
piped-core retention and missing worker-resource-accounting issues. These
controls do not establish physical memory erasure or semantic safety.

Still outstanding: unprivileged ingress/privileged broker separation, external
security assessment, realistic workload matrix, aggregate supervisor memory
qualification, sustained concurrency/availability, production routing and
rollback, OCI integration, fair competitor benchmarks, persistent-state broker
and a separate-kernel backend. Current-request exfiltration is explicitly outside
the confidentiality guarantee. Patches remain required.
