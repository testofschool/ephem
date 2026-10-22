# Threat model

This document describes EPHEM's experimental **read-only fresh-execution profile**. It is a design boundary and source-level contract. Executed observations, exact source/build identities and unresolved test outcomes belong in [the current evidence record](../evidence/RESULTS.md). Production qualification and an external independent security assessment remain outstanding.

## Security objective

Run each accepted request in a fresh restricted application process; keep that worker's mutable state private to its request; deny its direct durable filesystem and network effects; and release bounded output only after the configured lifecycle and resource checks succeed.

“Disposable” describes the worker's execution lifetime and request-local scratch filesystem. It does not mean that no information can leave, that memory is physically erased, or that any possible exploit is contained.

## Assets

- The host and trusted runtime's integrity and availability.
- The curated worker rootfs and its application/dependency bytes.
- Separation of request-local process and scratch state across requests.
- The response-release condition: no successful response before verified teardown.
- Controlled CPU, process count and memory use in request cgroups.

Current-request confidentiality has an essential limit: the worker is allowed to read its input and the readable rootfs and to return a response. The rootfs must contain only data the workload may read. No unrelated customer data, host credentials or long-lived infrastructure secrets should be present. The bundled test rootfs deliberately contains a synthetic canary to demonstrate this limitation.

## Adversary

Assume that request content is hostile and can trigger arbitrary native code execution inside the worker, including through bugs in an interpreter or library. Do not rely on the application to follow its intended control flow or voluntarily delete state.

The local caller able to connect to the mode-0600 Unix socket is trusted to invoke the configured workload, but its request data is not trusted. The gate is not an internet-facing HTTP server, authentication service or TLS endpoint. An upstream adapter and its caller authorization are separate trust boundaries.

The adversary does not control the host administrator, kernel, runtime binaries, rootfs preparation, launch configuration, cgroup hierarchy or build/dependency supply chain. Defending against those compromises requires additional controls outside this profile.

## Trusted computing base

The Linux kernel and enabled security mechanisms; host firmware/hardware; the Rust gate and its dependencies; the C launcher and seccomp policy; the rootfs provisioning process; and the administrative configuration are trusted.

The gate and launcher currently execute with root authority. There is no audited privilege separation between untrusted request parsing and privileged launch. This is a material reason to keep production activation on HOLD. Running the same gate inside a VM is useful containment for a lab, but does not turn the inner namespace jail into a separate-kernel worker sandbox.

Keep trusted components patched. A worker interpreter should also be patched: disposal reduces certain persistence opportunities; it does not remove vulnerabilities or current-request consequences.

## Request lifecycle

1. The gate admits a connection only if an in-flight slot is available. It parses one bounded `POST /run HTTP/1.1` request with `Host` and exactly one `Content-Length`. Unsupported framing is rejected.
2. The gate exclusively creates a new child of an administrator-provisioned cgroup v2 domain. It configures and reads back the memory, swap, process and CPU limits before launching the request.
3. The child attaches itself to that request cgroup in the pre-exec path, before the trusted launcher begins and before any worker code executes. The launcher inherits a gate identity supplied before spawn and checks parent liveness.
4. The launcher creates the worker's namespace boundary, sets up its filesystem, removes capabilities and privileges, applies Landlock and seccomp, and performs the single permitted bootstrap execution.
5. The gate reads worker stdout into a bounded parent-owned memfd. After EOF, it seals that buffer. Worker stderr is not used as a trusted receipt channel; the launcher emits the receipt separately.
6. The gate checks the launcher result and receipt, optionally parses CGI framing, and computes the released-body hash. This verifies lifecycle and byte handling, not application semantics.
7. For both success and failure, the gate kills only its owned request cgroup and waits for it to become empty. A successful response additionally requires removal of that group, zero OOM counters and disposal within the request deadline.
8. Only then can successful output be sent to the caller. Known execution failures withhold staged output. Error cleanup and response delivery have separate bounded allowances; there is no total round-trip or hard scheduling SLA.

The lifetime contract is implemented through process ownership, pidfds, parent-death checks and cgroup ownership. A catastrophic host failure or trusted-runtime bug can defeat those mechanisms. Do not interpret a teardown receipt as proof of physical erasure.

## Enforcement layers

| Layer | Current behavior | Boundary |
| --- | --- | --- |
| Process lifetime | Fresh worker per accepted request; no application-process pool | Host kernel and supervisor remain shared |
| Namespaces | New PID, mount, network, IPC and UTS namespaces | No separate guest kernel |
| Identity | UID/GID 65534; supplementary groups and capabilities removed; no-new-privileges | Shared host UID accounting can still cause interference |
| Filesystem | Curated root recursively read-only; `/tmp` is a private 16 MiB tmpfs | All readable rootfs content is available to the worker |
| Landlock | Mandatory filesystem restrictions, ABI 3 or newer | Kernel support and policy correctness remain trusted |
| Seccomp | Native-architecture allowlist; restricted bootstrap exec; later process creation, exec and sockets denied | Allowed kernel paths can still contain vulnerabilities |
| Resource scope | Per-request `memory.max`, `memory.swap.max=0`, `pids.max=2`, `memory.oom.group=1`, `cpu.max` | Excludes trusted gate buffers and other host costs |
| Response | Bounded, sealed staging; launcher/receipt/OOM/disposal checks | No semantic correctness or DLP oracle |
| Host-memory admission | Reject active swap and piped core collectors; disable gate core dumping | Startup observation, not continuous host attestation |

The cgroup helper also provisions aggregate request limits. They cover request launchers and workers, not the gate. Operators must separately budget the gate, admission buffers, response copies and other service/host overhead. Memory caps and deadlines do not establish immunity to denial of service.

## Host and artifact assumptions

Use a dedicated Linux environment with the required namespace, pidfd, mount, Landlock, seccomp and cgroup controls. Missing enforcement must fail closed. There is no permissive portability mode.

The cgroup root must be an empty, root-owned domain on cgroup v2, with `cpu`, `memory` and `pids` available and enabled for children. It must not contain the gate. The socket directory, installed binaries and rootfs must be controlled by trusted administrators. Do not install the jail setuid or expose arbitrary launcher arguments as an API.

Treat the rootfs and executable dependencies as immutable trusted administrative inputs. They must not change during a request. The packaging entrypoint rejects unsupported path layouts, symlinks and nested rootfs mounts; that preflight does not protect against a trusted administrator concurrently replacing files. A compatible interpreter plus libraries and application data must be supplied explicitly.

The gate checks `/proc/swaps` and `/proc/sys/kernel/core_pattern` before serving. A piped core handler is refused because `RLIMIT_CORE=0` alone does not prevent that handler receiving worker memory after exec. The launcher repeats the core-handler check. EPHEM does not automatically change host-wide settings. Administrators must preserve the accepted policy for the service's entire lifetime. See [operations](OPERATIONS.md).

## Explicit non-goals and remaining risks

### Current-request data loss

A compromised worker can return readable data through stdout while exiting zero. It can also emit incorrect or malicious application output. No direct network access is needed for this channel. The caller's authorization and downstream handling must account for it. A successful response, digest or clean exit must never be called proof of harmless execution.

A data-loss-prevention product would require additional data-access and output-policy guarantees. Generic output buffering cannot infer whether a result is authorized. Do not solve this by trusting a worker-authored “safe” or “commit” marker.

### Kernel, host and hardware compromise

Namespaces, seccomp and Landlock share the Linux kernel. This profile does not establish containment after a kernel exploit, runtime/control-plane compromise, hostile root administrator, hypervisor compromise, firmware attack, DMA attack or physical access. Hardware side channels and secure physical-memory erasure are unproven.

No-swap/no-piped-core admission narrows specific disk-retention paths. It does not audit kernel crash dumps, hibernation, VM snapshots, privileged tracing, memory acquisition, downstream logs or storage outside the worker. Discarded anonymous memory is not cryptographically erased RAM.

### External state

The offline profile does not give workers direct database, cache, message-queue or remote-API access. If a future integration adds those channels, a committed external operation survives process destruction. There is no generic transaction broker or rollback guarantee today. Authentication, SQL injection, authorization bugs and malicious-but-authorized operations require separate application controls.

### Availability and compatibility

The root gate is still exposed to bounded untrusted request bytes. Parser, allocator, scheduling and runtime bugs remain possible. A failure may reject legitimate traffic, and a missing prerequisite prevents startup. Limits on application address space, tmpfs, syscalls, process creation and response headers exclude many programs.

General PHP-FPM/framework compatibility, cookies, sessions, redirects, streaming responses, WebSockets, background tasks and warmed application snapshots are not supplied by this profile. The CGI adapter has a fixed minimal environment and accepts only its documented bounded response headers. Do not route an existing service through it without workload-specific tests.

## Verification and changes

Read [RESULTS.md](../evidence/RESULTS.md) for what was actually executed. A source review, a stored report consistency check, a fresh integration run and an independent security audit are different evidence levels.

Any change to launch order, descriptors, syscalls, mounts, ownership, cgroup membership, parsing or response release can change this model. Preserve the earlier evidence, freeze the new source identity, and add a denied case plus an appropriate positive control. The [initial audit](INITIAL_AUDIT.md) records historical gaps; the [roadmap](ROADMAP.md) names the remaining engineering gates. Report vulnerabilities through [SECURITY.md](../SECURITY.md).
