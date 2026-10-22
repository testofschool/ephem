# EPHEM: prior art, defensible claims, and implementation priorities

Research date: **2026-10-23, Asia/Seoul**. External sources below were accessed on that date. This is a technical prior-art and positioning review, not an exhaustive patent search, independent security audit, comparative benchmark, or customer-validation study.

## Decision

**Do not claim that ephemeral isolation, disposable execution, request isolation, or wrapping an existing application without source edits is a world first.** There are direct precedents, including Groundhog for transparent sequential request isolation; nsjail and bubblewrap for wrapping existing Linux executables; and Qubes, Windows Sandbox, and HP Sure Click for disposable environments. NVIDIA OpenShell is also a current example of adding security controls around existing agents without rewriting them. [Groundhog](https://groundhog.mpi-sws.org/), [nsjail](https://github.com/google/nsjail), [bubblewrap](https://github.com/containers/bubblewrap), [OpenShell](https://www.nvidia.com/en-us/ai/openshell/)

**A credible EPHEM product hypothesis is narrower:** make one-request disposable execution easy to adopt for existing, compatible CGI/CLI workloads, with no application-source edits, no worker network access, an immutable input filesystem, bounded request-local scratch space, bounded output staging, and explicit lifecycle evidence. This combination can be useful engineering and packaging. Its uniqueness, customer advantage, production safety, and comparative speed have not been established.

The security objective should be **reduce cross-request retention and persistence opportunities within a defined worker boundary**, not “nothing can be stolen,” “physically unhackable,” or “patches are unnecessary.” Current-request data remains available to the worker. An attacker can put it in an apparently successful response. Discarding that worker afterward does not recover data already released.

> Historical baseline review: the local measurements below describe Phase 2.
> Phase 3 adds cgroup accounting and host-policy checks; current observations are in
> [the release evidence](../evidence/RESULTS.md). Baseline timings do not describe Phase 3.

## What was inspected locally

Read-only review of the repository's existing `README.md`, `docs/CLAIMS.md`, and `docs/EPHEMERAL_RUNTIME.md`. No attached code was executed for this research, and no local measurements were rerun.

The existing runtime documentation describes fresh execution and new PID, mount, network, IPC, and UTS namespaces for every accepted request; UID/GID 65534; capability removal; Landlock and seccomp; a curated read-only rootfs; request-local `/tmp`; and output withheld until worker completion plus receipt validation. It explicitly says there is no warmed snapshot implementation, semantic corruption oracle, generic database rollback, or separate worker kernel. These are descriptions and recorded lab results, not independent verification in this report.

The baseline evidence must retain its scope:

| Recorded local observation | What it supports | What it does not support |
| --- | --- | --- |
| Frozen Linux lifecycle suite: 10/10 tests | Recorded fixture lifecycle and failure-path behavior on that lab | Arbitrary exploit prevention or production readiness |
| 50 sequential requests with 50 distinct host worker PIDs | No observed PID reuse for those requests; request workers were separate | Every possible form of host/kernel state isolation |
| Unchanged 963-byte receiver, four PHP-CGI requests | That specific application source ran unchanged for four tiny multipart cases | Transparent support for general PHP-FPM/framework applications |
| Sandbox p95 1.811606 ms, 50 fixture samples | A recorded one-host complete sandbox-request result | A latency SLA, competitor ranking, or PHP application p95 |
| No OCI rollout; no external audit; memory accounting unmeasured | Production gates remain open | A completed deployment or proven resource-containment guarantee |

Sources: historical original-workspace files `docs/EPHEMERAL_RUNTIME.md` and `docs/CLAIMS.md` (not included in this standalone release). These are the repository state at the time of this read; later implementation changes require a fresh evidence check.

## Closest prior art

The final column is an analytical comparison, not a claim that a competitor lacks features outside the cited material. “Not inherent” means that the isolation mechanism alone does not establish that property.

| System | Verified design or behavior | Difference relevant to EPHEM |
| --- | --- | --- |
| **Groundhog, EuroSys 2023** | Restores a clean initialized process state between function activations; language/runtime independent; no changes required to existing functions, libraries, runtimes, or OS kernels. | The strongest counterexample to a broad first-in-world claim. Uses restoration/reuse instead of EPHEM's documented fresh exec. Request isolation without source edits is established prior art. [Project](https://groundhog.mpi-sws.org/) |
| **nsjail** | Supports one-shot execution and an inetd-style TCP listener that forks a process per connection, with namespaces, read-only mounts, tmpfs, seccomp, resource limits and cgroups. | Very close substrate and wrapping pattern. A TCP connection can contain multiple application requests; per-connection execution alone does not establish HTTP per-request isolation. EPHEM needs to show value in its protocol, safe defaults and evidence. [Repository](https://github.com/google/nsjail) |
| **bubblewrap** | Builds configurable Linux namespace sandboxes around existing commands; temporary root namespace cleans up at last process exit; permits read-only mounts, isolated networking and supplied seccomp filters. Maintainers explicitly leave the security model to the caller. | Existing disposable filesystem and command-wrapping primitives. EPHEM can add an opinionated service contract and lifecycle tests, but should not present those primitives as new. [Repository](https://github.com/containers/bubblewrap) |
| **Firecracker** | KVM-based microVMs and a companion jailer; a separate guest kernel; snapshot facilities are available. | A different isolation boundary. MicroVMs are not automatically discarded after each HTTP request. EPHEM's namespace jail shares the host kernel, so a small fixture latency does not establish equal isolation or superiority. [Overview](https://firecracker-microvm.github.io/), [snapshots](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md) |
| **gVisor** | A userspace application kernel interposes on the application system-call surface and limits host interactions; it relies on host/platform protections for hardware attacks and on cgroups for resource exhaustion. | Stronger mediation of the host system-call interface than a bare namespace jail. Per-request disposal is a separate lifecycle decision. EPHEM should consider it as a backend or benchmark, not label it obsolete. [Security model](https://gvisor.dev/docs/architecture_guide/security/) |
| **Kata Containers** | Runs containers inside lightweight VMs and integrates with containerd/Kubernetes; a pod can have multiple containers inside the same VM. | Existing-container compatibility and VM isolation are not new. A pod/VM lifecycle is not inherently an HTTP-request lifecycle; EPHEM may add a request-oriented policy on top. [Architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md) |
| **AWS Lambda** | Official documentation describes execution-environment reuse, surviving global objects, reusable `/tmp` contents, and resumed background work. AWS cautions against storing sensitive user state in reusable environments. | “Serverless” or “stateless” does not mean a clean worker for every invocation. EPHEM's strict fresh-worker contract differs from Lambda's documented default reuse. This is not evidence that Lambda is generally insecure. [Lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html), [best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html) |
| **Cloudflare Workers** | V8 isolates separate guests; many isolates can share a process. The security model describes layered defenses and continuing work on side channels. | Isolate-based execution is established. It is not a generic unchanged-native-binary wrapper, and isolate isolation does not by itself imply fresh per-request memory. [Security model](https://developers.cloudflare.com/workers/reference/security-model/) |
| **Windows Sandbox** | A disposable Windows environment using a separate kernel and hypervisor; closing it removes its local software, files and state. Read-only mapped folders and disabled networking are recommended for safer use. | A clear precedent for discard-state execution. Desktop/session scope differs from a Linux server request wrapper. [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) |
| **Qubes disposables** | Stateless disposable qubes; normal disposables are deleted after their initial application closes. Official documentation includes untrusted documents, websites and sanitization use cases. | Disposable clean environments and untrusted-input processing are well established. The control plane, desktop workflow and VM boundary differ. [Qubes documentation](https://www.qubes-os.org/doc/DisposableVms/) |
| **HP Sure Click** | The vendor describes untrusted documents and web pages running in disposable hardware-isolated microVMs, with each risky task confined to its VM. | Commercial precedent for selling containment instead of relying only on detection. Endpoint document/browser protection differs from a server CGI gateway. Vendor statements are not an independent proof of invulnerability. [HP engineering account](https://threatresearch.ext.hp.com/bringing-threat-containment-to-arm/) |
| **WebAssembly / Wasmtime** | Instances have isolated linear memory and explicit host imports; WASI provides capability-based filesystem access. Wasmtime documents defense in depth and ongoing side-channel considerations. | Strong fit for newly compiled Wasm workloads, but ordinary native Linux binaries cannot simply run as a Wasm module. EPHEM's native CGI/CLI compatibility is a useful axis, not proof of greater security. [Wasmtime security](https://docs.wasmtime.dev/security.html) |
| **Unikernels / Unikraft / SEUSS** | Unikraft offers a Linux ELF binary-compatibility layer; SEUSS explored rapid serverless deployment through unikernel snapshot stacks. | Do not say all unikernels require source rewrites, or that clean snapshots are new. Compatibility and isolation vary by implementation. EPHEM currently has no warmed-snapshot implementation. [Unikraft ELF loader](https://github.com/unikraft/app-elfloader), [SEUSS](https://research.redhat.com/blog/publication/seuss-rapid-serverless-deployment-using-environment-snapshots/) |
| **SCIT / self-cleansing servers** | The originating research group's account describes converting static servers into dynamic servers and reducing their exposure while maintaining service. | Proactive cleansing and reduced attacker residence are older ideas. This source establishes the category, not a precise per-request mechanism, timing guarantee, or current commercial offering. [Originator's account](https://internationalcybercenter.org/arun_sood/) |
| **NVIDIA OpenShell** | Adds controls around existing agents without rewriting their harness; architecture separates sandbox and trusted supervisor, mediates egress and credentials, and describes fail-closed startup. | A current direct precedent for no-rewrite runtime security and an important design reference for privilege separation. Its sandbox lifecycle is not automatically EPHEM's one-request lifecycle. [Product](https://www.nvidia.com/en-us/ai/openshell/), [architecture](https://docs.nvidia.com/openshell/about/architecture) |

### Groundhog is the comparison that must appear in public material

Groundhog's authors published their work at EuroSys 2023. The paper distinguishes sequential invocation isolation from isolation between function instances, assumes the FaaS platform/kernel/hypervisor/services are trusted, and leaves side channels outside its model. It uses a clean snapshot taken before receiving request-specific arguments or credentials. Its published evaluation is a different workload, baseline and measurement from EPHEM's current lab, so quoting its overhead next to EPHEM's fixture timing would not be a valid ranking. [Paper, especially Sections 1, 3.3 and 4](https://people.mpi-sws.org/~dg/papers/eurosys2023-groundhog.pdf)

The honest distinction is **fresh-exec, restrictive offline worker profile and a small service wrapper**, versus a **transparent process restoration facility integrated with FaaS**. EPHEM's output staging can enforce a useful response-release condition. It does not give EPHEM a semantic oracle that distinguishes a successful exploit from a successful legitimate computation.

### Unresolved source names and access failures

“Phoenix” is not a sufficiently precise citation. Searches did not identify a single unambiguous Phoenix system matching request-local zero-persistence server isolation. Do not attribute capabilities to an unspecified Phoenix product or paper. The SCIT category is independently supported above.

An old GMU SCIT PDF URL (`https://cs.gmu.edu/~asood/scit/depend_2009_submitted_version-2.pdf`) redirected to the department homepage when opened. A SciTePress PDF endpoint returned HTTP 403. Search snippets from those URLs were not promoted into full-paper verification. No dates or detailed mechanism claims depend on those inaccessible papers.

## What Zero-Persistence can mean honestly

The phrase needs an explicit boundary. The following are different properties:

1. **No worker reuse:** request B does not run in request A's application process.
2. **No reusable worker scratch state:** request A's private temporary filesystem is not mounted into request B.
3. **No durable application writes:** the worker has no writable durable host/application paths or direct mutation channel.
4. **No credentials inside the worker:** long-lived backend secrets remain outside that boundary.
5. **No information leaves during execution:** a much stronger property, usually incompatible with returning a useful response unless a trusted policy restricts what may leave.
6. **No physical remnants anywhere:** includes swap, core dumps, logs, snapshots, RAM remanence and host behavior. Neither fresh exec nor tmpfs establishes this.

The current documented EPHEM profile targets the first three for compatible workloads. The fourth needs explicit secret inventory and a broker design before it can be generalized. The fifth and sixth are not established.

Linux's documentation says tmpfs may send pages to swap and that swap is enabled by default unless disabled for the mount. Therefore “uses tmpfs” is not equivalent to “never reaches disk.” Host swap policy, core dumps, tracing, payload logging and snapshots need explicit review. A teardown receipt reports lifecycle events; it is not a cryptographic certificate that all physical copies have been erased. [Linux tmpfs documentation](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html)

## Limits no honest implementation should hide

These are architectural deductions from the documented interface and threat boundary; they are not exploit-test results.

| Claim | Why it fails | Defensible replacement |
| --- | --- | --- |
| “There is nothing to steal.” | A useful worker processes current request data. A compromised worker may encode that data in successful stdout. | “No prior request's worker state is intentionally reused; minimize the data and credentials present in each worker.” |
| “Clean exit means safe output.” | Compromised or logically buggy code can exit zero and emit well-formed malicious output. A hash checks byte identity, not trustworthiness. | “Release output only after the configured lifecycle checks; validate downstream formats and authorization separately.” |
| “10,000 vulnerabilities cannot hurt us.” | Vulnerability counts say nothing about which trust boundaries fail. An allowed syscall, supervisor bug or kernel defect can defeat assumptions. | Name the threat model and tested failure paths; publish unresolved risks. |
| “Patches are no longer needed.” | The supervisor, launcher, kernel, libraries and any VM/VMM remain trusted code requiring maintenance. | “Reduce reliance on application patch timing for specific persistence paths; continue patching all trusted components.” |
| “It is physically impossible to escape.” | Software and hardware enforcement are fallible; namespace jails share a kernel. | “Defense in depth within a stated boundary; no universal escape-prevention guarantee.” |
| “Zero deployment.” | Wrapper installation, privileges, rootfs preparation and routing changes are deployment work. | “No application-source edits for compatible workloads; image-rebuild-free attachment where supported.” |
| “Zero customer modification cost.” | Operation, compatibility testing, cold starts, observability and rollout have costs even with unchanged source bytes. | State which source stayed unchanged and measure deployment effort separately. |
| “Worker deletion undoes a database write.” | A remote committed mutation survives worker destruction. | Keep external mutation unavailable in the first profile; add explicit transaction/capability protocols later. |
| “Read-only means confidential.” | Read-only mounted secrets can still be read and returned. | Build a minimal rootfs with no unrelated secrets, host credentials or previous customer inputs. |
| “No worker network means no exfiltration.” | The intended response channel is still an egress channel. | Treat stdout and returned artifacts as untrusted; do not expose data the caller is not authorized to receive. |

These limitations agree with mature projects' own boundaries. gVisor identifies host/platform dependence and recommends current kernel/firmware protections; Firecracker's host guide describes evolving hardware mitigations and says Firecracker cannot mitigate every lower-level issue. [gVisor model](https://gvisor.dev/docs/architecture_guide/security/), [Firecracker host guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)

Landlock is an additional access-control layer for restricting ambient rights, rather than an application-correctness proof. Available enforcement depends on kernel support. A product advertising a mandatory profile must explicitly refuse environments that cannot enforce its required controls. [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)

## Strengths worth building on

These are present design attributes or positioning hypotheses. They are not established unique advantages.

- **A clear lifetime contract:** one accepted request, one fresh worker, a finite completion condition, and no intentional application-process reuse. This is easier to explain and audit than a vague “stateless” label.
- **Existing-native-program entry point:** the documented unchanged PHP receiver is real, narrow compatibility evidence. A supported CGI/CLI adapter can be useful to teams unable to port code to Wasm or rewrite it into a cloud function.
- **Small offline policy:** denying worker networking and durable writes keeps the initial model understandable. A general networked application is a different product contract.
- **Fail-closed response handling:** crash, timeout, output overflow and known enforcement failures can withhold staged output. Public documentation must retain the distinction between these lifecycle checks and semantic validation.
- **Evidence as a product feature:** frozen fixtures, actual negative paths, report schemas, raw samples and explicit unsupported cells can make adoption review easier. The value is reduced integration uncertainty, not proof of immunity.

The potential moat is therefore **compatibility, safe integration, verifiable lifecycle enforcement, operational reliability, and distribution**. Namespaces, seccomp, temporary filesystems and process death are widely available primitives.

## Priorities before a production security claim

This is a recommendation, not authorization to change infrastructure or a statement that the work below has been completed.

| Priority | Work | Concrete acceptance evidence |
| --- | --- | --- |
| P0 | Publish one exact supported profile and threat model. | Explicit inputs, outputs, privileges, kernel/ABI requirements, allowed syscalls, writable paths, and trusted components. No silent fallback when required controls are missing. |
| P0 | Separate untrusted ingress from privileged launch. | Unprivileged gate; narrow helper protocol; fixed policy identifiers; authenticated/owned socket or descriptor channel; no arbitrary root-level command strings, paths or mount construction from request data; review of the boundary. |
| P0 | Add and measure cgroup v2 resource accounting. | Worker-group memory and process caps; CPU/admission limits; OOM/crash cleanup and reaping; observed peak memory and supervisor survival under the tested limits. RLIMIT_AS is not a substitute for total resource accounting. |
| P0 | Harden artifact and descriptor handling. | Immutable rootfs/build hashes; no writable inherited descriptors; negative tests for symlinks, nested mounts, path races and concurrent rootfs mutation; safe socket ancestry; capability/environment inventory. |
| P0 | Make data-retention claims testable. | Document swap/core-dump/tracing/logging/snapshot policies; prevent request payloads and secrets entering normal logs; demonstrate no marker crosses sequential or concurrent request boundaries. |
| P0 | Test successful-but-malicious output. | A harmless fixture emits a current-request canary and exits zero. The report must show that lifecycle checks do not prevent this leak, so marketing and downstream handling stay accurate. |
| P0 | Expand compatibility beyond the tiny receiver. | Realistic request sizes and upload cases; error behavior; headers, cookies, sessions, redirects and framework assumptions explicitly passed or unsupported. No universal PHP-FPM claim before this. |
| P1 | Add a separate-kernel backend for higher-risk code. | Same request contract on a microVM backend; documented additional trusted components, host requirements and lifecycle behavior; benchmarked separately. A microVM still does not solve application authorization. |
| P1 | Make integration boring. | Reproducible Linux amd64/arm64 builds, pinned release checksums, SBOM, license/security policy, working examples, preflight, service management, bounded metrics, reversible routing procedure and upgrade path. |
| P1 | Commission an external security assessment. | Independent reviewer, exact frozen commit/kernel/profile, findings and retest record. A separate agent on the same VM is not equivalent. |
| P2 | Add brokered external capabilities only for a specific use case. | Per-request authorization, minimal operation schema, destination binding, quotas, replay/idempotency handling and explicit commit conditions. No generic arbitrary-DB rollback promise. |
| P2 | Investigate warmed snapshots. | Snapshot is created before user secrets arrive; entropy, credentials, connections and unique identifiers are refreshed correctly; compare to cold exec. Keep unimplemented until measured. |

### Comparative benchmark contract

Use the same Linux host, architecture, kernel, worker executable, payloads, output verification and resource policy. Compare raw cold exec, an appropriately named warm application baseline, EPHEM, nsjail and bubblewrap first. Add gVisor and a microVM backend with their different security boundaries prominently stated.

Measure complete request latency, admission/queue time, launch time, execution time, output collection, cleanup and response release; throughput under sustained concurrency; peak worker and host memory; failure latency; and resource-leak behavior. Publish the raw sample count, quantile convention and exact commands. Do not compare a competitor's VM boot time against EPHEM's tiny native command, or a paper's percentage overhead against a different local absolute timing. “Fastest” remains **UNRUN** until a fair denominator exists.

## Practical first market hypothesis

The shortest credible path is **offline processing of untrusted input with an existing executable**, not immediate replacement of enterprise endpoint or network security platforms.

Candidate first workloads include a tightly constrained file metadata extractor, image/document converter, or read-only CGI endpoint. The contract is: one input, one bounded output, no credentials, no direct network, no durable writes, and a limited runtime. This fits the current architecture better than a stateful web application requiring sessions, database transactions, shared caches, background work or streaming responses.

Suggested buyer hypothesis: the platform engineer or application-security engineer responsible for that specific input-processing path, at a team that already has a reproducible Linux deployment. This is an inference about fit, not evidence of a reachable buyer, willingness to pay, or a validated market.

A first pilot should preserve the original executable/application hash, show expected outputs against the existing path, make the integration diff visible, and measure setup time, failure behavior and actual resource/latency cost. A useful commercial result would be a team keeping the wrapper enabled on a defined workload and agreeing that the operational benefit exceeds its cost. GitHub stars, a polished README and simulated economics do not establish that result.

AI-agent sandboxing is adjacent, but OpenShell already addresses several operational/security controls there. Enter that market only with a concrete request-disposal use case, not a claim that existing isolation products do not exist. [OpenShell architecture](https://docs.nvidia.com/openshell/about/architecture)

## Public messaging that can survive scrutiny

Recommended lead:

> **One request. One disposable worker.**
>
> EPHEM is an experimental Linux runtime for compatible CGI and CLI workloads. It starts a fresh restricted worker for every request, keeps the application filesystem read-only, denies worker networking, and withholds bounded output until its lifecycle checks complete.

Supporting statement tied to current evidence:

> The existing lab record includes 50 distinct workers for 50 sequential fixture requests and four successful PHP-CGI requests using the unchanged 963-byte receiver. Production rollout, broad compatibility and an external security audit remain open.

The exact implementation and tests may change during the current build; refresh these numbers from the final reports before publication.

An ambitious but clearly directional line is: **“A compromised request should not get a second lifetime.”** It states the motivation without pretending the system can prevent every compromise or all current-request leakage.

Do not publish: “world first,” “unhackable,” “zero vulnerabilities,” “patch-free security,” “physically impossible to steal data,” “works with any application,” “zero deployment,” “zero cost,” “military-grade,” or an unsupported performance rank.

## Source register

All sources accessed **2026-10-23 KST**. Official project documentation and original-author publications are used. Product descriptions are vendor claims; they do not independently certify the product's security.

| Source | URL | Use |
| --- | --- | --- |
| Groundhog project | https://groundhog.mpi-sws.org/ | Direct prior art for transparent sequential request isolation |
| Groundhog original paper | https://people.mpi-sws.org/~dg/papers/eurosys2023-groundhog.pdf | EuroSys 2023 venue, mechanism and threat-model boundaries |
| nsjail repository | https://github.com/google/nsjail | Single-run/listener modes and Linux isolation features |
| bubblewrap repository | https://github.com/containers/bubblewrap | Existing command wrapping, temporary filesystem and policy responsibility |
| Firecracker project | https://firecracker-microvm.github.io/ | KVM microVM and jailer architecture |
| Firecracker snapshot documentation | https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md | Existing snapshot facilities |
| Firecracker production host guide | https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md | Host/firmware/side-channel maintenance boundaries |
| gVisor security model | https://gvisor.dev/docs/architecture_guide/security/ | Application-kernel boundary and host/resource dependence |
| Kata architecture | https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md | VM/container/pod isolation relationship |
| AWS Lambda lifecycle | https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html | Reuse, local state, `/tmp`, background work |
| AWS Lambda best practices | https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html | User-data-retention caution |
| Cloudflare Workers security | https://developers.cloudflare.com/workers/reference/security-model/ | V8 isolate architecture and limits |
| Microsoft Windows Sandbox | https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/ | Disposable environment and hypervisor boundary |
| Qubes disposables | https://www.qubes-os.org/doc/DisposableVms/ | Task-lifetime disposable environments |
| HP Sure Click engineering account | https://threatresearch.ext.hp.com/bringing-threat-containment-to-arm/ | Existing commercial task-level disposable isolation |
| Wasmtime security | https://docs.wasmtime.dev/security.html | Wasm isolation and capability model |
| Unikraft ELF loader | https://github.com/unikraft/app-elfloader | Unmodified native ELF compatibility precedent |
| SEUSS original-author publication record | https://research.redhat.com/blog/publication/seuss-rapid-serverless-deployment-using-environment-snapshots/ | Unikernel snapshot lineage |
| SCIT originator biography | https://internationalcybercenter.org/arun_sood/ | Established self-cleansing-server lineage; no precise per-request claim |
| NVIDIA OpenShell product | https://www.nvidia.com/en-us/ai/openshell/ | No-rewrite runtime-security precedent |
| NVIDIA OpenShell architecture | https://docs.nvidia.com/openshell/about/architecture | Supervisor separation and egress/credential mediation |
| Linux tmpfs | https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html | Tmpfs may swap; temporary does not mean no disk copies |
| Linux Landlock | https://docs.kernel.org/userspace-api/landlock.html | Ambient-right restrictions and kernel support |

No claim in this report establishes that EPHEM has a unique combination, a safe production deployment, a paying market, or a universal no-exfiltration property.
