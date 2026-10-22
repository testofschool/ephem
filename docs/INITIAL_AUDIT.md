# Runtime source review — 23 October 2026

This review covers the pre-Phase-3 source snapshot below. It is a source audit and a recheck of stored evidence consistency on macOS, not a new Linux execution or an external security assessment. Any subsequent implementation needs new source hashes and new Linux results. Production remains **HOLD**.

## Material read and provenance

All UTF-8 text files in both supplied archives were read. Embedded plans, deployment commands, acceptance instructions and earlier claims were treated as historical data, not as new authorization. No archived executable was run.

| Archive | SHA-256 | Text inspected | Binary excluded |
| --- | --- | ---: | --- |
| `ephem-isolation.zip` | `0da37251fd5c69356126379d5ac00c4594d21f82a5c5d0014bfb4e29c63e335f` | 13 files, 37,044 bytes | none |
| `ephem-phase2.zip` | `fb5e5cf617c53d17f4ee6a1432455eedd051315bc9c595d3e23310d47c9c6c81` | 27 files, 94,187 bytes | `bin/ephem-gate` |

Current code inspected: Rust ingress/output staging, C launcher, actual classic seccomp-BPF policy and header, entrypoint, lifecycle harness, independent audit harness, direct seccomp probes, evidence verifier, runtime/audit documentation and corresponding final report metadata.

| Pre-change source | SHA-256 |
| --- | --- |
| `crates/ephem-gate/src/main.rs` | `4bf0640e516355287f0efcd8fdb0cbba23152095bcdd5052e235af53bdbbffaf` |
| `crates/ephem-jail/main.c` | `f6eca7cd41211ff532ba6309a7c6bd0d59389eb7b57d41b0e3cfa5f0a87e43e0` |
| `bpf/worker_containment.bpf.c` | `691cbe6d14293d419866059b379edfda3859cbc81984a150287f62c985a26b95` |
| `tests/test_ephemeral_lifecycle.py` | `3b3a13686472585edac6e004eb2c2d0fda0dfa905798be7c1fd699923f2c8a0d` |
| `tests/ephem/audit_probes.py` | `6bbfc11eacf6decf38f6c9f51cc21956dcc33eecb323f3bd8a39711aef43d495` |

Line references below refer to this exact snapshot, before follow-up edits.

## Is the current runtime better than the archives?

Yes, substantially, within its deliberately narrow read-only workload contract. It also contains one parent-identity regression relative to the second archive.

| Area | First archive | Second archive | Current pre-Phase-3 tree |
| --- | --- | --- | --- |
| Admission/protocol | stdin demonstration; no service adapter | bounded Unix HTTP POST; weak header validation | exact `POST /run`, Host/length checks, bounded headers, CGI adapter |
| Isolation setup | NET/mount unshare failure ignored; no actual filesystem policy | mandatory namespaces, Landlock and read-only root | separate C launcher; atomic `clone3` namespace creation and pidfd; UTS added |
| Syscall boundary | default allow, three denied syscall numbers | larger default-allow denylist; later exec allowed | native-architecture allowlist, default fatal; one brokered bootstrap exec; later exec rejected |
| Temporary writes | no request-private tmpfs enforcement | private 64 MiB tmpfs | private 16 MiB tmpfs, narrower Landlock creation rights |
| Persistent mutation contract | worker-authored fd3 bytes appended after clean exit | explicitly no DB broker | explicitly no DB broker; only staged output released |
| Output staging | unbounded vectors; burned diff still printed in outcome JSON | bounded output collected first, then copied into memfd | bounded incremental parent-owned memfd, sealed before validation/release |
| Real isolated execution evidence | small x86 fixture result, no full filesystem jail | full release check failed before execution due to environment EPERM | stored v5 Linux ARM64 results and four real PHP-CGI uploads |
| Parent identity before launcher startup | no expected-parent pin | explicit expected gate PID, pidfd/race checks | captures current parent after startup; pre-capture reparent race remains |

The first archive does not establish “no bytes persist”: a worker could write outside any ledger, its filesystem namespace call could fail silently, and `main` prints the worker diff even for a BURN verdict. The second archive correctly retracts universal transparency, arbitrary corruption attestation and database rollback claims. Its stored `tests/results/release-check.txt` contains four setup errors, not successful integration results.

The current implementation materially improves enforcement and measured scope. Its stored reports are evidence of named fixtures on one VM; they are not exhaustive escape tests, a comparative benchmark or a general application compatibility result.

## Findings requiring attention

### P1 — Parent-death protection can attach to the wrong parent

Evidence: Rust `main.rs:200-214` spawns the launcher without supplying the expected gate identity. C `main.c:438-440` records `owner = getppid()` only after launcher startup and checks it again after installing `PR_SET_PDEATHSIG`.

If the gate dies before the first `getppid()`, the launcher may already belong to init or a subreaper. It then records that new parent as the intended owner and passes its check. Its own worker-to-launcher check is sound for a live launcher, but does not recover the lost gate identity. A sleeping worker consumes little CPU, so `RLIMIT_CPU` does not impose a wall-clock bound. This is a source-confirmed race; no live reproduction was run during this review.

**Bounded correction:** pass the expected gate PID as trusted launcher configuration before spawn. Require an exact parent match, open a pidfd for that expected identity, install PDEATHSIG, then repeat both numeric-parent and pidfd-death checks before creating namespaces. A gate intentionally running as PID 1 must remain supported; reject mismatches rather than rejecting PID 1 categorically. A pre-opened inherited parent pidfd is an alternative with a smaller identity race.

**Verification:** a dedicated owned launcher harness should stop before entering jail `main`, terminate its original parent, then resume it. The launcher must reject and create no worker. Also repeat normal daemon SIGKILL after worker startup, SIGTERM shutdown, and parent exit during namespace/credential setup. Record PID plus `/proc/PID/stat` start identity; check workers including zombies. Existing `audit_probes.py` kills the launcher after the worker is already alive and does not cover the pre-capture gate-death window.

### P1 — Worker crash memory may reach a host core-dump helper

Evidence: `main.c:202` sets `RLIMIT_CORE=0`, `main.c:226` clears dumpability, and `main.c:274` subsequently executes the worker. Ordinary Linux exec resets dumpability to 1. A piped `core_pattern` ignores `RLIMIT_CORE`; the host handler can therefore receive memory despite those pre-exec controls. This follows from the governing [execve manual](https://man7.org/linux/man-pages/man2/execve.2.html) and [core-dump manual](https://man7.org/linux/man-pages/man5/core.5.html). The code does not presently qualify that host setting. This review did not crash a real application to collect its memory.

**Bounded correction:** reject a piped host core pattern in the strict no-residue profile, including unreadable/missing configuration. Keep hard `RLIMIT_CORE=0`, and disable gate/launcher dumps before they hold request data. Explain that pre-exec `PR_SET_DUMPABLE=0` alone does not survive ordinary exec. Changing a host-wide setting automatically is unnecessary; refusing an incompatible host is sufficient. Kernel crash dumps, hibernation, privileged host observers and hardware attacks require an explicit exclusion or separately qualified host policy.

**Verification:** an owned VM profile with piped `core_pattern` must be refused before worker execution; unreadable/unknown host policy must also refuse. For the accepted profile, verify both ordinary and fatal syscall/crash paths, then inspect only owned fixture artifacts. Do not record actual credentials or application memory in a proof artifact.

### P1 — Address-space and tmpfs caps do not account for all request memory

Evidence: `main.c:191-211` limits tmpfs to 16 MiB, address space to 256 MiB, and real-UID-wide process count to 128. The gate allows up to 128 concurrent requests (`main.rs:306`) and 16 MiB input/output each (`main.rs:307`). There is no cgroup admission/accounting. The gate itself holds the input vector (`167`), response memfd (`100-119`), later response vector and possible CGI copy (`250-253`). Worker-only address-space limits do not include all of these costs or aggregate host usage.

**Bounded correction:** require an administrator-provisioned cgroup v2 parent and per-request `memory.max`, `memory.swap.max=0`, `pids.max`, and `cpu.max` controls. Read back limits; reject unavailable controllers or failed writes. Place the worker in the cgroup before untrusted execution, preferably atomically using `CLONE_INTO_CGROUP`; avoid a post-spawn numeric-PID migration race. Use whole-cgroup kill on failure and require `populated=0` plus exact-child reaping before release/removal. The kernel describes inheritance and controllers in its [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The Rust supervisor still needs a separate service/aggregate memory budget; per-worker cgroups cannot certify that its request vectors or memfds are bounded by worker limits. Global no-swap admission is appropriate if claiming that gate-held request/output bytes cannot swap: `memory.swap.max=0` on worker groups alone does not cover the gate. A startup no-swap check assumes trusted administrators do not change host policy later. Swap-free anonymous RAM is not cryptographically erased RAM.

**Verification:** use bounded benign fixtures to exceed the configured memory budget and show local cgroup OOM/failure with staged output withheld. Observe exact worker membership, configured/read-back controller values, `memory.events`, peak/current values, CPU throttling and pids limits. Prove cleanup after success, crash, timeout, gate death and setup refusal. Preserve a healthy concurrent control request. Measure supervisor RSS/cgroup use separately at default and maximum admitted concurrency; do not promote worker accounting to a whole-host guarantee.

### P2 — Preserve the trust and confidentiality boundary in product claims

Evidence: Landlock allows reads beneath the entire curated root (`main.c:120-121`); returned worker output intentionally leaves the sandbox (`main.rs:283`). There is no semantic correctness oracle, and a compromised worker may return malicious or secret-bearing output while exiting zero. Anything placed in the request or readable rootfs is available to that worker. The runtime shares the host kernel and the ingress/launcher currently execute with root authority.

**Required wording:** “fresh execution with denied direct persistent worker effects, under a trusted Linux host and a curated secret-free rootfs.” Do not claim physically impossible compromise, arbitrary data theft prevention, no remaining patch requirement, zero configuration cost, universal PHP-FPM drop-in compatibility, or authenticated computation. A hash demonstrates byte identity only.

**Next product work after hardening:** support one exact read-only workload first; publish a generated dependency/rootfs manifest and a concrete ingress configuration; measure app compatibility and total deployment steps. State/secret brokers require independent authorization and narrowly scoped outputs, not worker-authored COMMIT receipts. A microVM backend would change the shared-kernel boundary, at additional cost that needs measurement.

### P2 — Strengthen release proof without converting stored logs into fresh tests

The existing integration harness has useful positive controls: exact binary echoes, host worker reaping before response (`test_ephemeral_lifecycle.py:190-201`), fresh temporary state (`223-229`), caught filesystem denial (`242-246`), and distinct concurrent workers (`274-282`). Keep them. Extend the suite for parent startup races, memory accounting and host residue guards. Add parser-specific regression cases when parser code changes; the current two Rust tests target CGI framing only.

`scripts/verify_ephem_evidence.py` was rerun read-only in this review:

```text
python3 scripts/verify_ephem_evidence.py \
  --report reports/ephem/linux-lifecycle-v5.json \
  --freeze research/ephem/process/SOURCE-FREEZE-v5.json --experimental

exit 0
result: BOUNDED_EXPERIMENT_PASS
errors: []
production: HOLD
world_rank: UNMEASURED
```

This confirms consistency of the stored report and current frozen source hashes. It does not rebuild, execute Linux primitives, attest the toolchain, or independently reproduce the recorded runtime result. The verifier does not itself validate every deployed artifact against the report; bind the new release's source/build/runtime binary hashes explicitly. Preserve v5 as historical evidence when any security source changes, and issue a new freeze/report version.

## Recommended implementation order

1. Close the expected-parent startup race and add its regression probe.
2. Add strict host no-swap/no-piped-core admission and gate dump controls.
3. Add fail-closed worker cgroup admission, accounting and complete teardown, with a separately stated supervisor budget.
4. Rerun the retained lifecycle, independent, policy and unchanged PHP fixture checks on the dedicated Linux VM; add new controls without weakening previous expectations.
5. Publish the resulting narrow experimental contract, supported host requirements, limitations and raw proof paths. Keep production qualification and external independent audit outstanding until actually performed.

No runtime source, archived artifact or existing proof report was modified by this review.
