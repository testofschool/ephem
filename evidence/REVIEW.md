# Stored-evidence consistency review

Reviewed on **2026-10-23 KST** against the current checkout and [source-freeze.json](source-freeze.json). This is an independent agent's review of downloaded records, not a new Linux execution, external security audit, reproducible-build attestation or production approval. The retained `arm64-v1` and final `arm64-v2` files, [build-v2 receipt](build-v2/receipt.json), downloaded AArch64 executables and current [RESULTS.md](RESULTS.md) were read without modification. Only this review file was updated.

**Result: the bounded functional claims below agree with the stored evidence. Production qualification and comparative performance claims remain HOLD.**

## Source and artifact identity

- Recomputed all **24** SHA-256 entries in `source-freeze.json` from the current local files: **24 match, 0 missing, 0 mismatched**. This includes the gate, resource module, launcher, active seccomp policy, build helpers and test sources.
- The lifecycle preregistration's test-source hashes and acceptance contract match the final lifecycle report. Its source hashes also match the current source freeze. The boundary and seccomp preregistration hashes recompute exactly to the SHA-256 values declared in their reports. The PHP preregistration hash also matches its report.
- The final v2 gate and jail hashes agree across lifecycle, boundary, PHP and build receipts. Independently rehashing the downloaded executables in `dist/linux-aarch64` produced the same values:

| Artifact | Recorded SHA-256 |
| --- | --- |
| `ephem-gate` | `4eaf7d844cf8791cbce87e359d2c5dba54ad08cfb3622a7af429134950aff2ab` |
| `ephem-jail` | `cfcc923329f8cf23bb94f636fb9a315401240e42db7eed5d6bd88f5c4e574894` |
| Static lifecycle/boundary fixture | `d8edead9110c1f016d4fea8de52dd96916e4bb81f46c7bf6125d58c3d5606fa3` |

The downloaded gate is **1,250,488 bytes**, and the jail is **73,272 bytes**. This confirms local binary identity against v2 records; it is not an independent reproducible-build attestation. The earlier v1 gate has a different recorded hash, `b329038325e1e9bdfbe83d553b0b41afffcbd2364c7d26d4bfb598ec9fc6b9cc`; jail and fixture hashes are unchanged. The exact frozen source files still match, but do not describe the gate binary as byte-identical between v1 and v2. The lifecycle preregistration freezes the test contract and test sources; binary hashes are added to its final report during setup. The boundary preregistration separately records its gate/jail/fixture hashes before its probes.

The later reproduction helper [`tests/ephem/build-patched-php.sh`](../tests/ephem/build-patched-php.sh) is **outside the pre-run 24-file freeze**. Its reviewed local SHA-256 is `65ee558a1cb74f3ded3a4a596a77493253068b29d163843bca1880551d3f3a2d`. It was added for reproduction documentation; its execution is not established by these runs. The final PHP fixture reused the previously built, pinned CGI binary and rootfs. Do not expand the original freeze or label that new helper tested by association.

## Final v2 records reconciled

The environment record names Linux **6.8.0-146-generic, AArch64**, Rust/Cargo **1.99.1**, GCC **13.3.0** and a `/proc/swaps` header with no active entries. These results do not establish execution on x86-64 or other kernels.

| Area | Verified observation | Record |
| --- | --- | --- |
| Build and lint | Explicit receipts for formatter, Clippy, unit tests, release build and C jail build: **5 commands, all returncode 0**. Unit stdout shows **5 passed, 0 failed**. | [Receipt](build-v2/receipt.json), [unit stdout](build-v2/2.stdout), [raw logs](build-v2/) |
| Lifecycle | **12 tests**, **0 failures**, **0 errors**, **0 skips**, reported exit **0**; stderr independently lists all 12 tests as `ok`. | [JSON](arm64-v2/integration/lifecycle.json), [stderr](arm64-v2/integration/lifecycle.stderr) |
| HTTP observations | **158** observations: **135 HTTP 200**, **16 HTTP 500**, **7 HTTP 400**. The seven malformed/oversized-input refusals account for the difference from executed request scopes. | [Lifecycle JSON](arm64-v2/integration/lifecycle.json) |
| Disposal | **151** resource-accounting records, **151 unique scope names**, every record `disposed:true`. The extracted `resource_disposals` array exactly matches the gate log. Each of its **151** execution outcome records is immediately preceded by a disposal record. | [Lifecycle JSON, `gate_log` and `resource_disposals`](arm64-v2/integration/lifecycle.json) |
| Fresh processes | The initial freshness check records **50 distinct host worker PIDs**. Successful-response checks also verify that their observed host PID is absent after response delivery. | [Lifecycle JSON](arm64-v2/integration/lifecycle.json), [test source](../tests/test_ephemeral_lifecycle.py) |
| Kernel OOM path | One scope records `memory_peak_bytes=134217728`, `oom=1`, `oom_kill=3`, `disposed:true`, followed by `accepted:false` for request **156**. The corresponding `MEMORY` observation is HTTP **500** with a fixed error body and no success digest; the next `ECHO after-oom` observation is HTTP **200**. | [Lifecycle JSON](arm64-v2/integration/lifecycle.json) |
| Boundary checks | **7 named probes PASS**: persistent chroot control; fresh private tmp; stdout receipt forgery treated as data; CGI body hash/header rejection; partial-request deadline; owned launcher death; exact fixture executable cleanup. | [Report](arm64-v2/integration/boundaries.json), [raw](arm64-v2/integration/boundaries.json.raw.json) |
| Direct seccomp | **5 probes PASS**: `peer0` and `vma0` reach expected errno results; `peer1`, `vma-high` and `dumpable` terminate with reported **SIGSYS (-31)**. | [Report](arm64-v2/integration/seccomp.json), [preregistration](arm64-v2/integration/seccomp.json.preregistration.json) |
| Fail-closed admission | **6 negative controls PASS**: four gate cgroup-path/configuration refusals before socket binding, plus missing/wrong expected-parent launcher refusals with exit **125**. | [Preflight](arm64-v2/integration/preflight.json) |
| Piped core refusal | Separate control reports exit **1** and `piped host core handlers are unsupported` under the captured original piped core pattern. | [Core refusal](arm64-v2/core-refusal.json) |
| Pre-main orphan race | **1 controlled orphan probe PASS**: launcher resumed after its expected supervisor died, rejected before starting a worker, and was reaped with exit **125**. | [Parent race](arm64-v2/integration/parent-race.json), [probe source](../tests/ephem/parent_race.py) |
| Real PHP-CGI | **4 HTTP 200** observations: two sequential and two concurrent benign uploads; all exact response bytes and response/header digests recompute correctly; **4 distinct host PIDs**; unchanged receiver hash before/after and inside rootfs. **4** disposal records have zero OOM counters. | [PHP report](arm64-v2/php.json), [preregistration](arm64-v2/php.preregistration.json), [gate log](arm64-v2/php.gate.log) |

For the boundary raw responses, all stored body SHA-256 values recompute correctly from `body_hex`, and successful-response header digests match those bodies. The PHP report's literal bodies independently match the preregistered JSON bytes and SHA-256. Its receiver SHA-256 agrees with the local source freeze. The historical response label `patched-php-fpm` does not change the recorded **PHP 8.3.36 CGI (`cgi-fcgi`)** SAPI.

The OOM values are the trusted gate's captured reads of the kernel cgroup counters, not three observed worker identities. **Do not interpret `oom_kill=3` as proof that three workers ran or died.** The code reads `memory.events` and `memory.peak` after the group becomes unpopulated and logs only after directory removal. Standalone copies of the control files were not retained.

The lifecycle preregistration field `contract.requests=50` names the initial freshness-check count. It must not be quoted as the total request count: the stored observation array contains **158 HTTP exchanges**.

## Timing reconciliation and retained v1

Recomputed all quantiles from the final v2 raw arrays: **50 samples per condition**, nearest rank `ceil(n*p)`, no samples removed. These values exactly match `RESULTS.md`:

| Final v2 condition | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Raw cold fixture execution | 0.338966 | 0.482178 | 0.630181 |
| Complete sandbox UDS HTTP request | 1.854501 | 2.195174 | 2.245218 |

For even sample counts, the nearest-rank p50 is not the two-center-value arithmetic median. The latter is **0.3415705 ms** raw and **1.859584 ms** sandbox; there is no inconsistency because `RESULTS.md` specifies nearest rank.

The earlier [v1 lifecycle report](arm64-v1/integration/lifecycle.json) also records 12 passing tests, 158 HTTP observations and 151 disposals. Its timing overlapped a separately reported Cargo build; preserve it as a confounded attempt. Its recomputed nearest-rank p95 values are **14.501685 ms** raw and **114.092019 ms** sandbox. The v1 arithmetic medians are **1.965300 ms** and **11.567031 ms**, respectively. No host-utilization trace was retained to independently reconstruct the interference. A second run with a separately identified rebuilt gate does not establish which proportion of the timing change arose from interference, rebuild effects or other run-to-run variation.

These are different raw and full-request paths, not a warmed baseline, isolated launch-cost measurement, realistic PHP benchmark, sustained-load test, competitor comparison or latency SLA. Comparative performance rank remains **UNMEASURED**.

## Build and host receipt gaps resolved by v2

The original [v1 fmt log](arm64-v1/fmt.log) lacked an explicit invocation/exit receipt. The final [build-v2 receipt](build-v2/receipt.json) now records `cargo fmt --all -- --check` with returncode **0**, plus four other successful commands. Their raw stdout/stderr files are retained beside the receipt. This resolves the specific formatter reporting gap for the final build.

The same receipt records `core_pattern_restored=true`, `active_swap_entries=0` and `remaining_ephem_cgroups=[]`. These are the run coordinator's captured final observations; no live VM inspection was performed by this reviewer. They resolve the missing post-run receipt in the downloaded record. They are not continuous policy attestation or proof of physical erasure.

## Material limits and unresolved evidence

1. **Build identity remains bounded.** The downloaded binaries independently hash to the final v2 identities, and all 24 frozen sources match. The historical v1 gate differs from v2; source equivalence must not be described as binary equivalence. A third-party reproducible build or signed build attestation was not performed.
2. **Host policy is narrow.** No active-swap refusal trial, hibernation/crash-dump audit, physical-memory-erasure test or continuous host attestation was executed. Core/swap admission and the restored-policy receipt must not be extended to those claims.
3. **Resource qualification is partial.** Actual worker-group OOM and disposal were observed. This does not measure supervisor/whole-host memory, aggregate-pressure survival, CPU throttling, PID saturation, production throughput, arbitrary cancellation or every setup-failure cleanup path. Limits are configured/read back in source; do not relabel unmeasured behavior as a passed live test.
4. **No general data-loss-prevention claim.** The final lifecycle probe `READSECRET` returns the synthetic readable canary in an HTTP **200** response. This is an explicit successful-output confidentiality counterexample, as required by the documented threat model. Disposal cannot undo a response already authorized for release.
5. **No external security or broad compatibility qualification.** These are benign, source-controlled probes in one VM. Shared-kernel escape resistance, compromised-host resistance, arbitrary applications, PHP-FPM, stateful frameworks, sessions, remote services and database rollback remain unestablished. The root gate's protocol-facing privilege is still a documented material risk.
6. **Post-freeze helper is unqualified.** The new PHP build helper is clearly separate from the executed 24-file source freeze. It needs a new frozen execution record before claiming that its complete build procedure was reproduced.

The counts, OOM values, binary hashes, PHP observations and nearest-rank timing values in the reviewed `RESULTS.md` agree with the final v2 records. It now distinguishes unchanged frozen source from the separately identified rebuilt gate binary; no remaining count or quantile discrepancy was found. The current README, threat model, operations guide and roadmap retain experimental status, production HOLD, a shared host kernel, a trusted root gate/launcher, real host setup cost, current-request output leakage, continued patch requirements and no world-first or comparative-ranking claim.
