# Stored-evidence consistency review

Reviewed on **2026-10-23 KST** against the current checkout and [source-freeze.json](source-freeze.json). This is an independent agent's review of downloaded records, not a new Linux execution, external security audit, reproducible-build attestation or production approval. The `arm64-v1` files were read without modification. The separately planned second run is outside this review.

**Result: the bounded functional claims below agree with the stored evidence. Production qualification and comparative performance claims remain HOLD.**

## Source and artifact identity

- Recomputed all **24** SHA-256 entries in `source-freeze.json` from the current local files: **24 match, 0 missing, 0 mismatched**. This includes the gate, resource module, launcher, active seccomp policy, build helpers and test sources.
- The lifecycle preregistration's test-source hashes and acceptance contract match the final lifecycle report. Its source hashes also match the current source freeze. The boundary and seccomp preregistration hashes recompute exactly to the SHA-256 values declared in their reports. The PHP preregistration hash also matches its report.
- The recorded gate and jail hashes agree across lifecycle, boundary and PHP records:

| Artifact | Recorded SHA-256 |
| --- | --- |
| `ephem-gate` | `b329038325e1e9bdfbe83d553b0b41afffcbd2364c7d26d4bfb598ec9fc6b9cc` |
| `ephem-jail` | `cfcc923329f8cf23bb94f636fb9a315401240e42db7eed5d6bd88f5c4e574894` |
| Static lifecycle/boundary fixture | `d8edead9110c1f016d4fea8de52dd96916e4bb81f46c7bf6125d58c3d5606fa3` |

The downloaded bundle does **not** contain these executable files, so their bytes could not be independently rehashed locally. Agreement is cross-record consistency, not independent proof of the source-to-binary build relationship. The lifecycle preregistration freezes the test contract and test sources; binary hashes are added to its final report during setup. The boundary preregistration separately records its gate/jail/fixture hashes before its probes.

## Executed records reconciled

The environment record names Linux **6.8.0-146-generic, AArch64**, Rust/Cargo **1.99.1**, GCC **13.3.0** and a `/proc/swaps` header with no active entries. These results do not establish execution on x86-64 or other kernels.

| Area | Verified observation | Record |
| --- | --- | --- |
| Build and lint | Release build and Clippy logs finish successfully; unit log shows **5 passed, 0 failed**. | [Build](arm64-v1/build.log), [Clippy](arm64-v1/clippy.log), [unit](arm64-v1/unit.log) |
| Lifecycle | **12 tests**, **0 failures**, **0 errors**, **0 skips**, reported exit **0**; stderr independently lists all 12 tests as `ok`. | [JSON](arm64-v1/integration/lifecycle.json), [stderr](arm64-v1/integration/lifecycle.stderr) |
| HTTP observations | **158** observations: **135 HTTP 200**, **16 HTTP 500**, **7 HTTP 400**. The seven malformed/oversized-input refusals account for the difference from executed request scopes. | [Lifecycle JSON](arm64-v1/integration/lifecycle.json) |
| Disposal | **151** resource-accounting records, **151 unique scope names**, every record `disposed:true`. The extracted `resource_disposals` array exactly matches the gate log. Each of its **151** execution outcome records is immediately preceded by a disposal record. | [Lifecycle JSON, `gate_log` and `resource_disposals`](arm64-v1/integration/lifecycle.json) |
| Fresh processes | The initial freshness check records **50 distinct host worker PIDs**. Successful-response checks also verify that their observed host PID is absent after response delivery. | [Lifecycle JSON](arm64-v1/integration/lifecycle.json), [test source](../tests/test_ephemeral_lifecycle.py) |
| Kernel OOM path | One scope records `memory_peak_bytes=134217728`, `oom=1`, `oom_kill=3`, `disposed:true`, followed by `accepted:false` for request **156**. The corresponding `MEMORY` observation is HTTP **500** with a fixed error body and no success digest; the next `ECHO after-oom` observation is HTTP **200**. | [Lifecycle JSON](arm64-v1/integration/lifecycle.json) |
| Boundary checks | **7 named probes PASS**: persistent chroot control; fresh private tmp; stdout receipt forgery treated as data; CGI body hash/header rejection; partial-request deadline; owned launcher death; exact fixture executable cleanup. | [Report](arm64-v1/integration/boundaries.json), [raw](arm64-v1/integration/boundaries.json.raw.json) |
| Direct seccomp | **5 probes PASS**: `peer0` and `vma0` reach expected errno results; `peer1`, `vma-high` and `dumpable` terminate with reported **SIGSYS (-31)**. | [Report](arm64-v1/integration/seccomp.json), [preregistration](arm64-v1/integration/seccomp.json.preregistration.json) |
| Fail-closed admission | **6 negative controls PASS**: four gate cgroup-path/configuration refusals before socket binding, plus missing/wrong expected-parent launcher refusals with exit **125**. | [Preflight](arm64-v1/integration/preflight.json) |
| Piped core refusal | Separate control reports exit **1** and `piped host core handlers are unsupported` under the captured original piped core pattern. | [Core refusal](arm64-v1/core-refusal.json) |
| Pre-main orphan race | **1 controlled orphan probe PASS**: launcher resumed after its expected supervisor died, rejected before starting a worker, and was reaped with exit **125**. | [Parent race](arm64-v1/integration/parent-race.json), [probe source](../tests/ephem/parent_race.py) |
| Real PHP-CGI | **4 HTTP 200** observations: two sequential and two concurrent benign uploads; all exact response bytes and response/header digests recompute correctly; **4 distinct host PIDs**; unchanged receiver hash before/after and inside rootfs. **4** disposal records have zero OOM counters. | [PHP report](arm64-v1/php.json), [preregistration](arm64-v1/php.preregistration.json), [gate log](arm64-v1/php.gate.log) |

For the boundary raw responses, all stored body SHA-256 values recompute correctly from `body_hex`, and successful-response header digests match those bodies. The PHP report's literal bodies independently match the preregistered JSON bytes and SHA-256. Its receiver SHA-256 agrees with the local source freeze. The historical response label `patched-php-fpm` does not change the recorded **PHP 8.3.36 CGI (`cgi-fcgi`)** SAPI.

The OOM values are the trusted gate's captured reads of the kernel cgroup counters, not three observed worker identities. **Do not interpret `oom_kill=3` as proof that three workers ran or died.** The code reads `memory.events` and `memory.peak` after the group becomes unpopulated and logs only after directory removal. Standalone copies of the control files were not retained.

The lifecycle preregistration field `contract.requests=50` names the initial freshness-check count. It must not be quoted as the total request count: the stored observation array contains **158 HTTP exchanges**.

## Material limits and unresolved evidence

1. **Performance HOLD.** The run coordinator reported a concurrent Cargo build during v1 timing collection. Preserve these samples as a confounded attempt. Recomputed medians are **1.965300 ms** for 50 raw cold fixture executions and **11.567031 ms** for 50 complete sandbox UDS HTTP requests; raw maximum is **69.596541 ms**, sandbox maximum **199.584914 ms**. These measure different paths and neither a warmed baseline nor a competitor. Do not market a latency/overhead rank from v1. The logs contain no host-utilization trace sufficient to reconstruct the interference independently.
2. **Format receipt is limited.** [fmt.log](arm64-v1/fmt.log) contains rustup installation messages and no formatter diagnostic or explicit command/exit-code receipt. That file alone cannot prove the formatter command's exact invocation or exit status. Build, unit and Clippy logs carry their own completion text; preserve explicit command/status receipts in future attempts.
3. **Host-policy restoration is not evidenced here.** The original piped core pattern and the refusal are captured, but v1 contains no post-run sysctl-restoration record. Successful launches are consistent with the startup checks accepting the temporary lab policy. They do not attest to continued policy or restoration. No active-swap refusal trial, hibernation/crash-dump audit, physical-memory-erasure test or continuous host attestation was executed in these records.
4. **Resource qualification is partial.** Actual worker-group OOM and disposal were observed. This does not measure supervisor/whole-host memory, aggregate-pressure survival, CPU throttling, PID saturation, production throughput, arbitrary cancellation or every setup-failure cleanup path. Limits are configured/read back in source; do not relabel unmeasured behavior as a passed live test.
5. **No general data-loss-prevention claim.** The final lifecycle probe `READSECRET` returns the synthetic readable canary in an HTTP **200** response. This is an explicit successful-output confidentiality counterexample, as required by the documented threat model. Disposal cannot undo a response already authorized for release.
6. **No external security or broad compatibility qualification.** These are benign, source-controlled probes in one VM. Shared-kernel escape resistance, compromised-host resistance, arbitrary applications, PHP-FPM, stateful frameworks, sessions, remote services and database rollback remain unestablished. The root gate's protocol-facing privilege is still a documented material risk.

The current README, threat model, operations guide and roadmap retain these important boundaries: experimental status; production HOLD; shared host kernel; trusted root gate/launcher; real host setup cost; current-request output leakage; continued patch requirements; and no world-first or comparative-ranking claim. No additional universal-security overclaim was found in those reviewed documents. Their linked `RESULTS.md` was not present when this review began; its eventual contents require their own consistency check.
