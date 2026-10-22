# Roadmap

EPHEM is an experimental request-isolation runtime. The next milestone is one reproducible, useful offline workload with a reviewed boundary and measured operational cost. Production qualification remains open. This document sets priorities, not delivery dates or claims of implemented features.

The current source includes mandatory request cgroups, host swap/core admission checks, expected-parent checks and output withheld through teardown. Their executed status belongs in [RESULTS.md](../evidence/RESULTS.md). The earlier gaps and their source provenance are preserved in [INITIAL_AUDIT.md](INITIAL_AUDIT.md).

## 1. Reduce privileged attack surface

Separate the network/protocol-facing gate from the privileged launcher. Keep request parsing, buffering and CGI interpretation unprivileged. Give a small launch broker fixed policy identifiers and descriptor-based inputs rather than arbitrary root-level commands, paths or mount instructions.

Acceptance evidence:

- A documented broker protocol and trusted/untrusted data inventory.
- Negative tests for unauthorized callers, descriptor confusion, path replacement, parent death and cancellation during setup.
- No change to the existing successful-output release conditions.
- External review of the privilege boundary, followed by a finding/retest record tied to the exact commit.

## 2. Complete operational resource and retention qualification

Request cgroups exclude the gate. Measure supervisor memory, staged output, aggregate concurrency and host overhead; provide an explicit service-level budget. Exercise worker OOM and supervisor pressure separately. Qualify cleanup after setup failure, timeout, crash, cancellation and gate termination.

Document artifact installation and upgrades, safe routing and rollback, startup refusal, stale owned resources and operator recovery. Make it possible to diagnose failures using fixed counters and synthetic evidence without collecting request payloads or credentials.

Acceptance evidence: raw measurements on a named Linux environment, complete ownership-scoped cleanup checks, retained failure cases, and an operations guide whose commands reproduce the accepted profile. Keep physical erasure and general host-forensic guarantees outside the claim.

## 3. Prove one realistic compatibility path

Choose an existing offline CLI or read-only CGI handler. Preserve its source/executable identity and compare its outputs with the existing path. Include realistic input sizes, malformed input, errors and supported headers, rather than only a tiny happy path.

Publish the dependency/rootfs manifest, required host setup and exact integration diff. Measure setup time and source/configuration changes separately. “No source edits” must name the tested program; it is not a promise that every application can be wrapped unchanged.

General sessions, database access, PHP-FPM replacement, background work and streaming should remain unsupported until their lifetime and side effects have an explicit design and evidence.

## 4. Add a backend with a different kernel boundary

Explore gVisor for host-syscall mediation and a Firecracker/Kata-style microVM backend for a separate guest kernel. These are design options, not current EPHEM capabilities. Reuse a small request contract while stating each backend's trusted components and requirements.

Acceptance evidence: the same lifecycle/failure controls on each backend; verified teardown and output gating; reviewed host interfaces; and measured startup/resource cost. Do not treat every backend as security-equivalent or claim that virtualization eliminates all escapes and side channels.

## 5. Publish a fair comparative benchmark

Begin with raw cold execution, a clearly named warm application baseline, EPHEM, nsjail and bubblewrap. Add gVisor and microVMs with their different isolation models visible. Use the same host, architecture, payloads, worker, resource policy and output checks where comparison is meaningful.

Report complete request latency and throughput under sustained concurrency, launch/cleanup costs, peak worker and supervisor memory, failure latency and resource leakage. Publish raw samples, versions, commands, quantile definitions and failed conditions. A tiny fixture is useful for mechanism cost; it is not an application benchmark or a security ranking.

## 6. Consider narrowly brokered external capabilities

Only after the offline path is useful, evaluate a specific need for a remote API or persistent operation. Keep long-lived credentials outside workers. Define per-request authorization, destination binding, minimal operation schemas, quotas, replay/idempotency rules and explicit commit semantics.

This work is not implemented. No generic DLP, database rollback or arbitrary-application transaction guarantee is promised. A compromised worker can misuse an operation it is authorized to request; a broker needs an application-specific authorization model.

## 7. Investigate startup optimization

Fresh exec is intentionally simple but repeats initialization. Compare that cost with preinitialized snapshots only after the supported workload and security contract are stable. Groundhog and serverless snapshot systems are relevant prior art.

A snapshot must predate request secrets. Entropy, credentials, identity, connections and external state need explicit handling. Multi-threaded runtime compatibility and a demonstrably clean restore are acceptance gates. There is no warmed-snapshot implementation today.

## What would justify production qualification?

A supported host/workload matrix, reviewed privilege boundary, measured worker and supervisor budgets, reproducible failure/cleanup evidence, safe upgrade and rollback procedures, and an external independent security assessment with resolved material findings.

Qualification would apply to that exact version and profile. It would not establish universal invulnerability, patch-free operation, zero customer effort or “nothing to steal.” The [threat model](THREAT_MODEL.md) remains part of the product contract.

See [PRIOR_ART.md](PRIOR_ART.md) for related systems and [CONTRIBUTING.md](../CONTRIBUTING.md) for proposing a change.
