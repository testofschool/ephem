# Independent x86_64 evidence ingestion

Date: 2026-10-23. Source commit and unchanged release tag target:
`1320713d065f04ae701026e14edf46226e71af6d`.
**Production: HOLD.** This work verifies supplied stored records and packages
them for review. It does not rerun EPHEM or perform an independent security audit.

## Source identities and dispositions

| Claim | Primary evidence / probe | Disposition and scope |
| :--- | :--- | :--- |
| x86 native p95 passes <2.0ms | All 1,000 values in [warm-native.json](../../evidence/x86-independent-v1/warm-native.json), nearest-rank index 949 | Confirmed stored arithmetic: 0.593124ms; not a production tail bound |
| 13 native lifecycle checks passed | All 13 cases and 23 worker receipts, compared with the pinned native harness | Confirmed recorded semantics: COW reset, SIGSEGV, eight classic seccomp SIGSYS denials with recovery, deadline, verifier and truncated IPC; every retained worker records EOF and reaping |
| x86 source/build identity | [upstream-commit.txt](../../evidence/x86-independent-v1/upstream-commit.txt), cargo logs and repository tag/commit | Declared source commit matches the release tag. Logs record 21 tests passed, 1 ignored real-PostgreSQL test, TEST_RC=0 and BUILD_RC=0. Clean source status and a source snapshot were not supplied |
| Binary checksums validated | [binary-sha256.txt](../../evidence/x86-independent-v1/binary-sha256.txt) and summary | Strings match internally. Actual x86 binary bytes are absent, so their hashes were not independently recomputed |
| Kernel and host profile | [env.txt](../../evidence/x86-independent-v1/env.txt) and summary | x86_64, kernel 6.18.44-fc-v140, Rust 1.99.1. Root/cgroup2 are summary assertions; CPU, microcode, distribution, VM/vCPU, affinity/governor, RAM, storage and load remain UNRECORDED |
| Full cross-architecture parity | Native-only archive and its explicit UNRUN fields | PARTIAL: native/classic-seccomp fixture compatibility only. PHP HTTP/paired timing, full reproduction checker, PostgreSQL live and BPF LSM are UNRUN on this x86 host |
| Earlier PHP gate failure disappeared | Original four pinned ARM64 reports and original stored-evidence gate | Contradicted: paired PHP p95 remains 3.730803ms FAIL and full script exit remains 1. Preserve all historical records |
| Sweep supports a commercial/adoption direction | Preserved ledger and check/rank/report script | Recomputed NO_PROPOSAL_BEATS_BASELINE. Ledger consistency is not market validation; no outreach is executed by this ingestion |

The report calls the source experiment an independent-host reproduction. This
ingestion verifies the supplied bytes and internal consistency; it does not
independently observe that host or certify containment. Warmup exclusion is a
recorded count; raw warmup timings are absent. The summary's command omits the
mandatory `--root` path and is an abbreviated invocation. A standalone native
exit-code transcript was not supplied; RC=0 is recorded in the summary.

## Exact x86 numbers and handoff corrections

| Statistic | Raw JSON value, ms |
| :--- | ---: |
| p50 | 0.44322300000000003 |
| p95 | 0.593124 |
| p99 | 0.7238249999999999 |
| max | 1.8941999999999999 |

The handoff examples' p50 0.380ms, p95 0.593ms, p99 0.840ms, max 1.210ms
and x86 kernel 6.8 are not the archive's values and are not used as results.
The ARM64 rows in the README retain each source run separately rather than
combining percentiles from different runs into a synthetic observation.

[Issue #4](https://github.com/testofschool/ephem/issues/4) also requests paired
PHP samples, adapter hashes and fuller host metadata. Those requirements are
not fulfilled by this archive. The owner selected keeping the issue open and
recording the native PASS plus these unmet requirements in a comment. This
ingestion does not claim complete x86 or production qualification.

## Preserved inputs and portable verification

Original archive SHA-256:

- `ephem-x86-reproduction.zip`: `92351d32208356ff3c9d63cc6d40358e625543cd36011320c84d063accfd4298`
- `EPHEM_Next_Step_2026-10-23.zip`: `278a049c3995515ecaab8059a751f206d768fffc0c3ef8341a159147d2fcb67f`

All eight x86 files are retained byte-for-byte. All 36 entries in the audit
ZIP's manifest were checked for size and SHA-256 before selecting ten relevant
audit/checker/sweep/workload-review files. Their original-to-repository mapping
is recorded in [the ingestion manifest](INGESTION_MANIFEST_20261023.json).
Outreach drafts and the wider research notes are not needed by these checkers.

The [original audit](INDEPENDENT_AUDIT_20261023.md), [gate](stored-evidence-20261023/verify_stored_evidence.py)
and [four-report manifest](stored-evidence-20261023/evidence_manifest.json) retain
their original bytes and pins. Their historical x86 UNRUN statement describes
that earlier invocation. It is not rewritten to imply a new execution.
The repository wrapper supplies the existing root `reports/` paths; the frozen
package's original standalone defaults require its original package layout.
The copied [gate description](stored-evidence-20261023/GATE_VALIDATION.md) and
[workload review](stored-evidence-20261023/WORKLOAD_REVIEW.md) are historical
guidance, not authorization for external contact or runtime deployment.

From the repository root:

```sh
python3 scripts/verify_stored_evidence.py
python3 scripts/verify_x86_evidence.py
python3 -m unittest discover -s tests -p test_stored_evidence.py -v
python3 -m unittest discover -s tests -p test_x86_evidence.py -v
python3 docs/audit/stored-evidence-20261023/process/direction_sweep.py check docs/audit/stored-evidence-20261023/SWEEP.json
python3 docs/audit/stored-evidence-20261023/process/direction_sweep.py rank docs/audit/stored-evidence-20261023/SWEEP.json
```

The historical checker intentionally validates only native receipt counts.
The x86 checker additionally validates all supplied native receipt semantics.
Neither command executes a worker, verifies missing binary bytes or upgrades
the scope to a security audit. PostgreSQL lost-COMMIT-ACK live injection remains
UNRUN; indeterminate commits must never be counted as zero writes.

The [current validation receipt](VALIDATION_20261023.json) records portable test
counts, both checker results, original-byte checks and sweep output comparisons.

## Release asset synchronization

The supplemental `ephem-phase3-x86_64-evidence.tar.gz` contains the eight original
files, flattened, plus an internal `SHA256SUMS.txt`. It contains evidence, not
x86 executable binaries. The existing ARM64 binary archive and release tag
remain at their original identities.

The release bundler prepares repository, staging and flattened-download
checksum lists. Upload the **staging** `SHA256SUMS.txt` together with
`DOWNLOAD_SHA256SUMS.txt` and the supplemental archive. Uploading the repository
root checksum file under that asset name would invalidate the existing
download manifest and its path contract. Repository root checksums separately
cover the new evidence, audit files, verifier/test sources and staged assets.

The prerelease remains experimental and **Production: HOLD**. Its new native
evidence does not supersede the recorded PHP latency failure, missing x86
adapter runs or optional enforcement gaps.
