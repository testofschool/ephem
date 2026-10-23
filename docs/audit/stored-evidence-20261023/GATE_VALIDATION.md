# Stored evidence gate

Run with Python 3 and its standard library:

```sh
python3 verify_stored_evidence.py
python3 -m unittest discover -s tests -v
```

`--root` selects the root containing the preserved `reports/phase3/...` paths.
`--manifest` selects a manifest file whose exact bytes must match the SHA-256
pin in the gate. Defaults are relative to the script, so the package can move.

The four copied reports are byte-for-byte snapshots from commit
`1320713d065f04ae701026e14edf46226e71af6d`. The manifest retains the Git blob
SHA-1 identifiers and source URLs from `research/ephem_next/source_index.json`
and adds exact-byte SHA-256 and size. The manifest itself is pinned in the
gate. Updating evidence requires an explicit review and pin update; merely
rehashing a modified report does not make it pass this snapshot gate.

The successful result is `STORED_EVIDENCE_CONSISTENT`, with
`runtime_reexecuted=false`, `independent_security_audit=false`, and
`production_status=HOLD`. Any failed pin, missing data, or checked inconsistency
returns exit code 1 and `STORED_EVIDENCE_INCONSISTENT`.

The gate recomputes nearest-rank p50/p95/p99/max from each set of 1,000 native
samples, requires 100 recorded warmups, and preserves both separate observations.
For native lifecycle records it checks only the count of 13; it does not check
the individual receipt semantics. The result explicitly reports
`native_receipt_semantics_checked=false`; no lifecycle proof is supplied.
It recomputes every PHP signed delta as `isolated_ms - baseline_ms`, then the
percentiles from 100 complete pairs; the report records 20 excluded warmup pairs.
Warmup raw timings are not present, so exclusion is checked as a recorded count.
The PHP paired p95 of 3.730803 ms remains a failed `<2ms` gate; the full reproduce
script remains failed with exit 1, and four UNRUN fields retain their exact values.

The five distinct recorded injected faults must each have HTTP 500, a burned
receipt, zero `committed_mutations`, recovery `PASS`, and a matching receipt in
the recorded ledger. Each of these five fault receipts must record empty worker
output and `reaped`, `state_eof`, and `stdout_eof` all exactly `true`.
Worker status dictionaries must match the recorded fault type with exact fields
and types: SIGSEGV 11, SIGSYS 31, exit code 73, `timed_out`, or
`verifier_failed` with its recorded message. This verifies stored receipt
semantics without establishing whether the events actually happened.
`corrupted_committed_keys` remains zero. No
`staged_mutations` count exists in these reports; the result labels it
`UNRECORDED`. Recovery status is checked as reported rather than reexecuted.

This checks stored byte identity, recorded fields, and arithmetic. It supplies
no sandbox correctness claim, secret-absence claim, production readiness claim,
or semantic proof. It does not execute ephem, inspect source code, contact a
remote service, or interpret natural-language narrative as evidence of truth.

Validation completed: 24 unittest cases passed. The semantic mutation tests
operate on decoded copies independently of the file hashes; CLI tests verify
that corrupted files and a rehashed substitute manifest fail. The result and
test record are in `validation/evidence_gate_result.json` and
`validation/evidence_gate_tests.txt`.
