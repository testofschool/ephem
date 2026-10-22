# Zero profile — executed result

This branch fixes the named ambient-root-secret replay and implements an encrypted-only, one-shot handoff in the owned lab. It does not achieve the universal claim that any unpatched system is physically impossible to steal from.

| Check | Executed observation |
| --- | --- |
| Original `READSECRET`, same input and worker | Secret-bearing responses **1 → 0**, one fresh run per arm |
| Exact root manifest and mutation refusals | **26/26 probes PASS** |
| Rust format, Clippy, units and release build | **7/7 unit tests PASS**, build exit 0 |
| Final client/relay/store units | **32/32 PASS** on Mac and Linux |
| Separate Mac client and real installed Linux gate/relay | **9/9 PASS** |
| Sample of owned relay writable private memory | **371,998,720 bytes, 86 mappings; 0 test plaintext/raw-key/encoded-key matches** |
| Source and installation consistency | **38 frozen source files match**, installed client/server readbacks match |
| Evidence gate negative controls | Valid bundle exits 0; source drift, stale test count and raw response tampering each exit 1 |

Raw reports, source freezes and failures are retained in this directory. The exact scope and reproduction commands are in [ZERO_PROFILE.md](../../docs/ZERO_PROFILE.md). The independent in-session source/evidence review is [claims-review.md](claims-review.md); it is not an external security audit.

## Device and installation

`packaging/zero-entrypoint.sh` refuses missing `EPHEM_ROOT_MANIFEST`; the gate verifies that external policy before binding and before each worker launch. The manifest establishes byte identity, not semantic absence of secrets. The encrypted relay supplies only ciphertext to a worker and never receives the supported client's decryption key.

The installed server was read back and run at `/opt/ephem-zero-lab-v1` in the owned Linux VM; the corrected client was installed separately at `/Users/felix/Desktop/php2shell/.runtime/ephem-zero-client-v2`. The session was stopped and its socket directory and cgroup removed after tests. No public production service is running.

The static-worker minimal-root builder is deliberately narrower than arbitrary CGI or stateful application migration. Metadata and ciphertext remain visible to the service. Current-request plaintext remains returnable by a plaintext worker, as an explicit positive counterexample records. Host administrators, the gate/relay, kernel, client, provisioning and cryptographic implementation remain trusted. Patch them.

## Force-solution result and census

The selected upstream converged escape is recorded in [upstream-selection.json](upstream-selection.json). The new encrypted relay is marked as a designer extension excluded from candidate selection. [SOLUTION.json](SOLUTION.json) names the bounded problem; the unmodified canonical skill checker returned **SOLVED, exit 0** for those device/replay/delivery fields ([raw output](solution-check.json)). That checker does not validate the separate global census or prove the universal objective.

The skill requires `memory_list(include_preview=true)`, which is unavailable in this session. Its canonical census is **UNUSABLE, exit 2**; there is no canonical completion line. The finite local inventory read 381 files / 184,593 lines with 207 outcome-bearing records. This is local coverage only ([status](census-status.json)). The full owner-record census remains **BLOCKED**, and universal patchless/physical-theft immunity remains **NOT_SOLVED**.

Run `python3 scripts/verify-zero-evidence.py` to check this bundle's stored consistency. Exit 0 does not rerun the experiments or certify production security. `scripts/verify-evidence.py` intentionally remains the separate historical alpha source-freeze check; the old freeze is preserved.

## Failed attempts preserved

- `root-replay-v1.json`: FAIL because a cleanup assertion incorrectly counted cgroup control files as leftovers. Only that test assertion changed before the v2 rerun; runtime bytes did not. The failed report is retained.
- `live-client-v1.json` and `server-live-client-v1.json`: FAIL before any live probes because the Node installation had non-root ownership. Root ownership was corrected; the admission check was retained.
- A later review found the client could over-allocate for a file growing after its initial size check, or hang while opening a FIFO. The bounded reader and two focused regressions fix that availability defect. Final v3 tests and live run exercise the corrected client. Earlier v2 measurements remain separate.
