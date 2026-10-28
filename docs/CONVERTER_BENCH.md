# Sandboxing `pdftotext` on untrusted uploads: five ways, one host, measured

If your service runs `pdftotext` (Poppler) on files strangers upload, you have probably looked at bubblewrap, nsjail or gVisor. This page puts them side by side on one machine, with one binary and one corpus, and adds EPHEM (this repo's jail). Every number links to raw data in `evidence/`.

**What was measured:** wall time per call (spawn → output EOF → reap), whether the extracted text is byte-identical to an unsandboxed run, whether a file written to `/tmp` by one call is visible to the next call, and whether the arm runs without root.

## Results

Host: 2 vCPU x86_64 cloud VM, Ubuntu 24.04.5, kernel 6.18.44, pdftotext 24.02.0 (same binary sha256 `46e5639c…` in every arm). 50 synthetic one-page PDFs × 20 timed rounds after 5 warm-up rounds = 1,000 timed calls per arm, run one at a time. Nearest-rank percentiles.

| Arm | Text equal to raw | p50 ms | p95 ms | p99 ms | `/tmp` marker seen by next call (seq · 8 concurrent) | Runs as non-root on this host | Kernel |
|---|---|---|---|---|---|---|---|
| raw `pdftotext` | 50/50 (reference) | 7.14 | 9.57 | 11.19 | 100/100 · — (positive control) | yes | host |
| bubblewrap 0.9.0 | 50/50 | 9.62 | 13.07 | 14.49 | 0/100 · 0/100 | yes | shared host kernel |
| nsjail | 50/50 | 10.64 | 14.40 | 17.42 | 0/100 · 0/100 | yes | shared host kernel |
| EPHEM `ephem-jail` | 50/50 | 9.09 | 12.14 | 13.47 | 0/100 · 0/100 | **no — requires root** (rc 125) | shared host kernel |
| gVisor `runsc` | 50/50 | 106.98 | 134.49 | 151.58 | 0/100 · 0/100 | yes (`--rootless`) | user-space kernel |

Sources: latency and residue from [`evidence/converter-bench-v1/REPORT.md`](../evidence/converter-bench-v1/REPORT.md) (raw samples in `raw/*.csv`, commands in `commands.txt`); the non-root column from [`evidence/converter-bench-v1-privilege/PRIVILEGE_PROBE.md`](../evidence/converter-bench-v1-privilege/PRIVILEGE_PROBE.md).

## How to read this

- **The arms are not ranked.** They draw different boundaries. bubblewrap, nsjail and EPHEM share the host kernel, so a kernel bug is shared too. gVisor puts a user-space kernel in between; its calls took about 100 ms longer here (sandbox start-up was not separated from the work).
- **EPHEM needs root** (`docs/OPERATIONS.md`: "The operator needs namespace/mount/credential privileges"). If your image must run as non-root, EPHEM is not an option today. bubblewrap, nsjail and rootless gVisor ran unprivileged here, but only because this host allows unprivileged user namespaces. **Docker's default seccomp profile and many hosts disable them. That case was not measured.**
- In the sandboxed arms the worker ran as uid 65534 with a fresh tmpfs `/tmp`. EPHEM additionally applies seccomp (one `execve`, no sockets), Landlock, rlimits and drops all capabilities. The other arms used only the flags in `commands.txt`.
- **Limits:** the PDFs are tiny and synthetic; only one residue channel (`/tmp`) was tested; the arms ran one after another, not interleaved; absolute milliseconds are specific to this host.

## Reproduce

The procedure (`HANDOFF_EPHEM_CONVERTER_BENCH_v2.md`) and corpus generator (`gen_corpus.py`; manifest sha256 `616d20d5…`) are in [`evidence/converter-bench-v1-procedure/`](../evidence/converter-bench-v1-procedure/); the harness (`bench.py`, `make_report.py`) is in `evidence/converter-bench-v1/`. Corrections are welcome as issues.
