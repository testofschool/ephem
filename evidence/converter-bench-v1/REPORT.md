# EPHEM converter benchmark v1 — REPORT (executed per HANDOFF v2)

Host: Claude Code cloud session, x86_64, 2 vCPU, kernel 6.18.44, Ubuntu 24.04.5. Run start 2026-10-27T07:50:05Z. Nothing was committed, pushed, posted or sent.

## 1. Pre-registered values

| # | Item | Expected | Observed | Match |
|---|---|---|---|---|
| P1 | HEAD after checkout | 380849c6…377b852a | 380849c6a1686772f1134da52336330c377b852a | ✅ |
| P2 | v0.3.0-stateful-alpha | 1320713d…af6d | 1320713d065f04ae701026e14edf46226e71af6d | ✅ |
| P3 | sha256 gen_corpus.py | 087f1233…5f72 | 087f123348af3964e6d38006fae1e95059065004fd889e46c1e2cea5383c5f72 | ✅ |
| P4 | corpus MANIFEST sha256 | 616d20d5…3e64 | 616d20d5ad078e9f65c16adf9531672508fe60c121b5df5d2ced56324f043e64 | ✅ |
| P5 | corpus count | 50 PDF + 1 manifest | 50 + 1 | ✅ |
| P6 | positive control present (raw, shared /tmp) | > 0 | 100/100 | ✅ (test valid) |
| P7 | sandboxed present, seq + concurrent | 0 | 0 in all 8 cells (bwrap, nsjail, ephem, gvisor × 2 modes) | ✅ |
| P8 | output equality vs raw | 50/50 per arm | 50/50 in all 5 arms; 0 of 5,000 timed runs differed | ✅ |
| P9 | jail smoke DIRTY/CLEAN | written / absent, rc 0 | written / absent, rc 0, exit_code 0 | ✅ |
| P10 | raw doc00 sha256 (pdftotext 24.02.0) | 8b31b66f…3712 | 8b31b66f26100224fceb735076e4c6e46eed33f9b6640f69e48f025008453712 | ✅ |
| P11 | jail with rootfs under /tmp | rc 125, trusted root-owned path | rc 125, 'requires a trusted root-owned rootfs path' | ✅ |

## 2. Track A — `pdftotext` (pdftotext 24.02.0, same binary sha256 46e5639c… in every arm)

Wall time from spawn to stdout EOF + reap, 50 files × 20 timed rounds after 5 warm-up rounds, run one at a time. Nearest-rank percentiles, recomputed from `raw/trackA_*.csv` by a second script (match).

| Arm | Output equal to raw | Timed runs | p50 ms | p95 ms | p99 ms | max ms | Worker identity | Kernel |
|---|---|---|---|---|---|---|---|---|
| raw | 50/50 | 1000 | 7.14 | 9.568 | 11.185 | 16.862 | host uid 0 | host |
| bwrap | 50/50 | 1000 | 9.62 | 13.065 | 14.488 | 17.998 | uid 65534, userns | shared host kernel |
| nsjail | 50/50 | 1000 | 10.64 | 14.403 | 17.415 | 26.939 | uid 65534 | shared host kernel |
| ephem | 50/50 | 1000 | 9.093 | 12.143 | 13.465 | 18.474 | uid 65534 | shared host kernel |
| gvisor | 50/50 | 1000 | 106.98 | 134.488 | 151.578 | 174.089 | uid 65534 | user-space kernel (Sentry) |

No arm is ranked. The arms differ in boundary: EPHEM, bwrap and nsjail share the host kernel; gVisor interposes a user-space kernel. EPHEM additionally applies seccomp (execve allowed once), Landlock, rlimits and drops all capabilities; the other arms were run with the flags in `commands.txt` only.

## 3. Track B — cross-request residue (`/tmp/marker` written by DIRTY, probed by CLEAN)

| Arm | Mode | Pairs | DIRTY `written` | CLEAN `present` | CLEAN `absent` | non-zero rc |
|---|---|---|---|---|---|---|
| raw | sequential | 100 | 100 | 100 | 0 | 0 |
| bwrap | sequential | 100 | 100 | 0 | 100 | 0 |
| bwrap | concurrent8 | 100 | 100 | 0 | 100 | 0 |
| nsjail | sequential | 100 | 100 | 0 | 100 | 0 |
| nsjail | concurrent8 | 100 | 100 | 0 | 100 | 0 |
| ephem | sequential | 100 | 100 | 0 | 100 | 0 |
| ephem | concurrent8 | 100 | 100 | 0 | 100 | 0 |
| gvisor | sequential | 100 | 100 | 0 | 100 | 0 |
| gvisor | concurrent8 | 100 | 100 | 0 | 100 | 0 |

**EPHEM concurrent (8 in flight) marker-crossing, the case the repo had not measured: 0/100 present.**

## 4. UNRUN and fallbacks taken

- None UNRUN. All five arms (raw, bwrap, nsjail, EPHEM, gVisor) ran both tracks.
- nsjail: apt package unavailable -> built from source (google/nsjail 4ff54a6e).
- gVisor: release URL 404 -> gVisor apt repo (runsc release-20261019.0).
- Rust 1.99.1 not installed: no arm uses ephem-gate; host rustc 1.97.0 recorded, unused.
- Parity flags added beyond v2 §5 examples: bwrap --uid/--gid 65534 and nsjail -u/-g 65534 --disable_proc, so every sandboxed worker runs as uid 65534 (measured with fixture ID). Recorded in commands.txt.

## 5. Build-input changes

- none — EPHEM source unchanged; ephem-jail built with packaging/build-jail.sh as shipped (sha256 9c53bd1f…).

## 6. Limits of this result

- 2 vCPU cloud VM (kernel 6.18.44-fc-v165; the hypervisor type is not verified); absolute ms are host-specific. Arms ran one after another, not interleaved, so slow drift between arms is not excluded.
- Latency is whole-process wall time (spawn→EOF→reap) dominated by pdftotext itself (~7 ms raw p50); sandbox overhead is the difference, not the headline number.
- Concurrent residue: 100 pairs, 8 workers; a separate check measured 8 pairs actually in flight at peak (EPHEM, gVisor), 0 present.
- Residue covers one channel only: a file in /tmp. Other channels (env, IPC, kernel state) were not tested.
- Corpus is 50 tiny synthetic one-line PDFs; real-world documents are untested.
