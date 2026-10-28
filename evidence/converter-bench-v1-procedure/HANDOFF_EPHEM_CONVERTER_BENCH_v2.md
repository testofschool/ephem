# HANDOFF v2 — EPHEM converter benchmark (same-host, fair-denominator)

- **Executor machine:** one Linux **x86_64** host with root, user+PID namespaces, Landlock ABI ≥ 3, and a non-piped `/proc/sys/kernel/core_pattern`. Measured instance of this class: a Claude Code cloud session (Ubuntu 24.04.5, kernel 6.18.44, 2 vCPU, 30 GB free) on 2026-10-27. A Codex cloud task qualifies only if the §4 preflight passes on it. **Excluded:** Felix's Mac Studio and its Lima `ephem` VM. That host is ARM64 with about 136 MB free per Codex's 2026-10-27 report, so it can never satisfy the x86_64 condition.
- **Executor folders:** work in `/root/ephem-bench`. Every jail rootfs goes under `/opt/ephem-bench/` (see §3a for why).
- **Canonical inputs:** `github.com/testofschool/ephem` @ `380849c6a1686772f1134da52336330c377b852a`, plus the attachment `gen_corpus.py` (sha256 `087f123348af3964e6d38006fae1e95059065004fd889e46c1e2cea5383c5f72`). Everything runs on this one machine.
- **Supersedes** `HANDOFF_EPHEM_CONVERTER_BENCH.md` (v1). Changes from v1 are listed in §9. Do not reuse the v1 harness package (`EPHEM_CONVERTER_BENCH_V1.zip`): it was written and self-tested on ARM64 against the v1 jail invocation, which §3a shows is incomplete.

## 1. Goal (one sentence)
Produce the first fair, same-host measurement of EPHEM wrapping an existing executable (`pdftotext`) on identical benign inputs, next to raw exec, bubblewrap and nsjail. It covers latency, output equality and cross-request residue (sequential and concurrent).

## 2. Human gates (the only points where a person acts)
1. Felix pastes this file and `gen_corpus.py` into the executor session. That is the start.
2. After the report, Felix decides whether to commit `evidence/converter-bench-v1/` and whether any figure is used outward. This gate dissolves once Felix answers in the next session.

Everything else runs unattended. A failed step is recorded and every step that does not depend on it continues. A track that fails affects only that track; every other track still reports its own results and names the failed track. Report once, at the end.

## 3. Pre-registered values (check first; a mismatch is recorded and blocks only its dependent steps)

| # | Item | Expected value | Measured where | Dependent steps |
|---|---|---|---|---|
| P1 | `git rev-parse HEAD` after checkout | `380849c6a1686772f1134da52336330c377b852a` | x86_64 cloud, 2026-10-27 | all EPHEM steps |
| P2 | `git rev-list -n1 v0.3.0-stateful-alpha` | `1320713d065f04ae701026e14edf46226e71af6d` | same | report header only |
| P3 | `sha256sum gen_corpus.py` | `087f123348af3964e6d38006fae1e95059065004fd889e46c1e2cea5383c5f72` | same | corpus |
| P4 | stdout of `python3 -I gen_corpus.py corpus` | `616d20d5ad078e9f65c16adf9531672508fe60c121b5df5d2ced56324f043e64` | same | Tracks A, B |
| P5 | corpus file count | 50 PDFs + 1 `MANIFEST.sha256` | same | Tracks A, B |
| P6 | Track B positive control (raw exec, shared host `/tmp`): CLEAN replies `present` | **> 0** (0 → residue test INVALID) | not yet measured | Track B verdict |
| P7 | Track B sandboxed arms, sequential and concurrent: CLEAN replies `present` | **0**; any non-zero value is reported as a finding | EPHEM sequential n=1: `absent` (smoke, same host) | Track B verdict |
| P8 | Track A jailed/sandboxed `pdftotext` stdout vs raw exec, per file | byte-identical, **50/50** per arm | EPHEM doc00 n=1: identical (smoke) | Track A latency per arm |
| P9 | Jail smoke: fixture worker, `DIRTY` then `CLEAN` | stdout `written\n` then `absent\n`; both rc 0; stderr JSON `"exit_code":0` | x86_64 cloud, 2026-10-27 | EPHEM arms |
| P10 | raw `pdftotext corpus/doc00.pdf -` sha256 | `8b31b66f26100224fceb735076e4c6e46eed33f9b6640f69e48f025008453712` **only if** `pdftotext -v` = 24.02.0; other versions record the value and skip this check | same | none (version check only) |
| P11 | jail invoked with rootfs under `/tmp` (negative control) | rc 125, stderr `requires a trusted root-owned rootfs path` | same | none |

Reference only (not a pass condition, different binary): x86_64 native-callback lifecycle p95 0.593124 ms (`evidence/x86-independent-v1/X86_REPRODUCTION.json`).

### 3a. ephem-jail standalone invocation contract (read from `crates/ephem-jail/main.c` @ 380849c; P9/P11 measured)
The v1 line `ephem-jail --root ROOTFS --worker /path -- args` is necessary but not sufficient. A direct call also needs all of the following:
- **Environment:** `EPHEM_GATE_PID` = the PID of the process that spawns the jail. The jail checks `getppid()` against it (main.c:425–434). In Python, spawn from the driver itself with `env={'PATH':'/usr/bin:/bin','EPHEM_GATE_PID':str(os.getpid())}`. A shell wrapper between the driver and the jail breaks this check.
- **Run as root** (main.c:440).
- **stdin and stdout must be pipes**, and stderr must not be a socket. With `capture_output=True` and no `input=`, stdin is not a pipe, so the jail returns rc 125 with `requires piped stdin/stdout`. Always pass `input=b''` or the command bytes.
- **Rootfs path:** every component must be root-owned and not group/world-writable (`validate_root`, main.c:380). Anything under `/tmp` fails (P11). `/home/claude` (owner `claude`) also fails. Use `/opt/ephem-bench/...`.
- **Inputs live inside the rootfs** (Landlock allows reads under `/` of the bind-mounted root, and writes only to a fresh tmpfs `/tmp`). Copy the corpus to `ROOTFS/in/` and pass `/in/docNN.pdf`.
- **Dynamic worker rootfs:** `pdftotext` plus every `ldd` path, **and `/etc/ld.so.cache`**. Without the cache the loader misses the multiarch library directory and the worker exits 127. This was observed and fixed in the smoke test.
- **Limits applied inside the jail:** `RLIMIT_AS` 256 MiB, `RLIMIT_NOFILE` 32, `RLIMIT_CPU` 30 s, stderr redirected to `/dev/null`, `/proc /sys /dev` detached. The jail's own stderr carries one JSON line per run (`worker_pid`, `exit_code`, `signal`, `landlock_abi`). Record it.
- **Kernel:** `core_pattern` must not start with `|` (main.c:412), and Landlock ABI must be ≥ 3 (main.c:338).

## 4. Preflight (record each result in `preflight.json`)
- `uname -m` = x86_64 → else record `WRONG_ARCH` and run only steps 1 and 3 (P1–P5); report no latency.
- `unshare -Ur -p -f --mount-proc true` exits 0 → else record `NO_USERNS` and run the raw-exec arm and P6 only.
- `cat /proc/sys/kernel/core_pattern` first char ≠ `|` → else `sysctl -w kernel.core_pattern=core` → else record `CORE_PIPED` and skip the EPHEM arms.
- `df -h /` ≥ 15 GB free → else delete earlier `target/` dirs → else record `LOW_DISK` and skip the nsjail source build.
- Rust: `rustup toolchain install 1.99.1 --profile minimal` (repo pins it in `rust-toolchain.toml`) → else the default channel, recording the version → else record `NO_RUST`. Only `ephem-gate` needs Rust; the jail arms do not.
- `apt-get update && apt-get install -y bubblewrap poppler-utils build-essential` → else `apt-get install` without update → else record which package failed and skip its arm.
- nsjail: `apt-get install -y nsjail` → else `git clone --depth 1 https://github.com/google/nsjail && apt-get install -y autoconf bison flex libprotobuf-dev libnl-route-3-dev libtool pkg-config protobuf-compiler && make -C nsjail` → else record `NSJAIL_UNRUN`.
- gVisor (optional): `apt-get install -y runsc` from the gVisor apt repo → else the official release binary → else record `GVISOR_UNRUN`.
- Record in `env.txt`: `uname -a`, CPU model, `nproc`, `pdftotext -v`, `bwrap --version`, `nsjail --version`, `cc --version`, `rustc -V`, Landlock ABI (from the jail's JSON line).

## 5. Steps

### Setup
1. `git clone https://github.com/testofschool/ephem /root/ephem-bench/ephem && git -C /root/ephem-bench/ephem checkout 380849c` → else `git fetch --depth 50 origin` then checkout → else record `CLONE_FAIL` (EPHEM arms skip). Check P1, P2.
2. Jail: `sh packaging/build-jail.sh /root/ephem-bench/ephem/target/ephem-jail` → else the same `cc` line by hand → else record `BUILD_FAIL`. Optionally build `ephem-gate` per `docs/OPERATIONS.md` (not needed for any arm here). Record the jail binary sha256.
3. Corpus: `python3 -I gen_corpus.py /root/ephem-bench/corpus`. Check P3–P5.
4. Fixture root: `sh tests/ephem/build-rootfs.sh /opt/ephem-bench/fixture-root` (the target must not exist; `/opt/ephem-bench` must be mode 755 and root-owned). Run P9 and P11.
5. pdftotext root at `/opt/ephem-bench/pdf-root`: `usr/bin/pdftotext`, every `ldd` path (copy with `cp -L` into the same path), `etc/ld.so.cache`, `in/` holding the 50 PDFs, and `tmp/` at mode 1777. Everything else gets `chmod -R go-w`. Write `rootfs-manifest.sha256`. Every arm uses this same rootfs and the same `pdftotext` binary.

### Track A — wrap `pdftotext`: output equality and latency
Arms: (a) raw exec of the host `pdftotext`; (b) `bwrap --unshare-all --ro-bind /opt/ephem-bench/pdf-root / --tmpfs /tmp --die-with-parent /usr/bin/pdftotext /in/docNN.pdf -`; (c) `nsjail -Mo --chroot /opt/ephem-bench/pdf-root -T /tmp --quiet -- /usr/bin/pdftotext /in/docNN.pdf -` (nsjail's default new network namespace stays on; record the flags actually used); (d) EPHEM per the §3a contract, `--worker /usr/bin/pdftotext -- /in/docNN.pdf -`; (e) gVisor if installed. Record each arm's exact command line in `commands.txt`.
- Run 5 warm-up rounds, then 50 files × 20 rounds = 1,000 timed runs per arm. Run sequentially, one at a time. Wall time runs from spawn to stdout EOF plus reap (`time.perf_counter_ns` around `subprocess.run`). Report p50, p95, p99 and max using nearest-rank. Write every sample to `raw/trackA_<arm>.csv`.
- Output equality: compare per file against arm (a) (P8). An arm below 50/50 reports its mismatch list and no latency headline.
- If an arm errors, record the first error verbatim (for EPHEM, include the jail JSON line) and continue.

### Track B — cross-request residue (positive control first)
Worker: the repo fixture (`/worker` in the fixture root; it reads `DIRTY` / `CLEAN` from stdin and replies `written` / `present` / `absent`).
- Positive control: build the fixture once for the host (`cc -O2 -static tests/ephem/fixture.c -o /root/ephem-bench/fixture-host`) and run it raw with the host's shared `/tmp`. Do 100 sequential DIRTY→CLEAN pairs and count `present` (P6). Before you count, read `fixture.c` to confirm which path it marks. If the marker path is not under the shared `/tmp`, point it at a shared dir and record that change.
- Each sandboxed arm (bwrap, nsjail, EPHEM) using the fixture root: 100 sequential pairs, then 100 concurrent pairs (8 in parallel; in each pair, CLEAN runs after its DIRTY returns, and different pairs overlap). Count `present` (P7).
- Report concurrent EPHEM marker-crossing on its own line. It is the one residue case the repo has not measured (`docs/PRIOR_ART.md` P0).
- This host has 2 vCPUs (if it is the measured instance). Concurrency affects only Track B, which counts residue, not time.

### Track C — gVisor (optional)
Run Tracks A and B with `runsc` only if the preflight installed it. Otherwise list `GVISOR_UNRUN`, and no gVisor number appears anywhere.

## 6. Acceptance (done = every file exists on the executor and the report is delivered)
- `/root/ephem-bench/evidence/converter-bench-v1/` containing `preflight.json`, `env.txt`, `commands.txt`, `raw/*.csv`, `trackA.json`, `trackB.json`, `rootfs-manifest.sha256`, `MANIFEST.sha256` (corpus) and `REPORT.md`.
- Each output file's mtime is later than the run start recorded in `preflight.json`. A stale file counts as not produced.
- `REPORT.md` opens with the P1–P11 table (expected / observed / match). Then one latency table per arm (only for 50/50 arms), one residue table, and the UNRUN list with reasons.
- State the boundary differences next to the numbers: EPHEM, bwrap and nsjail share the host kernel, while gVisor uses a user-space kernel. Do not write a "fastest" or ranking sentence. The table is the claim.
- Nothing is pushed, posted or sent.

## 7. Non-goals
- No exploit code is fetched, written or run (including PHP2Shell PoCs). Inputs are only the generated benign corpus and the repo fixture.
- No change to EPHEM source on its default branch. A local build fix goes in `REPORT.md`, file by file with byte deltas.
- No outreach text.

## 8. Report format (single message at the end)
1. P1–P11 match table.
2. Track A: per-arm 50/50 status + p50/p95/p99/max.
3. Track B: positive-control count; per-arm sequential and concurrent counts.
4. UNRUN list with reasons, and every fallback that was taken.
5. Build-input changes, file by file (or "none").

## 9. Changes from v1 (audit 2026-10-27, primary sources)
- v1 named "the Linux VM on Felix's Mac Studio" as the fallback, which is ARM64 and so cannot meet x86_64. Removed.
- v1 executor folder `/home/claude/ephem-bench`: a rootfs there fails `validate_root` because the owner is not root. Rootfs moved to `/opt/ephem-bench`.
- v1 jail invocation lacked `EPHEM_GATE_PID`, the piped-stdin requirement, inputs-inside-rootfs and `/etc/ld.so.cache`. Each was measured on 2026-10-27 (rc 125 ×2, rc 127, then rc 0 with identical output) and is now §3a.
- Added P9–P11. P7 and P8 carry n=1 smoke observations, which are labelled and are not the pass condition.
