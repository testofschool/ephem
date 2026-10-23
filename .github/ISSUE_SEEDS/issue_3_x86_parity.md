# [Benchmark] x86_64 native lifecycle & seccomp parity verification

The retained Phase 3 execution evidence is Linux **aarch64**, kernel
`6.8.0-146-generic`, Rust `1.99.1`, PHP NTS embed `8.3.6` and PostgreSQL `16.15`.
**No x86_64 execution was performed.** Please contribute matched runs on
Intel/AMD server profiles, reporting architecture compatibility separately
from latency and production qualification.

The latest retained reproduction reports native lifecycle p95 **0.520076ms**
(about **0.52ms**), with all five PHP fatal-fault fixtures burned and recovered
and **zero corrupted keys committed** in the SQLite fixture. PostgreSQL and BPF
LSM were **UNRUN in that reproduction**; earlier retained PostgreSQL evidence
is separate. These are observed ARM64 results, not required outcomes for a new
host or evidence of x86_64 parity.

The latest and historical ARM64 observations are retained together:

| Measured event | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Latest native warm lifecycle, 1000 samples after 100 warmups | 0.408537 | 0.520076 | 0.590034 |
| Historical native warm lifecycle, same sample counts | 0.448963 | 0.684507 | 0.916343 |
| Historical uncontained Python/PHP baseline, 100 samples | 3.915000 | 5.130096 | 5.421015 |
| Historical complete contained PHP HTTP, 100 samples | 2.205190 | 2.739029 | 3.486328 |
| Historical signed matched PHP delta, isolated minus baseline | -1.703809 | -0.941094 | -0.652507 |

The latest complete PHP HTTP p95 is **3.316038ms** and its signed matched delta
p95 is **-0.350578ms**. The raw latest reports live under
[`reports/phase3/release-alignment-final/`](https://github.com/testofschool/ephem/tree/main/reports/phase3/release-alignment-final).
The historical **0.684507ms** native result remains published; the later
**0.520076ms** observation is a reproduction at a different time, not a
controlled improvement experiment or guaranteed speedup. Preserve both runs
and report environment differences when comparing them.

A later integrated-checkout invocation is also retained: its separate native
p95 was **1.444133ms** (native gate PASS), while the PHP signed paired-delta
p95 was **3.730803ms** (gate FAIL, full reproduction script exit 1). Functional
checks still recorded zero corrupted keys. These different tails, with the
same rebuilt binary hashes, do not establish stable 0.52ms performance. See the
[remote-sync precheck](https://github.com/testofschool/ephem/blob/main/reports/phase3/REMOTE_SYNC_PRECHECK.json)
and its raw run directory. No PHP retry was used to replace that failure.

The native lifecycle gate is p95 < 2ms. It is a separate event from complete
PHP HTTP latency. The PHP harness compares 100 randomized pairs after 20
excluded warmup pairs with order seed `20261023`, full-response EOF timing,
nearest-rank percentiles, signed per-pair differences and no outlier removal.
Its baseline forks under an uncontained Python supervisor and opens SQLite per
request, while the Rust gate keeps its parent connection. That supervisor and
connection-lifetime confound prevents interpreting the negative delta as
universal overhead or a stock PHP-FPM/Node/WSGI guarantee. Production tails
and throughput are UNMEASURED; production remains **HOLD**.

Use a dedicated Linux x86_64 VM/host with root namespace/mount privileges,
cgroup v2, pidfds, close_range and recursive mount_setattr (kernel >=5.12),
Rust/Cargo, a C compiler and PHP NTS embed development dependencies. Run the
trusted repository fixture only: its baseline is deliberately uncontained.
From the checkout at the revision being compared:

```sh
cargo build --locked --release --workspace
cargo build --locked --release -p ephem-stateful -p ephem-warm-pool
cargo test --locked --workspace
sh runtime/phase3/build-php-adapter.sh
run_dir=$(mktemp -d /tmp/ephem-x86-parity.XXXXXX)
sudo install -d -o root -g root -m 0755 "$run_dir/native-root"
sudo target/release/ephem-warm-pool --root "$run_dir/native-root" \
  --iterations 1000 --warmup 100 --lifecycle-check --require-p95-ms 2 \
  > "$run_dir/native.json"
sudo python3 tests/test_stateful_isolation.py --pairs 100 --warmup 20 \
  --require-p95 --output "$run_dir/php-paired.json"
```

Retain every output and command exit status, including failures and UNRUN.
Do not overwrite the checked-in ARM64 evidence or select only the fastest
repeat. Record the exact commit and binary/adapter hashes, CPU model/microcode,
kernel/distribution, toolchain/PHP versions, bare-metal/VM details, vCPU count,
CPU governor/affinity, memory, storage and background load. Keep source,
release feature set, protocol, fixture, sample counts and measurement events
matched between compared hosts; report unavoidable differences explicitly.

Please attach the raw native samples, paired PHP samples, receipts and server
logs. The native `--lifecycle-check` must retain its COW reset, SIGSEGV, SIGSYS,
deadline, malformed state IPC, execve/execveat, signal/fcntl denial and recovery
results. The PHP harness additionally checks staged-write rejection on five
fatal fault types and zero corrupted committed keys. Explain failures rather
than dropping them from parity evidence. Optional BPF LSM enforcement requires
its own active-kernel test; successful classic seccomp runs do not imply it.

Sources: [latest raw native samples](https://github.com/testofschool/ephem/blob/main/reports/phase3/release-alignment-final/warm-native.json),
[latest PHP paired and fault report](https://github.com/testofschool/ephem/blob/main/reports/phase3/release-alignment-final/stateful-verification.json),
[Phase 3 measurement definitions and retained failures](https://github.com/testofschool/ephem/blob/main/docs/EPHEM_PHASE3.md),
[validation verdict](https://github.com/testofschool/ephem/blob/main/reports/phase3/VALIDATION.json),
[native harness](https://github.com/testofschool/ephem/blob/main/crates/ephem-warm-pool/src/main.rs),
[paired PHP harness](https://github.com/testofschool/ephem/blob/main/tests/test_stateful_isolation.py).
