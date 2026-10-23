# Phase 3: stateful warmed runtime

Status: implemented and Linux-tested for a bounded PHP adapter and one
transactional KV backend. Production HOLD; the complete universal contract in
the request is not established. The existing Phase 1/2 code and evidence remain
untouched. No existing service is configured or activated by these files.

## Remote-sync integration check (2026-10-23 KST)

The integrated Linux checkout preserves the public `ephem-gate` 0.2.0 source.
Workspace format, clippy with warnings denied, 21 unit tests and release builds
passed. The three rebuilt runtime binary SHA-256 hashes matched the original
validation. However, the full reproduction script **exited 1 at the PHP
paired-latency gate**; this invocation is not an end-to-end reproduction PASS.

| Remote-sync PHP result | Observation |
| --- | --- |
| Functional status | PASS |
| Initial clean requests / distinct workers | 100 / 232 |
| Corrupted committed keys | 0 in the SQLite fixture |
| Complete contained PHP HTTP p95 | 18.569558ms |
| Uncontained Python/PHP baseline p95 | 29.886462ms |
| Signed matched PHP delta p95 | **3.730803ms; FAIL against the <2.0ms gate** |
| Signed matched PHP delta maximum | 14.267238ms |
| Native stage in that script | UNRUN; the PHP gate stopped execution first |

The 21 passing unit tests comprise 16 attestation tests and five existing
gate tests; one PostgreSQL fixture remained ignored in this workspace run.
A separate native invocation then ran 1000 samples after 100 warmups:

| Separate remote-sync native event | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Warm native lifecycle | 0.610938 | 1.444133 | 2.111405 | 3.505912 |

Its lifecycle checks and native p95 <2.0ms gate passed. This separate native
result and the retained 0.520076ms result show run-to-run variability; they
do not establish a stable 0.52ms runtime or a production tail bound.

The signed delta is a percentile of matched request differences; subtracting
the route percentiles does not reproduce it. Functional success and zero
corrupted keys do not satisfy the failed performance gate. The PHP run is
retained without retry. The separately executed native check has its own
receipt and does not turn this full-script failure into a pass.

Evidence: [remote-sync precheck](../reports/phase3/REMOTE_SYNC_PRECHECK.json)
and [raw reproduction directory](../reports/phase3/remote-sync-run/).
Production remains **HOLD**. The 0.52ms release headline names the retained
release-alignment native result below, not this PHP measurement.

## Release-alignment follow-up (2026-10-23 KST)

The retained release-alignment native lifecycle **p95 is 0.520076ms (approximately 0.52ms)** on
the Linux ARM64 lab host. This follow-up reran the one-click reproduction
script for the native lifecycle and SQLite PHP paths. It preserves the
original 0.684507ms native result and all earlier raw evidence separately.
Their difference does not establish a measured performance improvement.
Production remains **HOLD**.

| Release-alignment measured event | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Warm native lifecycle, 1000 samples after 100 warmups | 0.408537 | 0.520076 | 0.590034 | 0.928572 |
| Complete contained PHP HTTP, 100 measured pairs | 2.076555 | 3.316038 | 3.658867 | 3.750616 |
| Signed matched PHP delta | -1.510438 | -0.350578 | 0.543993 | 0.601366 |

The complete PHP response measurement is a separate event from the native
lifecycle. The signed paired delta retains the differing-supervisor and DB
connection-lifetime caveats below; it does not establish universal <2ms
switching cost or stock PHP-FPM performance.

This invocation passed 18 workspace unit tests and 12 reproduction-checker
regression tests. All five SQLite PHP fatal-fault fixtures returned HTTP 500,
withheld output, committed zero corrupted keys and allowed clean recovery.
The native lifecycle checks passed. PostgreSQL live/paused-backend tests and
BPF LSM enforcement were **UNRUN in this invocation**; their original retained
results do not become new results. x86_64 remains **UNRUN**, and production
throughput and tails remain **UNMEASURED**.

Follow-up evidence: [release-alignment record](../reports/phase3/RELEASE_ALIGNMENT.json),
[native raw samples and receipts](../reports/phase3/release-alignment-final/warm-native.json),
[SQLite PHP samples and fault results](../reports/phase3/release-alignment-final/stateful-verification.json),
[PHP receipt stream](../reports/phase3/release-alignment-final/stateful-verification.receipts.jsonl),
and [recomputed comparison](../reports/phase3/release-alignment-final/comparison.txt).
The record describes the completed local preparation; publication receipts
belong to the subsequent Git release operation.

The measured workspace [Cargo.toml](../reports/phase3/measured-workspace/Cargo.toml)
and [Cargo.lock](../reports/phase3/measured-workspace/Cargo.lock) are preserved.
The published tree keeps the existing public `ephem-gate` package version
`0.2.0`; the measured lockfile recorded `0.1.0`. These lockfiles differ only in
that package-version metadata. The existing public gate source is preserved;
the recorded Phase 3 runtime measurements are tied to their retained evidence,
and any subsequent integrated-tree validation is a separate invocation.

## Verify downloaded release assets

GitHub release downloads flatten asset names. After downloading all assets
from `v0.3.0-stateful-alpha` into one empty directory, run:

```sh
sha256sum -c DOWNLOAD_SHA256SUMS.txt
mkdir payload
tar -xzf ephem-phase3-linux-arm64.tar.gz -C payload
(cd payload && sha256sum -c SHA256SUMS.txt)
```

`DOWNLOAD_SHA256SUMS.txt` covers the uploaded archive, both JSON reports and
uploaded staging checksum file by their downloaded basenames. The uploaded
`SHA256SUMS.txt` describes repository staging paths, including the release
notes; the archive's own checksum file covers its extracted original paths.
The historical `RELEASE_ALIGNMENT.json` retains its earlier local-only
publication state. Current publication is evidenced by the Git tag and release.

## Executable architecture

`ephem-stateful` first re-executes with an empty environment. Clearing environ
alone would leave old secret strings in the COW address space. On its only
thread, it loads the explicitly selected trusted PHP NTS embed adapter and
bootstrap, ignoring host php.ini and extension scan directories. Application
code has not run yet. No DB connection, sealing key, request listener, or
receipt log exists in this baseline.

`WarmPool::start` creates a privileged namespace launcher, then a namespace
PID 1 broker. PID, network, mount, IPC and UTS namespaces are established once.
A dedicated rootfs is recursively read-only, nosuid, nodev, and noexec. The
broker chroots, drops all supplementary groups and all user/group IDs to
65534, sets no-new-privileges and nondumpable state, and remains single-threaded.
Unprivileged user namespaces are unnecessary. A failure in any mandatory setup
operation aborts startup. There is no insecure fallback.

After that fork, the trusted parent opens its backend and generates its HMAC
key. Tokio admits bounded HTTP requests over a mode-0600 Unix socket. A bounded
queue feeds one blocking execution lane; the single broker handles one active
request. Multiple brokers would have to be initialized before starting threads
to create more lanes. No concurrency or throughput claim is made here.

For each request the broker forks a COW generation and transfers its pidfd,
output stream and duplex state stream through SCM_RIGHTS. The parent reads the
stable host PID before acknowledging the transfer. The broker holds the child
unreaped until that acknowledgment, avoiding pidfd fdinfo reporting a reaped
PID. All unrelated child descriptors are closed before application code runs.
Per-worker hard limits are applied, then classic seccomp with an architecture
check and default `KILL_PROCESS`. Exec, new sockets, clone/fork, ptrace,
process-memory APIs, mounts, BPF and io_uring are absent from the allowlist.
Filesystem opening is read-only. The only state capability is an already-open
Unix stream; no raw network socket or database credential is supplied.

The worker uses a loaded deployment stream adapter, `ephem://state`. Application
source uses its configured `DB_DSN` and ordinary PHP stream I/O. The adapter
translates a bounded RESP2 subset to framed IPC. It does not intercept arbitrary
MySQL, PostgreSQL, Redis, PDO, mysqli, or native extension traffic. The fixture
reads JSON `$_POST` supplied by this host adapter. It is a real warmed PHP
interpreter running actual PHP source, not PHP-FPM or a general CGI environment.
The fixture source is identical in baseline, contained, clean and fault runs;
hashes before/after and inside the rootfs are recorded. This does not prove zero
source changes for independently selected legacy applications.

Copy-on-write keeps each generation private. A child is destroyed after one
request; it is never reset and reused. `MADV_DONTNEED` is demonstrated only on
owned anonymous scratch pages in the native harness. Applying it to a live
interpreter would not rewind its object graph and is not used as a snapshot
restore mechanism. The kernel releases child COW pages when that PID exits.

## Switching cost

The fixture has zero source-line differences across the measured paths, but
installation requires a different execution host, the PHP embed/bootstrap
adapter, a supported state DSN/protocol and the fixed KV backend schema. Those
are real integration changes. A stock PDO/mysqli/Redis application cannot be
dropped into this path unchanged. Therefore universal `S_in=0` is not achieved;
only source preservation for this explicitly compatible fixture was measured.

## State and output decision

`TransactionGate` parses only GET, SET, SETEX, DEL, INCR, PING and QUIT. Values,
keys, command count, state frames, ledger, HTTP input and stdout have finite
limits. Unknown commands, malformed frames and backend read errors permanently
burn the session even if the worker ignores the returned error. A private
overlay provides read-your-writes. Versions and observed expiry are checked at
commit to reject stale snapshots, including delete/recreate conflicts.

Only the trusted parent constructs the ledger. It contains the request ID,
nonce, exact worker PID, observed values, ordered mutations and normalized
HTTP output. An HMAC-SHA256 tag binds those bytes, and memfd write/grow/shrink/
seal seals make the stored ledger immutable. No writable shared ring buffer
or sealing capability is exposed to the worker. Framed Unix IPC rather than
a memfd ring carries worker intents. Bounded serialization copies are present;
there is no zero-copy or zero-overhead assertion.

The parent drains output and state to EOF, receives the exact waitpid result
from its trusted broker, and checks the absolute deadline. A matching identity,
exit 0, no signal, complete IPC, valid sealed ledger, and unexpired decision are
required before backend commit. Response bytes stay quarantined until that
commit succeeds. Nonzero exit, SIGSEGV, seccomp SIGSYS, timeout, malformed IPC,
output bounds, client disconnect observed before decision, or verifier error
returns HTTP 500 and no committed worker mutations. A client already gone
cannot receive a 500; the burn is in its receipt.

SQLite uses WAL/FULL durability and one IMMEDIATE transaction. PostgreSQL uses
a fixed `public.ephem_kv` BYTEA schema, SERIALIZABLE isolation and optimistic
validation; the connection is opened after the warm fork. PostgreSQL DSNs are
read from a root-owned private regular file without following symlinks. The
built-in connector accepts local Unix sockets and rejects hostaddr overrides;
caller-managed TLS is available through the library API. A bounded actor owns
the PostgreSQL connection in a parent thread created after the warm fork.
Initialization waits at most 2 seconds and each adapter operation waits at most
100ms for reads and 500ms for commits at the supervisor boundary. A read timeout burns without dispatching a
commit; a commit timeout is indeterminate. A timed-out adapter is permanently
quarantined, with no automatic reconnect or retry. One stalled actor may retain
its thread/connection until the server resumes; quarantine is not cancellation. Arbitrary SQL is not forwarded, and there are no
side-effecting user queries or automatic retries.

A PostgreSQL commit acknowledgment can be lost after the server commits.
The runtime records `commit_status=indeterminate`, `committed_mutations=null`
and HTTP 500 with an unknown-outcome message. It does not claim that those
mutations were burned. Diagnostic receipt failure after a known commit also
cannot undo it: return the actual outcome and stop that executor.

## Boundaries that cannot be rounded into a pass

- A clean exit is lifecycle evidence, not a memory-integrity proof. Silent
  corruption that produces valid allowed commands and exit 0 can commit.
- Namespace and syscall policy reduce capabilities; they do not decide whether
  an allowed state mutation is malicious or unauthorized business behavior.
- General SQL can have nontransactional side effects. Writes through other
  files, mail, external services, or preopened descriptors cannot be rolled
  back by this gate; the worker is denied those capabilities in this profile.
- PostgreSQL/MySQL plus Redis do not share one atomic transaction. This runtime
  commits to one backend, and supplies no MySQL or native Redis backend.
- Disconnect before the commit decision burns. A disconnect during/after a DB
  commit cannot be atomically coordinated with the remote client; response
  loss may follow a committed request. Applications need their own request
  identity/idempotency semantics before retrying.
- A deadline can reject an expired decision; it cannot retroactively undo an
  already-linearized durable commit. Kernel/storage stalls are not a proven
  hard real-time bound. The synchronous state handler must use bounded I/O.
- Persistent storage may contain DB journal/WAL bytes even when no application
  mutation commits. “Zero bytes touched storage” is not claimed.
- The PHP adapter does not reproduce arbitrary HTTP globals, uploads, native
  DB extensions, header/status behavior, worker-start hooks or PHP-FPM behavior.
  PHP explicit `exit()` currently fails closed through the embed bailout.
- This does not patch a vulnerable interpreter or certify same-request memory
  corruption prevention. Resource ceilings can make allocations fail; vendor
  patching and application compatibility qualification remain necessary.

The optional [BPF LSM](../bpf/WARM_CONTAINMENT.md) has actual kernel programs
and a libbpf self-test. It is not loaded/enrolled by the Rust daemon. On the
current Linux VM `bpf` is absent from the active LSM list. Compilation passed;
its kernel enforcement test returns 77 / UNRUN. The real runtime tests exercise
classic seccomp and namespaces. An LSM denial cannot redirect network traffic.

## Reproduce in a dedicated Linux VM

Requirements: Linux x86_64 or aarch64, root namespace/mount permission, procfs,
pidfds, close_range, recursive mount_setattr (kernel >=5.12), Rust toolchain,
C compiler, PHP 8.3 NTS embed library and development headers. No host app or
service needs to be changed. The repository's task-local Lima helper can run
these inside the existing dedicated VM; see [LINUX_LAB.md](LINUX_LAB.md).
Do not run the uncontained baseline against untrusted applications.

```sh
cargo build --locked --release --workspace
# Match the tested deliverable feature set after workspace validation:
cargo build --locked --release -p ephem-stateful -p ephem-warm-pool
cargo test --locked --workspace
sh runtime/phase3/build-php-adapter.sh
sudo python3 tests/test_stateful_isolation.py \
  --output reports/phase3/stateful-new-run.json --require-p95
sudo install -d -o root -g root -m 0755 /tmp/ephem-native-root
sudo target/release/ephem-warm-pool --root /tmp/ephem-native-root \
  --iterations 1000 --warmup 100 --lifecycle-check --require-p95-ms 2
sh bpf/build-warm-containment.sh /tmp/ephem-warm-bpf
sudo /tmp/ephem-warm-bpf/warm-containment-test \
  /tmp/ephem-warm-bpf/warm_containment.bpf.o
```

The PHP runner refuses existing output files, uses fresh temporary rootfs/DBs,
starts only private Unix listeners, and terminates only the process groups it
created. Run it with root inside an isolated VM. Unsupported platforms return
77 / UNRUN, not PASS. `--require-p95` enforces only the reported bounded paired
comparison; read its baseline caveat before interpreting that gate.

A persistent PostgreSQL deployment must provision the fixed table/permissions
and supply a private DSN file after the baseline is created. Example local DSN:
`host=/private/postgres/socket user=ephem dbname=ephem connect_timeout=2`.
Use `ephem-stateful --help` for mutually exclusive `--database` and
`--postgres-dsn-file` backend selection. Do not put credentials in command-line
arguments, preload them into the worker, or expose the test ingress publicly.

## Original observed validation (2026-10-23 KST)

Linux aarch64, kernel 6.8.0-146-generic, Rust 1.99.1, NTS PHP embed 8.3.6,
PostgreSQL 16.15. No x86_64 execution was performed.

| Check | Observed result |
| --- | --- |
| Workspace unit tests | 18 PASS, including 16 new attestation tests |
| Real PostgreSQL adapter fixture | 1 PASS, explicitly executed separately from its default ignored status |
| New-crate format and clippy with warnings denied | PASS |
| Linux release workspace build and PHP adapter C build | PASS |
| SQLite PHP path | 100 initial clean requests; five fault types; recovery; 232 distinct reaped workers across full run; zero corrupt keys |
| PostgreSQL PHP path | 100 initial clean requests; five fault types; recovery; 113 distinct reaped workers; 212 final keys; zero corrupt keys |
| Actual paused PostgreSQL backend | Read returned HTTP500 in 106.746544ms; quarantined next request HTTP500 in 1.59785ms; explicit daemon restart recovered |
| Kernel seccomp probes | SIGSYS for Internet socket, execve/execveat, broker signal and fcntl signal routes; subsequent COW reset clean |
| Optional BPF LSM | C/object compilation PASS; kernel load/enforcement UNRUN, exit77 |
| Generic zero-switching/2ms target | UNVERIFIED; production HOLD |

| Measured event | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Warm native lifecycle, 1000 samples | 0.448963 | 0.684507 | 0.916343 |
| Uncontained Python/PHP baseline, 100 samples | 3.915000 | 5.130096 | 5.421015 |
| Complete contained PHP HTTP, 100 samples | 2.205190 | 2.739029 | 3.486328 |
| Signed matched PHP delta | -1.703809 | -0.941094 | -0.652507 |

These are the original validation measurements, retained before the
release-alignment follow-up above. The signed delta passes this comparison's numeric gate. The differing baseline
supervisor and DB connection lifetime prevent it from proving a stock
PHP-FPM/Node/WSGI overhead guarantee. The final native maximum was 1.383182ms;
earlier retained native runs had larger tails. These observations are not a
production SLA or a formal security proof.

Original validation evidence: [validation verdict](../reports/phase3/VALIDATION.json),
[PHP SQLite](../reports/phase3/stateful-isolation-final.json),
[PHP PostgreSQL](../reports/phase3/postgres-http-final.json),
[native lifecycle](../reports/phase3/warm-native-deliverable-final.json),
[actual PostgreSQL unit run](../reports/phase3/postgres-unit-final.log),
and [source/build provenance](../reports/phase3/provenance-final.json).
All normal output is withheld until commit; real lost-COMMIT-ACK network
injection remains UNRUN. The indeterminate response is unit-tested, and an
actual too-short commit-wait failure is retained as an indeterminate attempt,
without relabeling its persistent state as zero.

## Evidence and measurement definition

The raw PHP test uses 100 consecutive clean requests, then deliberate SIGSEGV,
AF_INET creation triggering SIGSYS, nonzero exit, timeout, and verifier denial
after two staged application writes. Each must return 500, preserve all prior
persistent rows, withhold its response, and allow a subsequent clean request.
The fixture also GETs its staged row before commit. An incomplete-body admission disconnect and
slow-header deadline are checked. The disconnect test cannot race a valid
request commit because the declared request body never completes. These are deterministic integration tests,
not a formal proof over all possible program executions.

The paired benchmark uses 100 randomized pairs after 20 excluded warmup pairs,
fixed order seed 20261023, one connection per request, complete-response EOF,
nearest-rank percentiles and signed per-pair differences. No outliers are
removed. Both paths use the identical PHP embed adapter, script, two-key
SQLite transaction and WAL/FULL durability. The baseline uses an uncontained
Python fork supervisor and reopens its SQLite connection after every fork;
the Rust gate keeps its parent connection. Baseline supervision and connection
policies therefore confound the isolated-cost estimate. A negative delta is
not proof of universal <2ms switching overhead. Native lifecycle and complete
PHP HTTP measurements are separate events. Final native measurements can differ
materially between runs on this VM; all retained samples stay visible and no
production tail bound is inferred from one run.

Retained intermediate evidence (before PostgreSQL/outcome-type additions):
[PHP v2](../reports/phase3/stateful-isolation-v2.json),
[raw receipts](../reports/phase3/stateful-isolation-v2.receipts.jsonl),
[earlier native run](../reports/phase3/warm-native-final.json).
The first PHP integration failure and first Rust compile failure are retained,
not overwritten with a successful verdict. The final validation/manifest files
identify the exact final sources and current observed outcomes.

Primary engineering references:
[kernel seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[PHP embed source](https://github.com/php/php-src/blob/PHP-8.3/sapi/embed/php_embed.c),
[PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html),
[PostgreSQL two-phase commit](https://www.postgresql.org/docs/current/sql-prepare-transaction.html),
and [Redis transaction limits](https://redis.io/docs/latest/develop/using-commands/transactions/).
