# One external workload: fit review before implementation

Status: request draft and evaluation contract only. No recipient, sample, permission to test external services, or external result has been established. Production remains HOLD.

## What to collect

The operator can answer in ordinary text; no JSON form is required.

1. One recurring task and the person who operates it. Identify their role without collecting unnecessary personal data.
2. A synthetic input and expected output, or an executable correctness checker. Explain which real constraint the example preserves. No credentials, customer documents, private data or malicious exploit payloads.
3. Language, runtime, dependencies, input/output size, CPU/memory/time limits, required subprocesses, files, network and persistent effects. Unknown is an acceptable answer and blocks claims of compatibility.
4. Their current execution method and one acceptance rule it does not meet. A preference or a hypothesis is recorded as such. If the current method meets the rule, retain that conclusion.
5. Permission for the exact local synthetic test, artifact sharing limits and a small time budget. Sharing a sample is not a purchase commitment.

## Classify before writing an adapter

| Result | Condition | Next action |
|---|---|---|
| INCOMPLETE | No input/checker, operator, requirements or test permission | Ask only for the missing field; run nothing |
| NO_FIT_CURRENT | Required Python/Node/general subprocess execution, direct network, arbitrary SQL/PDO/native Redis or unsupported effects | Record unsupported boundary and cost; no claim of drop-in support |
| BASELINE_SUFFICIENT | Existing method meets the operator's declared acceptance rule | Recommend retaining it for this task; no invented EPHEM advantage |
| CANDIDATE_FOR_LAB | Requirements fit the bounded PHP NTS/embed + state interface, finite I/O, isolated test permission and a real unmet rule | Write a specific test plan and time limit; this is not runtime or security approval |

Current verified scope: single lane, warmed PHP 8.3 NTS embed adapter, `ephem://state` GET/SET/SETEX/DEL/INCR/PING/QUIT, one SQLite **or** PostgreSQL KV table. A no-network task can still fail language, filesystem, process or adapter compatibility. Do not silently broaden syscall policy or expose host assets to make it pass.

## Reproduction has three separate stages

1. **Stored-record check:** run `python3 verify_stored_evidence.py`. This recomputes producer-recorded samples and checks pinned bytes. It executes no worker and yields no independent security finding.
2. **Trusted fixture on a fresh dedicated Linux VM:** pin commit `1320713d065f04ae701026e14edf46226e71af6d`. Follow the repository's prerequisite check and reproduction commands. Save complete commands, exit status, kernel/architecture/runtime versions, all samples, failures and UNRUN states. The repository's uncontained baseline is for its trusted fixture only. Do not insert an externally supplied untrusted workload into that baseline.
3. **Operator workload:** only after a fit review and an approved, bounded test plan. Use the same synthetic input/checker for both implementations; name the property the incumbent lacks. Record complete job latency, correctness, resource use, timeout/crash behavior and remaining effects. Any integration change creates a new tested configuration, not retrospective evidence for the released profile.

The one-click upstream script reruns SQLite PHP and native lifecycle. It does not supply new PostgreSQL, BPF LSM or x86_64 parity evidence automatically. Missing privileges/prerequisites are UNRUN; successful compilation is not enforcement.

## Preserve the transaction outcome

| Outcome | Permitted interpretation |
|---|---|
| BURNED before commit decision | Staged mutations discarded and response withheld for this observed request |
| COMMITTED with known DB acknowledgment | DB transaction committed; response loss can still occur |
| INDETERMINATE after COMMIT timeout/lost COMMIT acknowledgment | Durable outcome unknown; quarantine, reconcile, no automatic retry; never relabel as zero writes |

Clean exit and a valid HMAC ledger do not prove authorized business intent. Allowed readable secrets may leave in a valid response. DB WAL/journal bytes may persist. No test here implies host escape is universally impossible.

## Suggested one-week decision rule

This is a proposed research budget, not an outreach action or scheduled reminder.

- One initial invitation through a channel the owner already uses and is permitted to post in. No mass mentions or unsolicited bulk DMs.
- Success: one operator-authored packet containing task, synthetic input, output/checker, current method, unmet rule and bounded requirements. Stars, views and praise do not count.
- After receipt: at most two engineering hours for fit assessment before deciding whether an adapter deserves a separate budget. No promise of a benchmark in advance.
- Stop this outreach iteration after seven days without a qualified packet. Record zero responses separately from responses that do not qualify; absence of a reply does not falsify the runtime or market need.
- Stop the proposed integration if the incumbent meets the rule or the experiment needs a substantially wider trust boundary. A new requirement needs a new test contract.

After a real external run, publish a bounded result with the operator's permission, including failures. A maintainer reply is not endorsement; a community test is not a complete independent audit.
