# Direction sweep — Which external-validation direction is supported before further integration work?

Success line (minimum): Proposed research target: by 2026-10-30 receive one operator-authored synthetic task packet, including current method and unmet acceptance rule; no payment or adoption is claimed.
Swept at: 2026-10-23T01:41:23.122082+00:00

| Candidate | kind | payer | mechanism | substitute | reach | input | kill |
|---|---|---|---|---|---|---|---|
| C1 Immediate Paperless-ready optional profile proposal | proposal | ? | ✕ | △ | ✓ | ? | wounded |
| C2 Public break challenge using universal no-commit wording | proposal | ? | ✕ | ? | ? | ? | dead |
| C3 One qualified AI Tinkerers synthetic workload request | proposal | ? | ? | △ | ? | ? | wounded |
| S1 Retain the operator current method / existing sandbox | substitute | ? | ✓ | ? | ? | ? | — |
| W1 Keep HOLD and review public evidence before adopting any route | wait | ? | ✓ | ? | ? | ✓ | — |

**Verdict: NO_PROPOSAL_BEATS_BASELINE**

- survivor C3 One qualified AI Tinkerers synthetic workload request: unknown = ['payer', 'mechanism', 'reach', 'input']; test first = substitute
- baseline W1 Keep HOLD and review public evidence before adopting any route: unknown = ['payer', 'substitute', 'reach']; fails = none
- baseline S1 Retain the operator current method / existing sandbox: unknown = ['payer', 'substitute', 'reach', 'input']; fails = none
- eliminated C1 Immediate Paperless-ready optional profile proposal: premise 'mechanism' fails: Strict seccomp: no new sockets, AF_INET, execve or execveat
- eliminated C2 Public break challenge using universal no-commit wording: premise 'mechanism' fails: A PostgreSQL commit acknowledgment can be lost after the server commits. / killed: A failure can follow a durable commit; the universal announcement contradicts the state contract.

Escapes named by killers (designer-authored candidates excluded from the count):
- [converged] Collect an operator-selected synthetic task, expected result, current method and unmet rule before runtime changes. — named by C1, C3

**Pick: W1**
- Riskiest assumption: An external operator has an unmet rule worth testing; this is not yet observed.
- Cheapest test: Prepare an unsent synthetic-workload request and qualification packet; send only on a user-authorized permitted channel.
- Pass: One qualified operator packet: task, synthetic input, checker, current method, unmet rule, dependencies and bounds. This reopens C3; it does not prove production readiness. / Fail: Seven days after an actual authorized invitation, no qualified packet; classify no-send, no-reply and incomplete replies separately. / Stop: No integration work if current method meets the rule, requirements are unsupported, permission is absent, or the scoped two-hour fit budget expires.
- Registered 2026-10-23T01:41:23.122082+00:00, check by 2026-10-30T01:41:23.122082+00:00
