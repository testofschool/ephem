# [Architecture] Transactional gate semantics across heterogeneous backends (SQL + Redis)

Phase 3 commits each request to **one** versioned KV table, using either SQLite
or PostgreSQL. There is no MySQL or native Redis backend and no implemented
atomic commit spanning SQL and Redis. The supported worker protocol is the
bounded `ephem://state` RESP2 subset (GET, SET, SETEX, DEL, INCR, PING, QUIT),
not transparent arbitrary SQL/PDO/native Redis traffic.

Within that bounded single-backend scope, the parent stages an overlay,
validates the worker lifecycle and sealed HMAC ledger, then checks observed
versions/expiry and applies ordered mutations in one backend transaction.
SQLite uses WAL/FULL and an IMMEDIATE transaction. PostgreSQL uses SERIALIZABLE
isolation and optimistic validation in `public.ephem_kv`; versions survive
deletion to reject delete/recreate conflicts. Response release follows a known
successful commit. The worker receives an inherited state stream, no backend
credentials and no new network/exec capability.

The retained SQLite and PostgreSQL HTTP reports each show zero corrupted keys
committed for the executed fatal-fault fixtures. This is bounded test evidence,
not a guarantee about silent corruption that emits allowed commands and exits
zero. A timed-out/lost PostgreSQL COMMIT acknowledgment is **indeterminate**:
`committed_mutations=null`, HTTP 500, quarantined adapter and no automatic
retry. It must never be relabeled a known rollback. Real network lost-ACK
injection remains UNRUN.

We invite an RFC for heterogeneous SQL + Redis transactional gate semantics,
including whether two-phase commit is feasible under these constraints:

- Keep coordination and credentials entirely in the trusted parent. Workers
  retain the same bounded IPC and syscall restrictions; add no worker network,
  arbitrary query, descriptor-import or persistence capabilities.
- State exactly what each backend can durably prepare, commit and recover.
  Do not assume Redis MULTI/EXEC is a distributed prepare operation. If a
  backend cannot participate, distinguish a proposed protocol/adapter from
  an actually implemented capability and explain the atomicity limit.
- Define a durable coordinator decision, transaction/request identity,
  idempotency, participant timeouts and bounded resource consumption. Cover
  coordinator crashes, participant restarts, partitions, stalled prepared
  transactions and loss of acknowledgments at every transition.
- Specify `committed`, `burned` and `indeterminate` results, response withholding
  and reconciliation before retry. A client disconnect or elapsed deadline
  cannot retroactively undo an already durable commit.
- Provide a crash/fault matrix and an executable two-store test plan that
  detects partial visibility and retained prepared state. Include version/TTL
  conflicts, concurrent writers, recovery ownership and failed cleanup.

An outbox, saga, compensation or eventual repair proposal may be useful, but
must identify its weaker visibility/atomicity contract explicitly. An RFC
does not expand the current runtime's claim or remove production **HOLD**.

Relevant implementation:
[transaction gate and SQLite backend](https://github.com/testofschool/ephem/blob/main/crates/ephem-attestation/src/transaction_gate.rs),
[PostgreSQL backend](https://github.com/testofschool/ephem/blob/main/crates/ephem-attestation/src/postgres_backend.rs).
Authoritative repository evidence:
[Phase 3 semantics and boundaries](https://github.com/testofschool/ephem/blob/main/docs/EPHEM_PHASE3.md),
[validation verdict](https://github.com/testofschool/ephem/blob/main/reports/phase3/VALIDATION.json).
