#![cfg(target_os = "linux")]
//! Explicitly opted-in real PostgreSQL test. Ordinary `cargo test` reports this
//! as IGNORED, never as an executed PASS without a database.
//!
//! EPHEM_TEST_POSTGRES_DSN='host=/private/socket port=55439 user=ephem dbname=ephem' \
//! cargo test -p ephem-attestation --test postgres -- --ignored --nocapture
//!
//! Use a dedicated test database: this fixture creates public.ephem_kv and
//! removes only keys in its unique test namespace at successful completion.

use ephem_attestation::{
    CommitStatus, GateError, GateLimits, Mutation, PostgresStateBackend, StateBackend,
    TransactionGate, WorkerReceipt,
};
use postgres::{Client, NoTls};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn resp(parts: &[&[u8]]) -> Vec<u8> {
    let mut frame = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        frame.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        frame.extend_from_slice(part);
        frame.extend_from_slice(b"\r\n");
    }
    frame
}

fn receipt(id: u64) -> WorkerReceipt {
    WorkerReceipt {
        request_id: id,
        pid: std::process::id(),
        exit_code: Some(0),
        signal: None,
        timed_out: false,
        containment_violation: false,
        ipc_complete: true,
    }
}

#[test]
#[ignore = "real PostgreSQL UNRUN by default; set EPHEM_TEST_POSTGRES_DSN and run --ignored"]
fn actual_postgres_commit_crash_burn_conflict_and_partial_failure_rollback() {
    let dsn = std::env::var("EPHEM_TEST_POSTGRES_DSN")
        .expect("explicit real PostgreSQL test requires EPHEM_TEST_POSTGRES_DSN; no database substitute is used");
    let backend = PostgresStateBackend::connect(&dsn).expect("private test PostgreSQL connection");
    let observer =
        PostgresStateBackend::connect(&dsn).expect("independent PostgreSQL observer connection");
    let gate = TransactionGate::new(GateLimits::default()).unwrap();
    let namespace = format!(
        "ephem-real-pg-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let committed = format!("{namespace}:committed").into_bytes();
    let crashed = format!("{namespace}:crashed").into_bytes();
    let counter = format!("{namespace}:counter").into_bytes();
    let rolled_back = format!("{namespace}:rolled-back").into_bytes();
    let overflow = format!("{namespace}:overflow").into_bytes();

    let mut session = gate.begin(1, Duration::from_secs(10)).unwrap();
    session.bind_worker(std::process::id()).unwrap();
    session
        .execute_resp(&resp(&[b"SET", &committed, b"real server value"]), &backend)
        .unwrap();
    assert_eq!(
        session
            .execute_resp(&resp(&[b"GET", &committed]), &backend)
            .unwrap(),
        b"$17\r\nreal server value\r\n"
    );
    assert_eq!(observer.read(&committed).unwrap().value, None);
    session.set_http_output(b"ok").unwrap();
    let outcome = gate.finish(gate.seal(session).unwrap(), receipt(1), &backend);
    assert_eq!(outcome.commit_status, CommitStatus::Committed);
    assert_eq!(outcome.committed_mutations, Some(1));
    assert_eq!(
        observer.read(&committed).unwrap().value.unwrap(),
        b"real server value"
    );

    let mut session = gate.begin(2, Duration::from_secs(10)).unwrap();
    session.bind_worker(std::process::id()).unwrap();
    session
        .execute_resp(&resp(&[b"SET", &crashed, b"never committed"]), &backend)
        .unwrap();
    session.set_http_output(b"must remain quarantined").unwrap();
    let mut crashed_receipt = receipt(2);
    crashed_receipt.exit_code = None;
    crashed_receipt.signal = Some(11);
    let outcome = gate.finish(gate.seal(session).unwrap(), crashed_receipt, &backend);
    assert_eq!(outcome.commit_status, CommitStatus::Burned);
    assert_eq!(outcome.committed_mutations, Some(0));
    assert_eq!(observer.read(&crashed).unwrap().value, None);

    let mut first = gate.begin(3, Duration::from_secs(10)).unwrap();
    let mut second = gate.begin(4, Duration::from_secs(10)).unwrap();
    for session in [&mut first, &mut second] {
        session.bind_worker(std::process::id()).unwrap();
        assert_eq!(
            session
                .execute_resp(&resp(&[b"INCR", &counter]), &backend)
                .unwrap(),
            b":1\r\n"
        );
        session.set_http_output(b"ok").unwrap();
    }
    assert!(gate
        .finish(gate.seal(first).unwrap(), receipt(3), &backend)
        .committed());
    let outcome = gate.finish(gate.seal(second).unwrap(), receipt(4), &backend);
    assert_eq!(outcome.commit_status, CommitStatus::Burned);
    assert_eq!(observer.read(&counter).unwrap().value.unwrap(), b"1");

    // Force a real server-side BIGINT overflow on the second mutation, after
    // the first mutation has executed in the transaction. The first must roll
    // back, not remain as a partially committed row.
    let mut control = Client::connect(&dsn, NoTls).unwrap();
    let version = i64::MAX;
    let value = b"maximum version".to_vec();
    control
        .execute(
            "INSERT INTO public.ephem_kv(key,value,version) VALUES($1,$2,$3)",
            &[&overflow, &value, &version],
        )
        .unwrap();
    let failure = backend
        .commit(
            &[],
            &[
                Mutation {
                    key: rolled_back.clone(),
                    value: Some(b"transient".to_vec()),
                    expires_at_ms: None,
                },
                Mutation {
                    key: overflow.clone(),
                    value: Some(b"invalid next version".to_vec()),
                    expires_at_ms: None,
                },
            ],
        )
        .unwrap_err();
    assert!(matches!(failure, GateError::Failure(_)));
    assert_eq!(observer.read(&rolled_back).unwrap().value, None);
    assert_eq!(observer.read(&overflow).unwrap().version, i64::MAX as u64);

    assert!(matches!(
        backend.commit(
            &[],
            &[Mutation {
                key: rolled_back.clone(),
                value: Some(b"unsigned overflow".to_vec()),
                expires_at_ms: Some(u64::MAX)
            },]
        ),
        Err(GateError::Failure(_))
    ));
    assert_eq!(observer.read(&rolled_back).unwrap().value, None);

    for key in [&committed, &crashed, &counter, &rolled_back, &overflow] {
        control
            .execute("DELETE FROM public.ephem_kv WHERE key=$1", &[key])
            .unwrap();
    }
    println!("REAL_POSTGRES_PASS: commit visibility, staged read-your-writes, crash receipt burn, stale conflict, server-side partial failure rollback, u64 bounds");
}
