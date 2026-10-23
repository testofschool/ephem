//! Real PostgreSQL storage for the gate's bounded key/value state model.
//!
//! Open this adapter in the trusted parent AFTER the warm baseline forks. Only
//! fixed parameterized statements reach PostgreSQL. This is not a PostgreSQL
//! wire proxy, arbitrary SQL sandbox, or coordinator for PostgreSQL plus Redis.
//!
//! A COMMIT acknowledgement can be lost after the server durably commits. Such
//! an error is `CommitIndeterminate`: the HTTP response is 500, the mutation
//! count is unknown, and automatic retry is forbidden. A production deployment
//! needs its own durable request/idempotency reconciliation before retrying.
//!
//! One actor owns the blocking client, created after the warm baseline forks.
//! Initialization has a 2 s caller deadline and each dispatched operation a
//! 100 ms read / 500 ms commit caller deadline. A timeout permanently quarantines this adapter; a
//! blocked actor may remain until the server resumes or the daemon exits, but
//! no additional actor is spawned per request. COMMIT operation timeouts are
//! indeterminate; read timeouts cannot dispatch a COMMIT and burn known zero.

use crate::transaction_gate::{GateError, Mutation, ObservedValue, StateBackend, VersionedValue};
use postgres::{config::Host, Client, Config, GenericClient, IsolationLevel, NoTls};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_KEY: usize = 1024;
const MAX_VALUE: usize = 32_768;
const MAX_MUTATIONS: usize = 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_millis(100);
const COMMIT_OPERATION_TIMEOUT: Duration = Duration::from_millis(500);
const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(2);

enum Operation {
    Read(Vec<u8>),
    Commit(Vec<ObservedValue>, Vec<Mutation>),
}
enum Value {
    Read(VersionedValue),
    Committed(usize),
}
struct Reply {
    value: Result<Value, GateError>,
    discard: bool,
}
struct Request {
    operation: Operation,
    deadline: Instant,
    reply: mpsc::SyncSender<Reply>,
}

/// A synchronous, single-connection adapter. The mutex serializes calls within
/// this instance; SERIALIZABLE transactions also coordinate other instances.
pub struct PostgresStateBackend {
    sender: Mutex<Option<mpsc::SyncSender<Request>>>,
}

impl PostgresStateBackend {
    /// Connect using a private Unix-domain socket. TCP is rejected because this
    /// convenience constructor deliberately does not silently send credentials
    /// over an unauthenticated/unprotected transport. For remote deployments,
    /// establish a certificate-verified TLS Client and call `from_client`.
    pub fn connect(dsn: &str) -> Result<Self, GateError> {
        let mut config: Config = dsn
            .parse()
            .map_err(|_| failure("invalid PostgreSQL connection configuration"))?;
        if !config.get_hostaddrs().is_empty()
            || config.get_hosts().is_empty()
            || !config
                .get_hosts()
                .iter()
                .all(|host| matches!(host, Host::Unix(_)))
        {
            return Err(failure("PostgreSQL connect requires explicit Unix-domain socket hosts; use from_client for verified TLS"));
        }
        config.connect_timeout(Duration::from_secs(2));
        Self::start(move || {
            config
                .connect(NoTls)
                .map_err(|error| before_commit("connection failed", &error))
        })
    }

    /// The caller owns transport authentication and must supply a connection
    /// dedicated to this adapter. No connection may be inherited by workers.
    /// This initializes the fixed public.ephem_kv table if it does not exist.
    pub fn from_client(client: Client) -> Result<Self, GateError> {
        Self::start(move || Ok(client))
    }

    fn start(
        factory: impl FnOnce() -> Result<Client, GateError> + Send + 'static,
    ) -> Result<Self, GateError> {
        let (sender, receiver) = mpsc::sync_channel::<Request>(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("ephem-postgres".into())
            .spawn(move || {
                let result = factory().and_then(|mut client| {
                    initialize(&mut client)?;
                    Ok(client)
                });
                let mut client = match result {
                    Ok(client) => client,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(request) = receiver.recv() {
                    let (value, mut discard) = match request.operation {
                        Operation::Read(key) => (
                            check_deadline(request.deadline)
                                .and_then(|()| read_pg(&mut client, &key, now_ms()?, false))
                                .map(Value::Read),
                            false,
                        ),
                        Operation::Commit(observed, mutations) => {
                            let (result, discard) =
                                commit_client(&mut client, &observed, &mutations, request.deadline);
                            (result.map(Value::Committed), discard)
                        }
                    };
                    discard |= client.is_closed();
                    let _ = request.reply.send(Reply { value, discard });
                    if discard {
                        break;
                    }
                }
            })
            .map_err(|error| failure(format!("PostgreSQL actor creation failed: {error}")))?;
        ready_rx
            .recv_timeout(INITIALIZATION_TIMEOUT)
            .map_err(|_| {
                failure("PostgreSQL initialization deadline exceeded; actor quarantined")
            })??;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
        })
    }

    fn request(&self, operation: Operation) -> Result<Value, GateError> {
        let commit = matches!(operation, Operation::Commit(..));
        let operation_timeout = if commit {
            COMMIT_OPERATION_TIMEOUT
        } else {
            OPERATION_TIMEOUT
        };
        let mut slot = self
            .sender
            .try_lock()
            .map_err(|_| failure("PostgreSQL actor busy or poisoned; operation not dispatched"))?;
        let sender = slot.as_ref().ok_or_else(|| {
            failure("PostgreSQL actor quarantined; explicit reinitialization required")
        })?;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let deadline = Instant::now()
            .checked_add(operation_timeout)
            .ok_or_else(|| failure("PostgreSQL operation deadline overflow"))?;
        if sender
            .try_send(Request {
                operation,
                deadline,
                reply: reply_tx,
            })
            .is_err()
        {
            *slot = None;
            return Err(failure(
                "PostgreSQL actor unavailable before dispatch; no COMMIT sent",
            ));
        }
        match reply_rx.recv_timeout(operation_timeout) {
            Ok(reply) => {
                if reply.discard {
                    *slot = None;
                }
                reply.value
            }
            Err(_) => {
                // Permanently drop the only sender. At most one stuck actor
                // exists per adapter; no per-request threads/retries are made.
                *slot = None;
                if commit {
                    Err(GateError::CommitIndeterminate("PostgreSQL commit operation deadline/actor failure; reconcile before retry".into()))
                } else {
                    Err(failure("PostgreSQL read operation deadline/actor failure; no COMMIT dispatched, adapter quarantined"))
                }
            }
        }
    }
}

fn failure(message: impl Into<String>) -> GateError {
    GateError::Failure(message.into())
}

fn before_commit(stage: &str, error: &postgres::Error) -> GateError {
    // SQLSTATE is useful for diagnosis while omitting DSN credentials, query
    // values, and server error details that could contain application data.
    let code = error
        .as_db_error()
        .map(|db| db.code().code())
        .unwrap_or("transport");
    failure(format!(
        "PostgreSQL {stage} ({code}); no COMMIT issued by this operation"
    ))
}

fn now_ms() -> Result<u64, GateError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure("system clock precedes Unix epoch"))?
            .as_millis(),
    )
    .map_err(|_| failure("timestamp overflow"))
}

fn bounded_key(key: &[u8]) -> Result<(), GateError> {
    if key.is_empty() || key.len() > MAX_KEY {
        return Err(failure("PostgreSQL key bound exceeded"));
    }
    Ok(())
}

fn read_pg(
    client: &mut impl GenericClient,
    key: &[u8],
    now: u64,
    lock: bool,
) -> Result<VersionedValue, GateError> {
    bounded_key(key)?;
    let query = if lock {
        "SELECT version, value, expires_at_ms FROM public.ephem_kv WHERE key=$1 FOR UPDATE"
    } else {
        "SELECT version, value, expires_at_ms FROM public.ephem_kv WHERE key=$1"
    };
    let row = client
        .query_opt(query, &[&key])
        .map_err(|error| before_commit("read failed", &error))?;
    let Some(row) = row else {
        return Ok(VersionedValue {
            version: 0,
            value: None,
            expires_at_ms: None,
        });
    };
    let signed_version: i64 = row
        .try_get(0)
        .map_err(|error| before_commit("version decoding failed", &error))?;
    let mut value: Option<Vec<u8>> = row
        .try_get(1)
        .map_err(|error| before_commit("value decoding failed", &error))?;
    let signed_expiry: Option<i64> = row
        .try_get(2)
        .map_err(|error| before_commit("expiry decoding failed", &error))?;
    if signed_version <= 0 || signed_expiry.is_some_and(|value| value < 0) {
        return Err(failure("PostgreSQL stored metadata is out of range"));
    }
    if value.as_ref().is_some_and(|bytes| bytes.len() > MAX_VALUE) {
        return Err(failure("PostgreSQL stored value bound exceeded"));
    }
    let expires_at_ms = signed_expiry.map(|value| value as u64);
    if expires_at_ms.is_some_and(|expiry| expiry <= now) {
        value = None;
    }
    Ok(VersionedValue {
        version: signed_version as u64,
        value,
        expires_at_ms,
    })
}

impl StateBackend for PostgresStateBackend {
    fn read(&self, key: &[u8]) -> Result<VersionedValue, GateError> {
        bounded_key(key)?;
        match self.request(Operation::Read(key.to_vec()))? {
            Value::Read(value) => Ok(value),
            Value::Committed(_) => Err(failure("PostgreSQL actor reply type mismatch")),
        }
    }
    fn commit(
        &self,
        observed: &[ObservedValue],
        mutations: &[Mutation],
    ) -> Result<usize, GateError> {
        if observed.len() > MAX_MUTATIONS || mutations.len() > MAX_MUTATIONS {
            return Err(failure("PostgreSQL transaction budget exceeded"));
        }
        // Validate unsigned-to-BIGINT bounds before sending any mutation.
        for observation in observed {
            bounded_key(&observation.key)?;
            if observation.snapshot.version > i64::MAX as u64
                || observation
                    .snapshot
                    .expires_at_ms
                    .is_some_and(|expiry| expiry > i64::MAX as u64)
            {
                return Err(failure("PostgreSQL observed metadata exceeds BIGINT range"));
            }
        }
        for mutation in mutations {
            bounded_key(&mutation.key)?;
            if mutation
                .value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_VALUE)
                || mutation
                    .expires_at_ms
                    .is_some_and(|expiry| expiry > i64::MAX as u64)
            {
                return Err(failure("PostgreSQL mutation bounds exceeded"));
            }
        }

        match self.request(Operation::Commit(observed.to_vec(), mutations.to_vec()))? {
            Value::Committed(count) => Ok(count),
            Value::Read(_) => Err(GateError::CommitIndeterminate(
                "PostgreSQL actor commit reply type mismatch".into(),
            )),
        }
    }
}

fn commit_client(
    client: &mut Client,
    observed: &[ObservedValue],
    mutations: &[Mutation],
    deadline: Instant,
) -> (Result<usize, GateError>, bool) {
    if let Err(error) = check_deadline(deadline) {
        return (Err(error), false);
    }
    let mut transaction = match client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
    {
        Ok(transaction) => transaction,
        Err(error) => return (Err(before_commit("BEGIN failed", &error)), false),
    };
    let apply = (|| {
        check_deadline(deadline)?;
        let now = now_ms()?;
        for observation in observed {
            check_deadline(deadline)?;
            if read_pg(&mut transaction, &observation.key, now, true)? != observation.snapshot {
                return Err(failure("PostgreSQL optimistic conflict or key expiry"));
            }
        }
        for mutation in mutations {
            check_deadline(deadline)?;
            let expiry = mutation.expires_at_ms.map(|value| value as i64);
            transaction
                .execute(
                    "INSERT INTO public.ephem_kv (key,value,expires_at_ms,version)
                    VALUES ($1,$2,$3,1) ON CONFLICT(key) DO UPDATE SET
                    value=EXCLUDED.value, expires_at_ms=EXCLUDED.expires_at_ms,
                    version=public.ephem_kv.version+1",
                    &[&mutation.key, &mutation.value, &expiry],
                )
                .map_err(|error| before_commit("mutation failed", &error))?;
        }
        check_deadline(deadline)?;
        Ok::<(), GateError>(())
    })();
    if let Err(error) = apply {
        // No COMMIT has been sent. Even if the rollback acknowledgement is
        // lost, this transaction has no path to an automatic later COMMIT.
        let discard = transaction.rollback().is_err();
        return (Err(error), discard);
    }
    match transaction.commit() {
        Ok(()) => (Ok(mutations.len()), false),
        Err(error) => {
            let code = error.as_db_error().map(|db| db.code().code());
            // These server responses explicitly reject the transaction.
            // Transport loss and all other responses remain conservative
            // UNKNOWN; neither blind retry nor a false zero is permitted.
            if code.is_some_and(known_commit_abort) {
                (
                    Err(failure(format!(
                        "PostgreSQL COMMIT rejected ({})",
                        code.unwrap_or("unknown")
                    ))),
                    false,
                )
            } else {
                (
                    Err(GateError::CommitIndeterminate(format!(
                        "PostgreSQL COMMIT outcome indeterminate ({}); reconcile before retry",
                        code.unwrap_or("transport acknowledgement lost")
                    ))),
                    true,
                )
            }
        }
    }
}

fn known_commit_abort(code: &str) -> bool {
    code.starts_with("23")
        || code.starts_with("25")
        || matches!(code, "40000" | "40001" | "40002" | "40P01")
}

fn initialize(client: &mut Client) -> Result<(), GateError> {
    client.batch_execute("SET statement_timeout = '200ms';
            SET lock_timeout = '200ms';
            SET idle_in_transaction_session_timeout = '2s';
            SET synchronous_commit = on;
            SET application_name = 'ephem-attestation';
            SET search_path = pg_catalog;
            CREATE TABLE IF NOT EXISTS public.ephem_kv (
                key BYTEA PRIMARY KEY NOT NULL CHECK (pg_catalog.octet_length(key) BETWEEN 1 AND 1024),
                value BYTEA CHECK (value IS NULL OR pg_catalog.octet_length(value) <= 32768),
                expires_at_ms BIGINT CHECK (expires_at_ms IS NULL OR expires_at_ms >= 0),
                version BIGINT NOT NULL CHECK (version > 0)
            );").map_err(|error| before_commit("initialization failed", &error))?;
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<(), GateError> {
    if Instant::now() >= deadline {
        return Err(failure(
            "PostgreSQL operation deadline exceeded before COMMIT",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostaddr_cannot_override_unix_socket_guard() {
        let result =
            PostgresStateBackend::connect("host=/tmp hostaddr=127.0.0.1 user=ephem dbname=ephem");
        assert!(matches!(result, Err(GateError::Failure(ref message))
            if message.contains("requires explicit Unix-domain socket hosts")));
    }

    #[test]
    fn statement_completion_unknown_is_never_classified_as_burned() {
        assert!(!known_commit_abort("40003"));
        assert!(known_commit_abort("40001"));
        assert!(known_commit_abort("40P01"));
        assert!(!known_commit_abort("08006"));
    }
}
