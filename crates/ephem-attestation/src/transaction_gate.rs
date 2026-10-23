//! State stays in a private overlay until a sealed ledger, matching request
//! identity, completed IPC, deadline, and clean kernel exit have been verified.
//! Accepted commands are RESP2 GET, SET, SETEX, DEL, INCR, PING, and QUIT. There
//! is deliberately no fallback forwarding path for unsupported commands.
//!
//! The SQLite adapter validates optimistic read versions and applies the whole
//! ledger in one transaction. Conflict or any backend error rolls back. Worker
//! crashes never call the backend commit function. SQLite itself may create
//! transaction/WAL metadata on a failed *backend* commit; the guarantee is zero
//! committed worker mutations, not zero physical storage writes in every fault.

use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use crate::postgres_backend::PostgresStateBackend;

const SEAL_DOMAIN: &[u8] = b"EPHEM_PHASE3_LEDGER_V1\0";
const INTERNAL_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 22\r\nConnection: close\r\n\r\nTransaction discarded\n";
const UNKNOWN_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nCommit outcome unknown\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    Failure(String),
    CommitIndeterminate(String),
}

impl GateError {
    pub fn message(&self) -> &str {
        match self {
            Self::Failure(message) | Self::CommitIndeterminate(message) => message,
        }
    }
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for GateError {}
impl From<std::io::Error> for GateError {
    fn from(value: std::io::Error) -> Self {
        Self::Failure(format!("IPC/storage error: {value}"))
    }
}
impl From<rusqlite::Error> for GateError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Failure(format!("SQLite transaction error: {value}"))
    }
}

#[derive(Debug, Clone)]
pub struct GateLimits {
    pub max_commands: usize,
    pub max_command_bytes: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_ledger_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for GateLimits {
    fn default() -> Self {
        Self {
            max_commands: 1024,
            max_command_bytes: 65_536,
            max_key_bytes: 1024,
            max_value_bytes: 32_768,
            max_ledger_bytes: 1_048_576,
            max_response_bytes: 1_048_576,
        }
    }
}

/// Evidence supplied only by the trusted supervisor after reaping the exact
/// generation. `exit_code == Some(0)` is insufficient without all other checks.
/// A clean exit cannot establish absence of undetected memory corruption.
#[derive(Debug, Clone)]
pub struct WorkerReceipt {
    pub request_id: u64,
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub containment_violation: bool,
    pub ipc_complete: bool,
}

#[derive(Debug)]
pub struct GateOutcome {
    pub http_status: u16,
    pub response: Vec<u8>,
    pub committed_mutations: Option<usize>,
    pub commit_status: CommitStatus,
    pub burned_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitStatus {
    Committed,
    Burned,
    Indeterminate,
}

impl GateOutcome {
    pub fn burned(reason: impl Into<String>) -> Self {
        Self {
            http_status: 500,
            response: INTERNAL_ERROR.to_vec(),
            committed_mutations: Some(0),
            commit_status: CommitStatus::Burned,
            burned_reason: Some(reason.into()),
        }
    }
    pub fn indeterminate(reason: impl Into<String>) -> Self {
        Self {
            http_status: 500,
            response: UNKNOWN_ERROR.to_vec(),
            committed_mutations: None,
            commit_status: CommitStatus::Indeterminate,
            burned_reason: Some(reason.into()),
        }
    }
    pub fn committed(&self) -> bool {
        self.commit_status == CommitStatus::Committed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedValue {
    pub version: u64,
    pub value: Option<Vec<u8>>,
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedValue {
    pub key: Vec<u8>,
    pub snapshot: VersionedValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub expires_at_ms: Option<u64>,
}

/// The adapter must atomically validate observations and apply every mutation,
/// or apply none. A lost COMMIT acknowledgement MUST be represented with
/// `CommitIndeterminate`, because the server may already have committed.
/// Implementations are part of the trusted computing base.
pub trait StateBackend: Send + Sync {
    fn read(&self, key: &[u8]) -> Result<VersionedValue, GateError>;
    fn commit(
        &self,
        observed: &[ObservedValue],
        mutations: &[Mutation],
    ) -> Result<usize, GateError>;
}

/// A real persistent atomic adapter. Open it AFTER creating the warm baseline
/// so neither its database descriptor nor trusted state is inherited by workers.
/// Each instance serializes its own connection; SQLite's IMMEDIATE transaction
/// also coordinates independent connections.
pub struct SqliteStateBackend {
    connection: Mutex<Connection>,
}

impl SqliteStateBackend {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GateError> {
        Self::from_connection(Connection::open(path)?)
    }
    pub fn in_memory() -> Result<Self, GateError> {
        Self::from_connection(Connection::open_in_memory()?)
    }
    fn from_connection(connection: Connection) -> Result<Self, GateError> {
        connection.busy_timeout(Duration::from_millis(100))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS ephem_kv (
                key BLOB PRIMARY KEY NOT NULL, value BLOB,
                expires_at_ms INTEGER, version INTEGER NOT NULL CHECK(version > 0)
            ) WITHOUT ROWID;",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}

fn now_ms() -> Result<u64, GateError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GateError::Failure("system clock precedes Unix epoch".into()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| GateError::Failure("timestamp overflow".into()))
}

fn read_sql(connection: &Connection, key: &[u8], now: u64) -> Result<VersionedValue, GateError> {
    let row = connection
        .query_row(
            "SELECT version, value, expires_at_ms FROM ephem_kv WHERE key=?1",
            params![key],
            |r| {
                Ok(VersionedValue {
                    version: r.get(0)?,
                    value: r.get(1)?,
                    expires_at_ms: r.get(2)?,
                })
            },
        )
        .optional()?;
    let mut value = row.unwrap_or(VersionedValue {
        version: 0,
        value: None,
        expires_at_ms: None,
    });
    if value.expires_at_ms.is_some_and(|deadline| deadline <= now) {
        value.value = None;
    }
    Ok(value)
}

impl StateBackend for SqliteStateBackend {
    fn read(&self, key: &[u8]) -> Result<VersionedValue, GateError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| GateError::Failure("backend mutex poisoned".into()))?;
        read_sql(&connection, key, now_ms()?)
    }
    fn commit(
        &self,
        observed: &[ObservedValue],
        mutations: &[Mutation],
    ) -> Result<usize, GateError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| GateError::Failure("backend mutex poisoned".into()))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_ms()?;
        for observation in observed {
            if read_sql(&transaction, &observation.key, now)? != observation.snapshot {
                return Err(GateError::Failure(
                    "optimistic transaction conflict or key expiry".into(),
                ));
            }
        }
        for mutation in mutations {
            // Versions survive deletion so concurrent delete/recreate cannot
            // produce the same observable version (the ABA problem).
            transaction.execute(
                "INSERT INTO ephem_kv (key,value,expires_at_ms,version)
                VALUES (?1,?2,?3,1) ON CONFLICT(key) DO UPDATE SET
                value=excluded.value, expires_at_ms=excluded.expires_at_ms,
                version=version+1",
                params![&mutation.key, &mutation.value, mutation.expires_at_ms],
            )?;
        }
        transaction.commit()?;
        Ok(mutations.len())
    }
}

#[derive(Serialize, Deserialize)]
struct Ledger {
    version: u32,
    request_id: u64,
    worker_pid: Option<u32>,
    nonce: [u8; 16],
    observed: Vec<ObservedValue>,
    mutations: Vec<Mutation>,
    http_status: u16,
    response: Vec<u8>,
    burn_reason: Option<String>,
}

pub struct TransactionGate {
    key: [u8; 32],
    limits: GateLimits,
}

pub struct Session {
    limits: GateLimits,
    request_id: u64,
    worker_pid: Option<u32>,
    nonce: [u8; 16],
    deadline: Instant,
    observed: BTreeMap<Vec<u8>, VersionedValue>,
    overlay: BTreeMap<Vec<u8>, Mutation>,
    mutations: Vec<Mutation>,
    response: Option<(u16, Vec<u8>)>,
    burn_reason: Option<String>,
    commands: usize,
    quit: bool,
}

/// Deliberately not Clone and with no public file/key access. The supervisor
/// consumes each ledger once; workers must never inherit this descriptor.
pub struct SealedLedger {
    file: File,
    mac: [u8; 32],
    len: usize,
    nonce: [u8; 16],
    deadline: Instant,
}

fn random<const N: usize>() -> Result<[u8; N], GateError> {
    let mut bytes = [0; N];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

impl TransactionGate {
    /// Create AFTER creating the warm baseline, otherwise fork would copy the
    /// trusted sealing secret into the untrusted process address space.
    pub fn new(limits: GateLimits) -> Result<Self, GateError> {
        if limits.max_commands == 0
            || limits.max_key_bytes == 0
            || limits.max_value_bytes == 0
            || limits.max_command_bytes < 16
            || limits.max_ledger_bytes < 512
            || limits.max_response_bytes < 128
        {
            return Err(GateError::Failure("invalid gate resource limits".into()));
        }
        Ok(Self {
            key: random()?,
            limits,
        })
    }

    pub fn begin(&self, request_id: u64, timeout: Duration) -> Result<Session, GateError> {
        if timeout.is_zero() {
            return Err(GateError::Failure(
                "request deadline must be positive".into(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| GateError::Failure("request deadline overflow".into()))?;
        Ok(Session {
            limits: self.limits.clone(),
            request_id,
            worker_pid: None,
            nonce: random()?,
            deadline,
            observed: BTreeMap::new(),
            overlay: BTreeMap::new(),
            mutations: Vec::new(),
            response: None,
            burn_reason: None,
            commands: 0,
            quit: false,
        })
    }

    pub fn seal(&self, mut session: Session) -> Result<SealedLedger, GateError> {
        if Instant::now() >= session.deadline {
            session.burn("request deadline exceeded");
        }
        let ledger = session.ledger();
        let bytes = serde_json::to_vec(&ledger)
            .map_err(|e| GateError::Failure(format!("ledger encoding: {e}")))?;
        if bytes.len() > self.limits.max_ledger_bytes {
            return Err(GateError::Failure("sealed ledger limit exceeded".into()));
        }
        let file = immutable_memfd(&bytes)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| GateError::Failure("invalid sealing key".into()))?;
        mac.update(SEAL_DOMAIN);
        mac.update(&bytes);
        Ok(SealedLedger {
            file,
            mac: mac.finalize().into_bytes().into(),
            len: bytes.len(),
            nonce: session.nonce,
            deadline: session.deadline,
        })
    }

    pub fn finish(
        &self,
        mut sealed: SealedLedger,
        receipt: WorkerReceipt,
        backend: &dyn StateBackend,
    ) -> GateOutcome {
        match self.verify_and_commit(&mut sealed, &receipt, backend) {
            Ok(outcome) => outcome,
            Err(GateError::Failure(error)) => GateOutcome::burned(error),
            Err(GateError::CommitIndeterminate(error)) => GateOutcome::indeterminate(error),
        }
    }

    fn verify_and_commit(
        &self,
        sealed: &mut SealedLedger,
        receipt: &WorkerReceipt,
        backend: &dyn StateBackend,
    ) -> Result<GateOutcome, GateError> {
        if receipt.pid == 0
            || receipt.exit_code != Some(0)
            || receipt.signal.is_some()
            || receipt.timed_out
            || receipt.containment_violation
            || !receipt.ipc_complete
        {
            return Err(GateError::Failure(
                "worker exit, containment, deadline, or IPC verification failed".into(),
            ));
        }
        if Instant::now() >= sealed.deadline {
            return Err(GateError::Failure("request deadline exceeded".into()));
        }
        verify_memfd(&sealed.file)?;
        if sealed.len > self.limits.max_ledger_bytes
            || sealed.file.metadata()?.len() != sealed.len as u64
        {
            return Err(GateError::Failure("sealed ledger length mismatch".into()));
        }
        sealed.file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; sealed.len];
        sealed.file.read_exact(&mut bytes)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| GateError::Failure("invalid sealing key".into()))?;
        mac.update(SEAL_DOMAIN);
        mac.update(&bytes);
        mac.verify_slice(&sealed.mac)
            .map_err(|_| GateError::Failure("ledger authentication failed".into()))?;
        let ledger: Ledger = serde_json::from_slice(&bytes)
            .map_err(|e| GateError::Failure(format!("ledger decoding: {e}")))?;
        if ledger.version != 1
            || ledger.request_id != receipt.request_id
            || ledger.worker_pid != Some(receipt.pid)
            || ledger.nonce != sealed.nonce
        {
            return Err(GateError::Failure(
                "ledger generation identity mismatch".into(),
            ));
        }
        if let Some(reason) = ledger.burn_reason {
            return Err(GateError::Failure(reason));
        }
        if ledger.response.len() > self.limits.max_response_bytes
            || ledger.mutations.len() > self.limits.max_commands
        {
            return Err(GateError::Failure("ledger exceeds resource bounds".into()));
        }
        // The deadline is checked before starting the bounded backend operation.
        // A completed DB COMMIT cannot safely be undone if the clock advances
        // during that operation. The adapter's commit is the linearization point.
        if Instant::now() >= sealed.deadline {
            return Err(GateError::Failure(
                "request deadline exceeded before backend commit".into(),
            ));
        }
        let count = backend.commit(&ledger.observed, &ledger.mutations)?;
        Ok(GateOutcome {
            http_status: ledger.http_status,
            response: ledger.response,
            committed_mutations: Some(count),
            commit_status: CommitStatus::Committed,
            burned_reason: None,
        })
    }
}

impl Session {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn failed(&self) -> bool {
        self.burn_reason.is_some()
    }
    /// Bind the identity returned by the trusted generation supervisor. This
    /// must never be populated from a PID claimed in worker IPC.
    pub fn bind_worker(&mut self, pid: u32) -> Result<(), GateError> {
        if pid == 0 || self.worker_pid.is_some() {
            self.burn("invalid or repeated worker identity binding");
            return Err(GateError::Failure(
                "invalid or repeated worker identity binding".into(),
            ));
        }
        self.worker_pid = Some(pid);
        Ok(())
    }
    pub fn burn(&mut self, reason: impl Into<String>) {
        if self.burn_reason.is_none() {
            self.burn_reason = Some(reason.into());
        }
        self.overlay.clear();
        self.mutations.clear();
        self.response = None;
    }

    /// Accept one complete RESP2 array. Malformed/unsupported commands latch a
    /// permanent burn even if the worker catches the error and exits with zero.
    pub fn execute_resp(
        &mut self,
        frame: &[u8],
        backend: &dyn StateBackend,
    ) -> Result<Vec<u8>, GateError> {
        let result = self.execute_inner(frame, backend);
        if let Err(error) = &result {
            self.burn(error.message().to_owned());
        }
        result
    }

    fn execute_inner(
        &mut self,
        frame: &[u8],
        backend: &dyn StateBackend,
    ) -> Result<Vec<u8>, GateError> {
        self.check_active()?;
        if self.quit {
            return Err(GateError::Failure("command after QUIT".into()));
        }
        if frame.len() > self.limits.max_command_bytes || self.commands >= self.limits.max_commands
        {
            return Err(GateError::Failure("command budget exceeded".into()));
        }
        let args = parse_resp(frame)?;
        self.commands += 1;
        let command = args[0].to_ascii_uppercase();
        let reply = match command.as_slice() {
            b"PING" if args.len() == 1 => b"+PONG\r\n".to_vec(),
            b"QUIT" if args.len() == 1 => {
                self.quit = true;
                b"+OK\r\n".to_vec()
            }
            b"GET" if args.len() == 2 => bulk(self.current(&args[1], backend)?.value.as_deref()),
            b"SET" if args.len() == 3 => {
                self.current(&args[1], backend)?;
                self.stage(args[1].clone(), Some(args[2].clone()), None)?;
                b"+OK\r\n".to_vec()
            }
            b"SETEX" if args.len() == 4 => {
                let seconds = ascii_u64(&args[2])?;
                if seconds == 0 {
                    return Err(GateError::Failure("SETEX expiry must be positive".into()));
                }
                let deadline = seconds
                    .checked_mul(1000)
                    .and_then(|s| now_ms().ok()?.checked_add(s))
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or_else(|| GateError::Failure("SETEX expiry overflow".into()))?;
                self.current(&args[1], backend)?;
                self.stage(args[1].clone(), Some(args[3].clone()), Some(deadline))?;
                b"+OK\r\n".to_vec()
            }
            b"DEL" if args.len() == 2 => {
                let existed = self.current(&args[1], backend)?.value.is_some();
                self.stage(args[1].clone(), None, None)?;
                if existed {
                    b":1\r\n".to_vec()
                } else {
                    b":0\r\n".to_vec()
                }
            }
            b"INCR" if args.len() == 2 => {
                let current = self.current(&args[1], backend)?;
                let expiry = if current.value.is_some() {
                    current.expires_at_ms
                } else {
                    None
                };
                let number = match current.value {
                    Some(bytes) => redis_integer(&bytes)?,
                    None => 0,
                }
                .checked_add(1)
                .ok_or_else(|| GateError::Failure("INCR integer overflow".into()))?;
                self.stage(
                    args[1].clone(),
                    Some(number.to_string().into_bytes()),
                    expiry,
                )?;
                format!(":{number}\r\n").into_bytes()
            }
            _ => return Err(GateError::Failure("unsupported command or arity".into())),
        };
        if serde_json::to_vec(&self.ledger())
            .map_err(|e| GateError::Failure(format!("ledger encoding: {e}")))?
            .len()
            > self.limits.max_ledger_bytes
        {
            return Err(GateError::Failure("ledger budget exceeded".into()));
        }
        Ok(reply)
    }

    fn current(
        &mut self,
        key: &[u8],
        backend: &dyn StateBackend,
    ) -> Result<VersionedValue, GateError> {
        if key.is_empty() || key.len() > self.limits.max_key_bytes {
            return Err(GateError::Failure("key limit exceeded".into()));
        }
        if let Some(mutation) = self.overlay.get(key) {
            let mut value = mutation.value.clone();
            let now = now_ms()?;
            if mutation.expires_at_ms.is_some_and(|expiry| expiry <= now) {
                value = None;
            }
            return Ok(VersionedValue {
                version: 0,
                value,
                expires_at_ms: mutation.expires_at_ms,
            });
        }
        if !self.observed.contains_key(key) {
            let snapshot = backend.read(key)?;
            if snapshot
                .value
                .as_ref()
                .is_some_and(|v| v.len() > self.limits.max_value_bytes)
            {
                return Err(GateError::Failure(
                    "backend value exceeds gate limit".into(),
                ));
            }
            self.observed.insert(key.to_vec(), snapshot);
        }
        let mut value = self
            .observed
            .get(key)
            .cloned()
            .ok_or_else(|| GateError::Failure("missing observed key".into()))?;
        let now = now_ms()?;
        if value.expires_at_ms.is_some_and(|expiry| expiry <= now) {
            value.value = None;
        }
        Ok(value)
    }

    fn stage(
        &mut self,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        expires_at_ms: Option<u64>,
    ) -> Result<(), GateError> {
        if value
            .as_ref()
            .is_some_and(|v| v.len() > self.limits.max_value_bytes)
        {
            return Err(GateError::Failure("value limit exceeded".into()));
        }
        let mutation = Mutation {
            key: key.clone(),
            value,
            expires_at_ms,
        };
        self.overlay.insert(key, mutation.clone());
        self.mutations.push(mutation);
        Ok(())
    }

    fn check_active(&self) -> Result<(), GateError> {
        if let Some(reason) = &self.burn_reason {
            return Err(GateError::Failure(format!(
                "transaction already burned: {reason}"
            )));
        }
        if Instant::now() >= self.deadline {
            return Err(GateError::Failure("request deadline exceeded".into()));
        }
        Ok(())
    }

    /// Quarantine stdout. Accept a complete HTTP/1.x response, CGI headers, or a
    /// raw body (wrapped in HTTP 200). Chunked transfer coding, duplicate length,
    /// invalid headers, and length mismatches fail closed to prevent smuggling.
    pub fn set_http_output(&mut self, output: &[u8]) -> Result<(), GateError> {
        let result = (|| {
            self.check_active()?;
            if self.response.is_some() {
                return Err(GateError::Failure(
                    "response supplied more than once".into(),
                ));
            }
            if output.len() > self.limits.max_response_bytes {
                return Err(GateError::Failure("stdout limit exceeded".into()));
            }
            let response = normalize_http(output)?;
            if response.1.len() > self.limits.max_response_bytes {
                return Err(GateError::Failure("HTTP response limit exceeded".into()));
            }
            self.response = Some(response);
            Ok(())
        })();
        if let Err(error) = &result {
            self.burn(error.message().to_owned());
        }
        result
    }

    fn ledger(&self) -> Ledger {
        let (status, response) = self.response.clone().unwrap_or((500, Vec::new()));
        Ledger {
            version: 1,
            request_id: self.request_id,
            worker_pid: self.worker_pid,
            nonce: self.nonce,
            observed: self
                .observed
                .iter()
                .map(|(key, snapshot)| ObservedValue {
                    key: key.clone(),
                    snapshot: snapshot.clone(),
                })
                .collect(),
            mutations: self.mutations.clone(),
            http_status: status,
            response,
            burn_reason: self
                .burn_reason
                .clone()
                .or_else(|| {
                    self.response
                        .is_none()
                        .then(|| "worker response missing".into())
                })
                .or_else(|| {
                    self.worker_pid
                        .is_none()
                        .then(|| "worker identity missing".into())
                }),
        }
    }
}

fn ascii_u64(bytes: &[u8]) -> Result<u64, GateError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(GateError::Failure("invalid unsigned integer".into()));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| GateError::Failure("unsigned integer overflow".into()))
}

fn redis_integer(bytes: &[u8]) -> Result<i64, GateError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GateError::Failure("INCR target is not an integer".into()))?;
    let number = text
        .parse::<i64>()
        .map_err(|_| GateError::Failure("INCR target is not an integer".into()))?;
    if number.to_string() != text {
        return Err(GateError::Failure(
            "INCR target is not a canonical integer".into(),
        ));
    }
    Ok(number)
}

fn parse_resp(frame: &[u8]) -> Result<Vec<Vec<u8>>, GateError> {
    fn line<'a>(frame: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], GateError> {
        let rest = frame
            .get(*cursor..)
            .ok_or_else(|| GateError::Failure("RESP cursor out of range".into()))?;
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| GateError::Failure("incomplete RESP line".into()))?;
        let result = &rest[..end];
        *cursor = cursor
            .checked_add(end + 2)
            .ok_or_else(|| GateError::Failure("RESP offset overflow".into()))?;
        Ok(result)
    }
    let mut cursor = 0;
    let header = line(frame, &mut cursor)?;
    if header.first() != Some(&b'*') {
        return Err(GateError::Failure("RESP2 array required".into()));
    }
    let count = ascii_u64(&header[1..])?;
    if !(1..=4).contains(&count) {
        return Err(GateError::Failure("RESP array arity limit exceeded".into()));
    }
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let header = line(frame, &mut cursor)?;
        if header.first() != Some(&b'$') {
            return Err(GateError::Failure("RESP bulk string required".into()));
        }
        let len = usize::try_from(ascii_u64(&header[1..])?)
            .map_err(|_| GateError::Failure("RESP bulk length overflow".into()))?;
        let end = cursor
            .checked_add(len)
            .ok_or_else(|| GateError::Failure("RESP bulk offset overflow".into()))?;
        let data = frame
            .get(cursor..end)
            .ok_or_else(|| GateError::Failure("incomplete RESP bulk string".into()))?;
        let suffix_end = end
            .checked_add(2)
            .ok_or_else(|| GateError::Failure("RESP suffix overflow".into()))?;
        if frame.get(end..suffix_end) != Some(b"\r\n") {
            return Err(GateError::Failure("invalid RESP bulk terminator".into()));
        }
        result.push(data.to_vec());
        cursor = suffix_end;
    }
    if cursor != frame.len() {
        return Err(GateError::Failure(
            "trailing or pipelined RESP bytes".into(),
        ));
    }
    Ok(result)
}

fn bulk(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        None => b"$-1\r\n".to_vec(),
        Some(bytes) => {
            let mut reply = format!("${}\r\n", bytes.len()).into_bytes();
            reply.extend_from_slice(bytes);
            reply.extend_from_slice(b"\r\n");
            reply
        }
    }
}

fn normalize_http(output: &[u8]) -> Result<(u16, Vec<u8>), GateError> {
    let http = output.starts_with(b"HTTP/");
    let cgi = output.starts_with(b"Status:")
        || output.starts_with(b"Content-Type:")
        || output.starts_with(b"Content-type:");
    if !http && !cgi {
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", output.len()).into_bytes();
        response.extend_from_slice(output);
        return Ok((200, response));
    }
    let end = output
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| GateError::Failure("incomplete HTTP headers".into()))?;
    if end > 16_384 {
        return Err(GateError::Failure("HTTP header limit exceeded".into()));
    }
    let headers = std::str::from_utf8(&output[..end])
        .map_err(|_| GateError::Failure("HTTP headers are not UTF-8".into()))?;
    let mut lines = headers.split("\r\n");
    let mut status = 200;
    let mut safe_headers = Vec::new();
    if http {
        let first = lines
            .next()
            .ok_or_else(|| GateError::Failure("HTTP status line missing".into()))?;
        let mut parts = first.splitn(3, ' ');
        if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
            return Err(GateError::Failure("unsupported HTTP version".into()));
        }
        status = parse_status(parts.next().unwrap_or(""))?;
    }
    let body = &output[end + 4..];
    let mut length = None;
    let mut status_seen = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| GateError::Failure("malformed HTTP header".into()))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f)
        {
            return Err(GateError::Failure("invalid HTTP header bytes".into()));
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => {
                return Err(GateError::Failure(
                    "transfer encoding is unsupported".into(),
                ))
            }
            "content-length" => {
                if length.is_some() {
                    return Err(GateError::Failure("duplicate Content-Length".into()));
                }
                length = Some(ascii_u64(value.as_bytes())?);
            }
            "connection" | "keep-alive" | "proxy-connection" | "upgrade" | "trailer" => {}
            "status" if !http => {
                if status_seen {
                    return Err(GateError::Failure("duplicate CGI status".into()));
                }
                status_seen = true;
                status = parse_status(value.split(' ').next().unwrap_or(""))?;
            }
            _ => safe_headers.push(format!("{name}: {value}\r\n")),
        }
    }
    if length.is_some_and(|n| n != body.len() as u64) {
        return Err(GateError::Failure("HTTP body length mismatch".into()));
    }
    if (status == 204 || status == 304 || status < 200) && !body.is_empty() {
        return Err(GateError::Failure("body forbidden for HTTP status".into()));
    }
    if status < 200 {
        return Err(GateError::Failure(
            "interim HTTP response is unsupported".into(),
        ));
    }
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\n",
        if status == 200 { "OK" } else { "Response" }
    )
    .into_bytes();
    for header in safe_headers {
        response.extend_from_slice(header.as_bytes());
    }
    response.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    response.extend_from_slice(body);
    Ok((status, response))
}

fn parse_status(text: &str) -> Result<u16, GateError> {
    if text.len() != 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GateError::Failure("invalid HTTP status".into()));
    }
    let status = text
        .parse::<u16>()
        .map_err(|_| GateError::Failure("invalid HTTP status".into()))?;
    if !(100..=599).contains(&status) {
        return Err(GateError::Failure("HTTP status out of range".into()));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
fn immutable_memfd(bytes: &[u8]) -> Result<File, GateError> {
    use std::os::fd::FromRawFd;
    // SAFETY: The static name is NUL-terminated and valid for the entire syscall;
    // flags request close-on-exec and explicitly permit subsequent sealing.
    let fd = unsafe {
        libc::memfd_create(
            c"ephem-ledger".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: memfd_create returned a fresh owned descriptor. File takes sole
    // ownership and closes it on every later success/error path.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    let flags = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: fd remains owned by file; F_ADD_SEALS takes integer flags and no
    // pointer argument. There are no writable mappings of this private memfd.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, flags) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn verify_memfd(file: &File) -> Result<(), GateError> {
    use std::os::fd::AsRawFd;
    // SAFETY: file owns an open descriptor; F_GET_SEALS has no pointer argument.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if flags < 0 || flags & required != required {
        return Err(GateError::Failure("ledger memfd is not immutable".into()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn immutable_memfd(_bytes: &[u8]) -> Result<File, GateError> {
    Err(GateError::Failure("sealed memfd requires Linux".into()))
}
#[cfg(not(target_os = "linux"))]
fn verify_memfd(_file: &File) -> Result<(), GateError> {
    Err(GateError::Failure("sealed memfd requires Linux".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = format!("*{}\r\n", parts.len()).into_bytes();
        for part in parts {
            bytes.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
            bytes.extend_from_slice(part);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes
    }

    fn gate() -> TransactionGate {
        TransactionGate::new(GateLimits::default()).unwrap()
    }
    fn session(gate: &TransactionGate, id: u64) -> Session {
        let mut session = gate.begin(id, Duration::from_secs(10)).unwrap();
        session.bind_worker(1234).unwrap();
        session
    }
    fn clean(id: u64) -> WorkerReceipt {
        WorkerReceipt {
            request_id: id,
            pid: 1234,
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            containment_violation: false,
            ipc_complete: true,
        }
    }

    #[test]
    fn resp_rejects_truncation_overflow_and_pipelining() {
        for bytes in [
            b"*0\r\n".as_slice(),
            b"*1\r\n$999999999999999999999999\r\n",
            b"*1\r\n$3\r\nGE",
            b"*1\r\n$3\r\nGET\r\nx",
            b"*1\r\n+GET\r\n",
        ] {
            assert!(parse_resp(bytes).is_err());
        }
        let frame = resp(&[b"SET", b"key", b"\0\xff\r\n"]);
        assert_eq!(parse_resp(&frame).unwrap()[2], b"\0\xff\r\n");
    }

    #[test]
    fn whitelist_failure_cannot_be_caught_and_ignored() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        let mut session = session(&gate, 1);
        session
            .execute_resp(&resp(&[b"SET", b"key", b"initial"]), &backend)
            .unwrap();
        assert!(session
            .execute_resp(&resp(&[b"EVAL", b"evil"]), &backend)
            .is_err());
        assert!(session.failed());
        assert!(session.mutations.is_empty());
        assert!(session
            .execute_resp(&resp(&[b"SET", b"key", b"late"]), &backend)
            .is_err());
        assert_eq!(backend.read(b"key").unwrap().value, None);
    }

    #[test]
    fn http_rejects_smuggling_and_incomplete_responses() {
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\nx",
            b"HTTP/1.1 204 No Content\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            assert!(normalize_http(bytes).is_err());
        }
        assert_eq!(
            normalize_http(b"Status: 201 Created\r\nContent-Type: text/plain\r\n\r\ncreated")
                .unwrap()
                .0,
            201
        );
        assert_eq!(normalize_http(b"raw php output").unwrap().0, 200);
    }

    #[test]
    fn expired_key_increment_drops_old_expiry() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        backend
            .commit(
                &[],
                &[Mutation {
                    key: b"counter".to_vec(),
                    value: Some(b"9".to_vec()),
                    expires_at_ms: Some(1),
                }],
            )
            .unwrap();
        let mut session = session(&gate, 2);
        assert_eq!(
            session
                .execute_resp(&resp(&[b"INCR", b"counter"]), &backend)
                .unwrap(),
            b":1\r\n"
        );
        assert_eq!(session.mutations[0].expires_at_ms, None);
    }

    #[test]
    fn backend_failure_rolls_back_prior_mutation() {
        let backend = SqliteStateBackend::in_memory().unwrap();
        let result = backend.commit(
            &[],
            &[
                Mutation {
                    key: b"first".to_vec(),
                    value: Some(b"staged".to_vec()),
                    expires_at_ms: None,
                },
                Mutation {
                    key: b"second".to_vec(),
                    value: Some(b"invalid".to_vec()),
                    expires_at_ms: Some(u64::MAX),
                },
            ],
        );
        assert!(result.is_err());
        assert_eq!(backend.read(b"first").unwrap().value, None);
        assert_eq!(backend.read(b"second").unwrap().value, None);
    }

    #[test]
    fn response_missing_and_limit_failures_latch() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        let mut session = session(&gate, 3);
        assert!(session.ledger().burn_reason.is_some());
        let oversized = vec![b'x'; GateLimits::default().max_value_bytes + 1];
        assert!(session
            .execute_resp(&resp(&[b"SET", b"key", &oversized]), &backend)
            .is_err());
        assert!(session.set_http_output(b"caught error").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clean_commit_has_read_your_writes_and_quarantined_output() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        let mut session = session(&gate, 10);
        session
            .execute_resp(&resp(&[b"SET", b"key", b"value"]), &backend)
            .unwrap();
        assert_eq!(
            session
                .execute_resp(&resp(&[b"GET", b"key"]), &backend)
                .unwrap(),
            b"$5\r\nvalue\r\n"
        );
        assert_eq!(backend.read(b"key").unwrap().value, None);
        session.set_http_output(b"private until commit").unwrap();
        let outcome = gate.finish(gate.seal(session).unwrap(), clean(10), &backend);
        assert!(outcome.committed());
        assert_eq!(outcome.committed_mutations, Some(1));
        assert_eq!(backend.read(b"key").unwrap().value.unwrap(), b"value");
        assert!(outcome.response.ends_with(b"private until commit"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_untrusted_completion_path_burns() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        for fault in 0..6 {
            let id = 20 + fault;
            let mut session = session(&gate, id);
            session
                .execute_resp(&resp(&[b"SET", b"key", b"must not persist"]), &backend)
                .unwrap();
            session.set_http_output(b"must not leak").unwrap();
            let mut receipt = clean(id);
            match fault {
                0 => receipt.signal = Some(11),
                1 => receipt.exit_code = Some(7),
                2 => receipt.exit_code = None,
                3 => receipt.timed_out = true,
                4 => receipt.containment_violation = true,
                _ => receipt.ipc_complete = false,
            }
            let outcome = gate.finish(gate.seal(session).unwrap(), receipt, &backend);
            assert_eq!(outcome.http_status, 500);
            assert!(!outcome.committed());
            assert_eq!(outcome.committed_mutations, Some(0));
            assert!(!outcome.response.windows(13).any(|w| w == b"must not leak"));
            assert_eq!(backend.read(b"key").unwrap().value, None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_snapshot_conflict_does_not_lose_increment() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        let mut first = session(&gate, 30);
        let mut second = session(&gate, 31);
        for session in [&mut first, &mut second] {
            assert_eq!(
                session
                    .execute_resp(&resp(&[b"INCR", b"counter"]), &backend)
                    .unwrap(),
                b":1\r\n"
            );
            session.set_http_output(b"ok").unwrap();
        }
        assert!(gate
            .finish(gate.seal(first).unwrap(), clean(30), &backend)
            .committed());
        assert!(!gate
            .finish(gate.seal(second).unwrap(), clean(31), &backend)
            .committed());
        assert_eq!(backend.read(b"counter").unwrap().value.unwrap(), b"1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seals_are_immutable_and_wrong_key_or_mac_burns() {
        let gate = gate();
        let other = self::gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        for fault in 0..2 {
            let mut session = session(&gate, 40 + fault);
            session.set_http_output(b"ok").unwrap();
            let mut sealed = gate.seal(session).unwrap();
            assert!(sealed.file.write_all(b"overwrite").is_err());
            assert!(sealed.file.set_len(0).is_err());
            let outcome = if fault == 0 {
                sealed.mac[0] ^= 1;
                gate.finish(sealed, clean(40), &backend)
            } else {
                other.finish(sealed, clean(41), &backend)
            };
            assert!(!outcome.committed());
            assert!(outcome.burned_reason.unwrap().contains("authentication"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wrong_generation_or_missing_binding_burns() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        for fault in 0..3 {
            let mut session = if fault == 2 {
                gate.begin(50, Duration::from_secs(10)).unwrap()
            } else {
                session(&gate, 50)
            };
            session.set_http_output(b"ok").unwrap();
            let mut receipt = clean(50);
            if fault == 0 {
                receipt.pid = 9876;
            }
            if fault == 1 {
                receipt.request_id = 51;
            }
            assert!(!gate
                .finish(gate.seal(session).unwrap(), receipt, &backend)
                .committed());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn elapsed_deadline_burns_without_timing_flakiness() {
        let gate = gate();
        let backend = SqliteStateBackend::in_memory().unwrap();
        let mut session = session(&gate, 60);
        session
            .execute_resp(&resp(&[b"SET", b"key", b"value"]), &backend)
            .unwrap();
        session.set_http_output(b"ok").unwrap();
        let mut ledger = gate.seal(session).unwrap();
        ledger.deadline = Instant::now();
        let outcome = gate.finish(ledger, clean(60), &backend);
        assert_eq!(outcome.http_status, 500);
        assert_eq!(backend.read(b"key").unwrap().value, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backend_commit_error_burns_and_replaces_stdout() {
        struct Failing;
        impl StateBackend for Failing {
            fn read(&self, _key: &[u8]) -> Result<VersionedValue, GateError> {
                Err(GateError::Failure("backend offline".into()))
            }
            fn commit(
                &self,
                _read: &[ObservedValue],
                _write: &[Mutation],
            ) -> Result<usize, GateError> {
                Err(GateError::Failure("commit unavailable".into()))
            }
        }
        let gate = gate();
        let mut session = session(&gate, 70);
        session
            .set_http_output(b"application success must be withheld")
            .unwrap();
        let result = gate.finish(gate.seal(session).unwrap(), clean(70), &Failing);
        assert_eq!(result.http_status, 500);
        assert_eq!(result.committed_mutations, Some(0));
        assert_eq!(result.response, INTERNAL_ERROR);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lost_commit_acknowledgement_is_unknown_not_false_zero() {
        struct LostAcknowledgement;
        impl StateBackend for LostAcknowledgement {
            fn read(&self, _key: &[u8]) -> Result<VersionedValue, GateError> {
                Ok(VersionedValue {
                    version: 0,
                    value: None,
                    expires_at_ms: None,
                })
            }
            fn commit(
                &self,
                _read: &[ObservedValue],
                _write: &[Mutation],
            ) -> Result<usize, GateError> {
                Err(GateError::CommitIndeterminate(
                    "commit acknowledgement lost".into(),
                ))
            }
        }
        let gate = gate();
        let mut session = session(&gate, 71);
        session
            .execute_resp(
                &resp(&[b"SET", b"key", b"possibly committed"]),
                &LostAcknowledgement,
            )
            .unwrap();
        session
            .set_http_output(b"application success must be withheld")
            .unwrap();
        let result = gate.finish(gate.seal(session).unwrap(), clean(71), &LostAcknowledgement);
        assert_eq!(result.http_status, 500);
        assert_eq!(result.commit_status, CommitStatus::Indeterminate);
        assert_eq!(result.committed_mutations, None);
        assert_eq!(result.response, UNKNOWN_ERROR);
        assert!(!result.committed());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_never_silently_uses_an_unsealed_file() {
        let gate = gate();
        let mut session = session(&gate, 80);
        session.set_http_output(b"ok").unwrap();
        assert!(gate
            .seal(session)
            .err()
            .unwrap()
            .message()
            .contains("requires Linux"));
    }
}
