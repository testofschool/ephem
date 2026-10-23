#![deny(unsafe_op_in_unsafe_fn)]
//! A trusted, fail-closed transaction coordinator for a bounded Redis-compatible
//! key/value protocol and one SQLite or PostgreSQL database. This is not a general SQL proxy,
//! Redis replacement, distributed transaction coordinator, or memory-corruption
//! detector. The supervising parent must create the gate after forking its warm
//! baseline and supply exit evidence obtained from the kernel, not the worker.

pub mod postgres_backend;
pub mod transaction_gate;

pub use postgres_backend::PostgresStateBackend;

pub use transaction_gate::{
    CommitStatus, GateError, GateLimits, GateOutcome, Mutation, ObservedValue, SealedLedger,
    Session, SqliteStateBackend, StateBackend, TransactionGate, VersionedValue, WorkerReceipt,
};
