# Phase 3 Linux arm64 binaries

These are the tested Linux aarch64 release binaries, not macOS executables.
The PHP adapter dynamically requires the Ubuntu PHP 8.3 NTS embed library and
its system dependencies. It is not a self-contained runtime distribution.

Build command: `cargo build --locked --release -p ephem-stateful -p ephem-warm-pool`.
Build the adapter with `sh runtime/phase3/build-php-adapter.sh`.
The workspace-wide build also passes; Cargo feature unification can produce a
different binary hash when the legacy gate is built in the same command.

Source/run instructions: `docs/EPHEM_PHASE3.md`.
Exact hashes: `reports/phase3/provenance-final.json`.
Production status HOLD; no universal zero-switching or memory-integrity claim.
