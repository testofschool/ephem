# Contributing

Start with a reproducible boundary or compatibility failure using synthetic data.
Small changes with explicit before/after behavior are easier to review. Security
issues follow [SECURITY.md](SECURITY.md).

Build on Linux with Rust and a C compiler:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release
sh packaging/build-jail.sh
```

Run the dedicated-VM integration instructions in [the runbook](docs/OPERATIONS.md).
Do not run privileged tests on a production host. A skip or missing prerequisite
is UNRUN, never PASS. Preserve failed evidence when changing a security boundary.
For a new capability, add both a denied case and a positive control showing the
limits of the claim. Do not relax the syscall policy just to make a test green.

Use respectful, specific technical discussion. Contributions are licensed under
Apache-2.0, matching the project. Do not submit code you cannot license.
