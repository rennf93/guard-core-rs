# Development

This chapter covers the contributor workflow for `guard-core-rs`.

## Toolchain

- Stable Rust >= 1.85 (Rust 2024 edition).
- `rustfmt` and `clippy` components.
- Optional: `cargo-audit`, `cargo-deny`, `cargo-llvm-cov`, `cargo-machete`, `cargo-nextest`.

Bootstrap with:

```bash
make install-dev
```

This runs `cargo fetch`, installs the `rustfmt` + `clippy` components, and pulls the auxiliary cargo subcommands listed above.

## Project rules

- Rust 2024 edition, MSRV 1.85.
- `#![forbid(unsafe_code)]` across the crate (enforced at the workspace level).
- `clippy::all` at warn level; zero warnings under `-D warnings`.
- No `#[allow(...)]`, no `// TODO` comments, no `panic!` in library code.
- Prefer `return Ok(Some(response))` for policy denials; reserve `Err` for unexpected failures.
- Every builder is `#[must_use]` friendly: a method returning `Self` consumes and returns the builder; do not silently drop results.

## Directory conventions

- `src/core/`, `src/detection_engine/`, `src/handlers/`, `src/decorators/`, `src/protocols/`, `src/utils.rs`, `src/models.rs`, `src/error.rs` — library surface.
- `tests/` — integration tests, one file per module/behaviour. `tests/support/` holds shared mocks.
- `benches/` — criterion benchmarks. See [Testing](./testing.md) for the current suites.
- `examples/` — runnable binaries. Each example calls only the public API.
- `docs/` — this mdBook. Build with `mdbook build docs/`.

## Common commands

| Command | Effect |
|---------|--------|
| `make fmt` | `cargo fmt --all` |
| `make fmt-check` | `cargo fmt --all -- --check` |
| `make clippy` | `cargo clippy --all-features --all-targets -- -D warnings` |
| `make lint` | fmt-check + clippy + `cargo check --all-features --all-targets` |
| `make test` | `cargo test --all-features` |
| `make nextest` | `cargo nextest run --all-features` |
| `make coverage` | `cargo llvm-cov --all-features --workspace --summary-only` |
| `make bench` | `cargo bench` |
| `make doc` | `cargo doc --all-features --no-deps --open` |
| `make audit` | `cargo audit` |
| `make deny` | `cargo deny check` |
| `make machete` | `cargo machete` (unused deps) |

`make check-all` runs lint, security, tests, and coverage in one shot. `make quality` runs lint plus machete.

## Adding a new check

1. Create `src/core/checks/implementations/<name>.rs` with a struct holding the middleware and any helpers.
2. Implement [`SecurityCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/trait.SecurityCheck.html).
3. Re-export the struct from `src/core/checks/implementations/mod.rs` and `src/core/checks/mod.rs`.
4. Add integration tests at `tests/test_check_<name>.rs` using the mock fixtures.
5. If the check introduces a new failure mode, extend [`GuardCoreError`](https://docs.rs/guard-core-rs/latest/guard_core_rs/error/enum.GuardCoreError.html).
6. Update this book where relevant.

## Adding a new handler

1. Place it under `src/handlers/<name>.rs` and re-export from `src/handlers/mod.rs`.
2. Accept `Arc<SecurityConfig>` by default; expose `initialize_redis(DynRedisHandler)` and `initialize_agent(DynAgentHandler)` when the handler has stateful side channels.
3. Never hold `tokio::sync::Mutex` across an `.await` in hot paths; prefer `parking_lot::RwLock` for sync data and `dashmap` for concurrent maps.
4. Tests: construct the handler with a `MockRedis` / `MockAgent` fixture, assert both happy and failure paths.

## Release workflow

1. Update the version in `Cargo.toml`.
2. Regenerate `Cargo.lock` with `cargo update --workspace`.
3. Run `make check-all`.
4. Rebuild rustdoc with `make doc-check` (fails on warnings).
5. Tag the release (`v<version>`), push, and let CI publish.

## Cross-references

- Rustdoc: <https://docs.rs/guard-core-rs/>
- Python counterpart: <https://github.com/rennf93/guard-core>
- Reference adapters (contributions welcome): forthcoming axum/actix/rocket shims.

Report bugs or design questions via issues on GitHub. Include a minimal reproduction and, where possible, the failing test.
