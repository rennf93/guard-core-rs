Contributing to guard-core-rs
==============================

Thanks for considering a contribution. This document describes how to propose
changes, the conventions we follow, and the checks that must pass before a
pull request can be merged.

Code of Conduct
---------------

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it. Report unacceptable behavior via
GitHub to the maintainers.

___

How to Contribute
-----------------

### Reporting Bugs

Search existing issues before filing a new one. When you file a bug report,
include:

- A clear, descriptive title
- Minimal reproduction steps (ideally a short Rust snippet or failing test)
- Observed behavior vs. expected behavior
- Logs, backtraces, and output of `rustc --version && cargo --version`
- Operating system and relevant feature flags

### Suggesting Enhancements

Enhancement proposals are tracked as GitHub issues. Include:

- A clear title
- A description of the proposed API or behavior
- Motivation — why this improves `guard-core-rs`
- Sketch of the API and a usage example
- Any reference implementations from the Python `guard-core` reference

### Pull Requests

1. Fork the repository and create a topic branch (`feature/...` or `fix/...`)
2. Make the change; keep commits focused and logically separated
3. Add or update tests — a PR that fixes a bug should include a regression test
4. Update documentation (`///` rustdoc on new public items, `docs/src/*.md` for
   user-facing behavior changes, `CHANGELOG.md` under `## Unreleased`)
5. Ensure all `make check-all` targets pass locally
6. Push the branch and open a pull request

___

Development Setup
-----------------

Requirements:

- Rust stable 1.85 or later (edition 2024)
- `cargo-llvm-cov`, `cargo-audit`, `cargo-deny`, `cargo-machete` (installed by
  `make install-dev`)
- A running Redis instance on `localhost:6379` for the integration tests that
  use real Redis; otherwise those tests short-circuit via a probe

```bash
# Clone and install dev tools
git clone https://github.com/rennf93/guard-core-rs
cd guard-core-rs
make install-dev

# Iterate
make fmt        # rustfmt
make clippy     # clippy with -D warnings
make test       # full test suite
make coverage   # llvm-cov report
```

___

Testing
-------

The test suite lives in `tests/` as integration tests, with shared mocks under
`tests/support/`. Every change that touches `src/` must keep coverage at the
current level or raise it — `cargo llvm-cov --all-features --tests` reports
line/function/region coverage.

```bash
# Run everything
make test

# Run a single test binary
cargo test --all-features --test test_models

# Run with coverage HTML report
make coverage-html
```

___

Style Guidelines
----------------

- `rustfmt` is authoritative (`rustfmt.toml` in the repo root). Run `make fmt`
  before committing
- `clippy` runs with `-D warnings` in CI — warnings block merges
- Lint suppressions via `#[allow(...)]` are forbidden. Fix the underlying
  issue. Test-only dead-code warnings are handled by touch-all helpers in
  `tests/support/` or by restructuring mocks per test
- No code comments. Names are the documentation. `///` rustdoc on `pub` items
  is required
- No `// TODO` / `// FIXME` in committed code; use GitHub issues

___

Documentation
-------------

User-facing docs live under `docs/src/*.md` and build with mdBook. API docs
are generated from `///` comments on public items and published via
`cargo doc`. When you add or change a public API, update both.

```bash
make doc         # cargo doc --all-features --no-deps --open
mdbook serve docs
```

___

Versioning
----------

This project follows [Semantic Versioning](https://semver.org/). Breaking
changes bump the major version; backward-compatible feature additions bump
minor; bug fixes bump patch.

### Release Process

1. Update the version in `Cargo.toml`
2. Update `CHANGELOG.md` — move entries from `## Unreleased` under a new
   `## vX.Y.Z (YYYY-MM-DD)` section
3. Commit and tag: `git tag vX.Y.Z && git push --tags`
4. CI publishes to crates.io from the tagged commit

___

Questions?
----------

Open an issue for discussion — prefer public threads over private messages so
everyone benefits from the answer.
