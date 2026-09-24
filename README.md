# guard-core-rs

Rust port of the [guard-core](https://github.com/rennf93/guard-core) detection engine. The workspace ships two published crates:

- `guard-core-engine` (4.0.4 on crates.io): the detection engine entry point used by the framework adapters.
- `guard-core-rs` (4.0.4 on crates.io): the facade crate re-exporting `compiler`, `preprocessor`, and `semantic`.

## Status

Production port of the Python engine, tracked against guard-core 4.0.x with a conformance corpus. Used by the Rust adapters: [tower-guard-rs](https://github.com/rennf93/tower-guard-rs), [axum-guard-rs](https://github.com/rennf93/axum-guard-rs), [actix-guard-rs](https://github.com/rennf93/actix-guard-rs), and [rocket-guard-rs](https://github.com/rennf93/rocket-guard-rs).

Docs: https://rennf93.github.io/guard-core-rs/

## Install

```sh
cargo add guard-core-engine@4.0.4
```

## Links

- Python reference: https://github.com/rennf93/guard-core
- TypeScript port: https://github.com/rennf93/guard-core-ts
- Adapters: [tower](https://github.com/rennf93/tower-guard-rs), [axum](https://github.com/rennf93/axum-guard-rs), [actix-web](https://github.com/rennf93/actix-guard-rs), [rocket](https://github.com/rennf93/rocket-guard-rs)
- Telemetry: [guard-agent-rs](https://github.com/rennf93/guard-agent-rs)
- Cloud platform: https://app.guard-core.com

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
