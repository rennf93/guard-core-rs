# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/advanced_app/Dockerfile .
#
# The example consumes the engine from the same repository, so the build
# needs the workspace manifest, the lock file, the facade + engine crates,
# and the examples directory (for the workspace members list).
FROM rust:1.95-slim-bookworm AS build

WORKDIR /build

COPY Cargo.toml Cargo.lock ./guard-core-rs/
COPY crates ./guard-core-rs/crates
COPY examples ./guard-core-rs/examples

WORKDIR /build/guard-core-rs
RUN cargo build --release -p guard-core-rs-advanced-app

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 guard

COPY --from=build /build/guard-core-rs/target/release/guard-core-rs-advanced-app /usr/local/bin/advanced-app

USER guard

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/advanced-app"]
