ARG RUST_VERSION=1.85
FROM rust:${RUST_VERSION}-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV CARGO_TERM_COLOR=always \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    RUST_BACKTRACE=1

COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src/ src/
COPY tests/ tests/
COPY benches/ benches/
COPY examples/ examples/

RUN cargo fetch --locked

FROM builder AS test
CMD ["cargo", "test", "--all-features"]

FROM builder AS release
RUN cargo build --release --all-features
