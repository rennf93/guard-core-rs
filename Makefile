RUST_CHANNEL ?= stable
CARGO ?= cargo
MSRV := 1.85


.PHONY: install
install:
	@$(CARGO) fetch


.PHONY: install-dev
install-dev:
	@$(CARGO) fetch
	@rustup component add rustfmt clippy --toolchain $(RUST_CHANNEL)
	@$(CARGO) install --locked cargo-audit cargo-deny cargo-llvm-cov cargo-machete cargo-outdated cargo-nextest || true


.PHONY: build
build:
	@$(CARGO) build --all-features


.PHONY: release
release:
	@$(CARGO) build --release --all-features


.PHONY: lock
lock:
	@$(CARGO) update --workspace


.PHONY: upgrade
upgrade:
	@$(CARGO) update
	@$(CARGO) build --all-features


.PHONY: fmt
fmt:
	@$(CARGO) fmt --all


.PHONY: fmt-check
fmt-check:
	@$(CARGO) fmt --all -- --check


.PHONY: clippy
clippy:
	@$(CARGO) clippy --all-features --all-targets -- -D warnings


.PHONY: check
check:
	@$(CARGO) check --all-features --all-targets


.PHONY: lint
lint: fmt-check clippy check
	@echo "All lint checks passed."


.PHONY: fix
fix:
	@$(CARGO) fmt --all
	@$(CARGO) clippy --all-features --all-targets --fix --allow-dirty --allow-staged


.PHONY: test
test:
	@$(CARGO) test --all-features


.PHONY: nextest
nextest:
	@$(CARGO) nextest run --all-features


.PHONY: test-msrv
test-msrv:
	@rustup toolchain install $(MSRV) --profile minimal || true
	@$(CARGO) +$(MSRV) build --all-features
	@$(CARGO) +$(MSRV) test --all-features


.PHONY: coverage
coverage:
	@$(CARGO) llvm-cov --all-features --workspace --summary-only


.PHONY: coverage-html
coverage-html:
	@$(CARGO) llvm-cov --all-features --workspace --html


.PHONY: audit
audit:
	@$(CARGO) audit


.PHONY: deny
deny:
	@$(CARGO) deny check


.PHONY: machete
machete:
	@$(CARGO) machete


.PHONY: outdated
outdated:
	@$(CARGO) outdated --exit-code 1 || true


.PHONY: security
security: audit deny
	@echo "Security checks complete."


.PHONY: quality
quality: lint machete
	@echo "Quality checks complete."


.PHONY: analysis
analysis: machete outdated
	@echo "Analysis complete."


.PHONY: check-all
check-all: lint security test coverage
	@echo "All checks complete."


.PHONY: doc
doc:
	@$(CARGO) doc --all-features --no-deps --open


.PHONY: doc-check
doc-check:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --all-features --no-deps


.PHONY: bench
bench:
	@$(CARGO) bench


.PHONY: clean
clean:
	@$(CARGO) clean


.PHONY: bump-version
bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	@sed -i.bak 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml && rm Cargo.toml.bak


.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' || cat $(MAKEFILE_LIST)


.DEFAULT_GOAL := help


.PHONY: show-versions
show-versions:
	@echo "Rust channel: $(RUST_CHANNEL)"
	@echo "MSRV: $(MSRV)"
	@rustc --version
	@$(CARGO) --version
