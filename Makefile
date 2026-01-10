.PHONY: build
build: ## Run project locally
	cargo build

.PHONY: lint
lint: ## Run linter
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

.PHONY: test
test: ## Run tests
	cargo test --all-targets --all-features
	cargo test --doc
