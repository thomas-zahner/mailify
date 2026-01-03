.PHONY: build
build: ## Run project locally
	cargo build

.PHONY: lint
lint: ## Run linter
	cargo fmt --all -- --check
	cargo clippy -- -D warnings

.PHONY: test
test: ## Run tests
	cargo test
	cargo test --doc
