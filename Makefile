.PHONY: help build release test check version version-check bump-patch bump-minor bump-major tag clean

help:
	@echo "ReadyHai - Build and Versioning Commands:"
	@echo "  make build         - Build debug binary"
	@echo "  make release       - Build release binary"
	@echo "  make test          - Run full test suite"
	@echo "  make check         - Run cargo check & verify version sync"
	@echo "  make version       - Show current version from single source of truth"
	@echo "  make version-check - Verify version consistency across all files"
	@echo "  make bump-patch    - Bump patch version (x.y.Z+1)"
	@echo "  make bump-minor    - Bump minor version (x.Y+1.0)"
	@echo "  make bump-major    - Bump major version (X+1.0.0)"
	@echo "  make tag           - Create annotated git tag for current version"
	@echo "  make clean         - Clean cargo build artifacts"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

check:
	cargo check
	@./scripts/version.sh check

version:
	@./scripts/version.sh get

version-check:
	@./scripts/version.sh check

bump-patch:
	@./scripts/version.sh bump patch

bump-minor:
	@./scripts/version.sh bump minor

bump-major:
	@./scripts/version.sh bump major

tag:
	@./scripts/version.sh tag

clean:
	cargo clean
