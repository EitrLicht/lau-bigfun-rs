#!/usr/bin/env bash
# Checks the dependencies in Cargo.lock against the RustSec advisory database, failing on any
# crate with a known vulnerability, or one that is unmaintained or yanked. Every workflow that
# checks advisories calls it, so the cargo-deny version is pinned in one place. cargo-deny only warns
# about a yanked crate by default, so it is denied here.
set -euo pipefail

CARGO_DENY_VERSION="0.20.2"

cargo install --locked cargo-deny --version "$CARGO_DENY_VERSION"
cargo deny --locked check --deny yanked advisories
