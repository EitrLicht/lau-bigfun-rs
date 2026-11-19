#!/usr/bin/env bash
# Checks the dependencies in Cargo.lock against the RustSec advisory database, failing on any
# crate with a known vulnerability, or one that is unmaintained or yanked. Both ci.yml and
# release.yml call it, so the cargo-deny version is pinned in one place.
set -euo pipefail

CARGO_DENY_VERSION="0.20.2"

cargo install --locked cargo-deny --version "$CARGO_DENY_VERSION"
cargo deny --locked check advisories
