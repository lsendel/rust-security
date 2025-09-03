#!/bin/bash
# Fully quiet Clippy run - completely silent on success
cargo clippy --workspace --all-features -- -A clippy::cargo >/dev/null 2>&1
