#!/usr/bin/env bash
# Local-only stock APT PDiff qualification. Prerequisites: signed B09 fixture,
# Linux apt-get + apt-helper, GnuPG, Python 3, ferrum-verifier on PATH, Rust tools.
# First generate B09 with fixture/generate.sh (unchanged). Private keys are read
# only by the generator; Ferrum receives only public keyrings and signed trees.
# Optional: FERRUM_FIXTURE_PUBLIC, FERRUM_FIXTURE_PRIVATE, CARGO_TARGET_DIR.
# The test prints observed full-vs-PDiff HTTP body bytes and checks exact final
# Packages, malformed/corrupt/missing/rotated-history fallback and recovery.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export FERRUM_FIXTURE_PUBLIC="${FERRUM_FIXTURE_PUBLIC:-$ROOT/fixture/public}"
PRIVATE="${FERRUM_FIXTURE_PRIVATE:-$ROOT/fixture/private}"
python3 fixture/pdiff.py --public "$FERRUM_FIXTURE_PUBLIC" --private "$PRIVATE"
cargo test --locked -p ferrum --features test-harness --test publication \
    pdiff:: \
    -- --ignored --nocapture --test-threads=1
