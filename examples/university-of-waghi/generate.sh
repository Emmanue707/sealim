#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$DIR"
cargo run --quiet --manifest-path "$DIR/Cargo.toml"
echo "Wrote transcript.txt, trust.json, qr.txt, and qr.png"