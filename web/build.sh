#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$ROOT"
if ! command -v wasm-pack >/dev/null 2>&1; then
  cargo install wasm-pack --locked
fi
wasm-pack build crates/sealim-wasm --target web --out-dir "$ROOT/web/pkg"