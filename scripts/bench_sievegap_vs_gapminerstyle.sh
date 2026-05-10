#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ITERS="${1:-200}"
WINDOW_SIZE="${2:-8388608}"
SIEVE_LIMIT="${3:-500000}"

echo "[bench] building bench_sievegap"
make tests/bench_sievegap >/dev/null

echo "[bench] running bench_sievegap iters=${ITERS} window_size=${WINDOW_SIZE} sieve_limit=${SIEVE_LIMIT}"
./tests/bench_sievegap "$ITERS" "$WINDOW_SIZE" "$SIEVE_LIMIT"
