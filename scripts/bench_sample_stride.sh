#!/usr/bin/env bash
# Copyright (C) 2026  cpugapminer contributors
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Benchmark various --sample-stride values for cpugapminer (non-CRT GPU path).
#
# Usage:
#   MINER_ARGS="--rpc-url http://127.0.0.1:31397 --rpc-user benxy031 --rpc-pass xx \
#               --shift 68 --threads 4 --fast-euler --cuda \
#               --sieve-primes 3300000 --sieve-size 25500000 --no-gpu-sieve" \
#   DURATION_SEC=180 STRIDES="1,2,5,10,20" ./scripts/bench_sample_stride.sh
#
# Env knobs:
#   MINER_ARGS    Base args passed to gap_miner (RPC/GPU/thread/sieve config).
#                 Do NOT include --sample-stride here; the script adds it.
#   DURATION_SEC  Per-stride duration in seconds (default: 180).
#   STRIDES       Comma-separated stride values to test (default: 1,2,5,10,20).
#   LOG_DIR       Output dir for logs/summaries (default: logs/bench_stride).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/gap_miner}"
MINER_ARGS="${MINER_ARGS:---rpc-url http://127.0.0.1:31397 --rpc-user benxy031 --rpc-pass xx \
--shift 68 --threads 6 --fast-euler \
--sieve-primes 1000000 --sieve-size 33500000 --no-gpu-sieve}"
DURATION_SEC="${DURATION_SEC:-180}"
STRIDES="${STRIDES:-29,37,47,57}"
LOG_DIR="${LOG_DIR:-logs/bench_stride}"

if [[ ! -x "$BIN" ]]; then
  echo "error: missing executable $BIN" >&2
  echo "hint: build first with: make WITH_RPC=1 WITH_CUDA=1 CUDA_ARCH=\"-arch=sm_86\"" >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "error: timeout command not found" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$LOG_DIR/$TS"
mkdir -p "$OUT_DIR"

summary_file="$OUT_DIR/summary.tsv"
printf "stride\tsieved_per_s\ttested_per_s\tpps\tprimes_pct\tpairs_per_msieved\tsurv_per_msieved\tbest_merit\tgaps\test\tgpu_batch\tgpu_sieve_calls\n" > "$summary_file"

echo "benchmark output: $OUT_DIR"
echo "duration per stride: ${DURATION_SEC}s"
echo "strides: $STRIDES"
echo ""

IFS=',' read -r -a STRIDE_LIST <<< "$STRIDES"

for stride in "${STRIDE_LIST[@]}"; do
  log_file="$OUT_DIR/stride_${stride}.log"
  echo "== stride=$stride =="
  echo "log: $log_file"

  # shellcheck disable=SC2086
  cmd=("$BIN" $MINER_ARGS --sample-stride "$stride")

  set +e
  stdbuf -oL -eL timeout "${DURATION_SEC}s" "${cmd[@]}" >"$log_file" 2>&1
  rc=$?
  set -e

  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "  stride=$stride failed (rc=$rc); see $log_file" >&2
  fi

  last_stats="$(grep "^STATS:" "$log_file" | tail -n 1 || true)"
  if [[ -z "$last_stats" ]]; then
    echo "  no STATS line found"
    printf "%s\tNA\tNA\tNA\tNA\tNA\tNA\tNA\tNA\tNA\tNA\tNA\n" "$stride" >> "$summary_file"
    continue
  fi

  extract() { echo "$last_stats" | sed -n "s/.*${1}=\([^ ]*\).*/\1/p" | head -1; }

  # sieved/s from "sieved=N (Xs/s)"
  sieved_per_s="$(echo "$last_stats" | sed -n 's/.*sieved=[0-9]* (\([0-9]*\)\/s).*/\1/p' | head -1)"
  tested_per_s="$(echo "$last_stats" | sed -n 's/.*tested=[0-9]* (\([0-9]*\)\/s).*/\1/p' | head -1)"
  pps="$(extract 'pps')"
  primes_pct="$(echo "$last_stats" | sed -n 's/.*primes=[0-9]* (\([0-9.]*\)%).*/\1/p' | head -1)"
  best_merit="$(echo "$last_stats" | sed -n 's/.*best=\([0-9.]*\) .*/\1/p' | head -1)"
  gaps="$(echo "$last_stats" | sed -n 's/.*gaps=\([0-9]*\) .*/\1/p' | head -1)"
  est="$(echo "$last_stats" | sed -n 's/.* est=\([^ ]*\).*/\1/p' | head -1)"
  gpu_batch="$(extract 'gpu_batch')"
  gpu_sieve_calls="$(extract 'gpu_sieve_calls')"

  pairs_per_msieved="$(echo "$last_stats" | sed -n 's/.*pairs\/Msieved=\([0-9.]*\).*/\1/p' | head -1)"
  surv_per_msieved="$(echo "$last_stats"  | sed -n 's/.*surv\/Msieved=\([0-9.]*\).*/\1/p'  | head -1)"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$stride" "$sieved_per_s" "$tested_per_s" "$pps" "$primes_pct" \
    "$pairs_per_msieved" "$surv_per_msieved" \
    "$best_merit" "$gaps" "$est" \
    "${gpu_batch:-NA}" "${gpu_sieve_calls:-NA}" >> "$summary_file"

  echo "  sieved/s=${sieved_per_s}  tested/s=${tested_per_s}  pps=${pps}  pairs/Msieved=${pairs_per_msieved}  best=${best_merit}  gaps=${gaps}  est=${est}"
  echo ""
done

echo "=== Summary ==="
column -t -s $'\t' "$summary_file"
echo ""
echo "Full summary: $summary_file"
