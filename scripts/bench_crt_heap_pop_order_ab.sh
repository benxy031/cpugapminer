#!/usr/bin/env bash
# Copyright (C) 2026  cpugapminer contributors
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

# A/B/C test for --crt-heap-pop-order (score [default] vs fifo vs random):
# does changing which pending CRT window the consumer(s) pop next affect
# throughput (tested/s, windows/s) or correctness (false_gaps)? This is
# "Plan A" from the GapMiner-Unified comparative study (hazard-based top-K
# queue): score already implements a priority pop (max-heap on
# cramer_score/sqrt(surv_cnt+1)); fifo and random are the two baselines that
# isolate whether the priority ordering itself is doing anything measurable
# versus just being "any deterministic-ish policy on a bounded queue".
#
# This is measurement only; it does not change the default (score) pop
# order, and --crt-heap-pop-order is off by default (opt-in flag).
#
# Usage:
#   ./scripts/bench_crt_heap_pop_order_ab.sh
#   FILE=crt/crt_s768_m28.txt DURATION_SEC=1800 REPS=3 \
#     CUDA_DEVICES=0 ./scripts/bench_crt_heap_pop_order_ab.sh
#
# Env knobs:
#   BIN            Miner binary (default: ./bin/gap_miner).
#   FILE           CRT file to test (default: crt/crt_s768_m23.txt).
#   THREADS        Total miner threads (default: 8).
#   FERMAT_THREADS Consumer threads for --fermat-threads (default: 2; must
#                  be > 0 — pop-order only matters in producer/consumer
#                  mode, this is what feeds the bounded crt_heap).
#   DURATION_SEC   Per-run duration in seconds (default: 1800 = 30 min;
#                  the pop-order effect, if any, is expected to be small,
#                  so short runs will be dominated by noise).
#   MODES          Comma-separated pop-order modes to test (default:
#                  score,fifo,random).
#   REPS           Repeats per mode (default: 3).
#   HEADER         Fixed 64-hex-char header so runs are reproducible and
#                  RPC-free (default: all zeros).
#   CUDA_DEVICES   If set (e.g. "0"), run with `--cuda "$CUDA_DEVICES"
#                  --crt-gpu-consumer` (GPU Fermat consumer) instead of the
#                  CPU-only baseline. --crt-gpu-consumer is required here:
#                  without it GPU stays disabled in producer/consumer CRT
#                  mode even with --cuda given (silent no-op).
#   LOG_DIR        Output root (default: logs/bench_crt_heap_pop_order_ab).
#
# The (mode, rep) run order is randomized (via `shuf`, when available) so a
# fixed arm ordering doesn't get confounded with time-of-day/thermal drift
# across the whole sweep. After the sweep, group summary.tsv by mode and
# compare mean/stdev of tested_per_s and windows_per_s across reps; also
# check stale/wait_pct to see whether score actually reduces staleness vs
# fifo/random as hypothesized, or whether the bounded heap is small/fast
# enough that pop policy doesn't matter in practice.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/gap_miner}"
FILE="${FILE:-crt/crt_s768_m23.txt}"
THREADS="${THREADS:-8}"
FERMAT_THREADS="${FERMAT_THREADS:-2}"
DURATION_SEC="${DURATION_SEC:-1200}"
MODES="${MODES:-score,fifo,random}"
REPS="${REPS:-3}"
HEADER="${HEADER:-0000000000000000000000000000000000000000000000000000000000000000}"
CUDA_DEVICES="${CUDA_DEVICES:-}"
LOG_DIR="${LOG_DIR:-logs/bench_crt_heap_pop_order_ab}"

if [[ ! -x "$BIN" ]]; then
  echo "error: missing executable $BIN" >&2
  echo "hint: build first (see /memories/repo/cpugapminer-build-and-patch.md)" >&2
  exit 1
fi

if [[ ! -f "$FILE" ]]; then
  echo "error: CRT file not found: $FILE" >&2
  exit 1
fi

if (( FERMAT_THREADS < 1 )); then
  echo "error: FERMAT_THREADS must be >= 1 (pop-order only applies in producer/consumer mode)" >&2
  exit 1
fi

shift_val=$(awk '$1=="shift"{print $2; exit}' "$FILE")
if [[ -z "$shift_val" ]]; then
  echo "error: could not parse shift from header of $FILE" >&2
  exit 1
fi

gpu_flags=()
gpu_desc="off (CPU-only baseline)"
if [[ -n "$CUDA_DEVICES" ]]; then
  gpu_flags=(--cuda "$CUDA_DEVICES" --crt-gpu-consumer)
  gpu_desc="--cuda $CUDA_DEVICES --crt-gpu-consumer (GPU Fermat consumer)"
fi

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$LOG_DIR/$TS"
mkdir -p "$OUT_DIR"

summary_file="$OUT_DIR/summary.tsv"
printf "mode\trep\ttested_per_s\twindows_per_s\tfalse_gaps\tgaplist_hwm\tpush\treplace\tdrop_pct\tpop\twait_pct\tstale\n" > "$summary_file"

echo "output dir: $OUT_DIR"
echo "file: $FILE (shift=$shift_val)"
echo "threads=$THREADS fermat_threads=$FERMAT_THREADS duration=${DURATION_SEC}s"
echo "gpu: $gpu_desc"
echo "modes: $MODES  reps: $REPS"

IFS=',' read -r -a mode_list <<< "$MODES"
plan=()
for m in "${mode_list[@]}"; do
  for ((r=1; r<=REPS; r++)); do
    plan+=("$m:$r")
  done
done

if command -v shuf >/dev/null 2>&1; then
  mapfile -t plan < <(printf '%s\n' "${plan[@]}" | shuf)
else
  echo "note: shuf not found; running arms in fixed order (mode x rep)" >&2
fi

echo "run order (randomized where possible): ${plan[*]}"

for item in "${plan[@]}"; do
  mode="${item%%:*}"
  rep="${item##*:}"
  log_file="$OUT_DIR/${mode}_rep${rep}.log"
  echo
  echo "== mode=$mode rep=$rep =="
  echo "  log: $log_file"

  set +e
  stdbuf -oL -eL timeout "${DURATION_SEC}s" "$BIN" --shift "$shift_val" \
    --threads "$THREADS" --crt-file "$FILE" --fermat-threads "$FERMAT_THREADS" \
    --crt-heap-pop-order "$mode" "${gpu_flags[@]}" --header "$HEADER" \
    >"$log_file" 2>&1
  rc=$?
  set -e
  # timeout exits 124 by design; treat as success for a timed benchmark.
  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "  warning: run failed rc=$rc, see $log_file" >&2
  fi

  # print_stats() emits STATS + the CRT windows/heap block as one unbroken
  # write (no newline between log_msg calls), so all counters below live on
  # the same log line.
  last_stats="$(grep "STATS:" "$log_file" | tail -n 1 || true)"

  tested_per_s="$(echo "$last_stats" | sed -n 's/.*tested=[0-9]\+ (\([0-9.]\+\)\/s).*/\1/p')"
  # Require the literal two-space prefix so this doesn't match unrelated
  # "..._windows=" counters (partial_auto/adaptive_presieve/consumer_windows).
  windows_per_s="$(echo "$last_stats" | sed -n 's/.*  windows=[0-9]\+ (\([0-9.]\+\)\/s).*/\1/p')"
  false_gaps="$(echo "$last_stats" | sed -n 's/.*false_gaps=\([0-9]\+\).*/\1/p')"
  gaplist_hwm="$(echo "$last_stats" | sed -n 's/.*hwm=\([0-9]\+\).*/\1/p')"
  push="$(echo "$last_stats" | sed -n 's/.*push=\([0-9]\+\).*/\1/p')"
  replace="$(echo "$last_stats" | sed -n 's/.* rep=\([0-9]\+\).*/\1/p')"
  drop_pct="$(echo "$last_stats" | sed -n 's/.*drop=[0-9]\+ (\([0-9.]\+\)%).*/\1/p')"
  pop="$(echo "$last_stats" | sed -n 's/.* pop=\([0-9]\+\).*/\1/p')"
  wait_pct="$(echo "$last_stats" | sed -n 's/.*wait%=\([0-9.]\+\).*/\1/p')"
  stale="$(echo "$last_stats" | sed -n 's/.*stale=\([0-9]\+\).*/\1/p')"

  tested_per_s="${tested_per_s:-NA}"
  windows_per_s="${windows_per_s:-NA}"
  false_gaps="${false_gaps:-NA}"
  gaplist_hwm="${gaplist_hwm:-NA}"
  push="${push:-NA}"
  replace="${replace:-NA}"
  drop_pct="${drop_pct:-NA}"
  pop="${pop:-NA}"
  wait_pct="${wait_pct:-NA}"
  stale="${stale:-NA}"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$mode" "$rep" "$tested_per_s" "$windows_per_s" "$false_gaps" "$gaplist_hwm" \
    "$push" "$replace" "$drop_pct" "$pop" "$wait_pct" "$stale" \
    >> "$summary_file"

  echo "  tested/s=$tested_per_s windows/s=$windows_per_s false_gaps=$false_gaps wait%=$wait_pct stale=$stale"
done

echo
echo "done. summary: $summary_file"
column -t -s $'\t' "$summary_file"
echo
echo "next: group by mode and compare mean/stdev of tested_per_s and"
echo "windows_per_s across reps; false_gaps must stay 0 (or match baseline)"
echo "in every arm — a nonzero delta there would mean the pop-order change"
echo "broke correctness, not just performance."
