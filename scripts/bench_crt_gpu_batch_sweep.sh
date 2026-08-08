#!/usr/bin/env bash
# Copyright (C) 2026  cpugapminer contributors
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

# Sweep --gpu-batch (CRT GPU-Fermat accumulator flush threshold) for a fixed
# CRT geometry/target on a CUDA GPU, looking for a peak-then-regression
# throughput curve. This is "Plan B" from the GapMiner-Unified comparative
# study: that project found its CGBN row-population sweep on an RTX 3090
# peaked at 512 rows (+1.36% over 256) and then regressed monotonically at
# 1024/2048/4096/8192. Their numbers do not transfer directly — different
# GPU architecture (CGBN per-row wavefront vs. this project's flat
# accumulate-then-flush batch) and a different card (RTX 3070 here, Ampere
# GA104 sm_86, vs. their RTX 3090) — but the *methodology* (fixed batch
# size per run, same CRT geometry/duration, look for a non-monotonic curve
# instead of assuming "bigger batch = always better") is directly
# applicable.
#
# --crt-gpu-batch-adaptive is intentionally left OFF (its default) on every
# run in this sweep so each case uses a genuinely fixed --gpu-batch value;
# the adaptive tuner would otherwise grow/shrink the batch at runtime and
# defeat the point of sweeping it.
#
# Every run also passes --crt-gpu-consumer: without it, GPU is disabled in
# producer/consumer CRT mode (--fermat-threads N>0) even with --cuda given,
# and no gpu_flushes/gpu_batched stats line is ever emitted. This flag is
# marked "experimental" in --help; that is a pre-existing project label,
# unrelated to this script.
#
# This is measurement only; it does not change any default.
#
# Usage:
#   ./scripts/bench_crt_gpu_batch_sweep.sh
#   FILE=crt/crt_s768_m28.txt CUDA_DEVICES=0 DURATION_SEC=1200 \
#     BATCHES="512,1024,2048,4096,8192,16384,24576,32768" \
#     ./scripts/bench_crt_gpu_batch_sweep.sh
#
# Env knobs:
#   BIN            Miner binary (default: ./bin/gap_miner).
#   FILE           CRT file to test (default: crt/crt_s768_m23.txt — a
#                  shift=768 file so the sweep matches the shift band whose
#                  phase1 profile default gpu_batch is highest, 16384; see
#                  g_crt_phase1_profiles in src/main.c).
#   CUDA_DEVICES   CUDA device index/list for --cuda (default: 0; required
#                  — this script always builds a --cuda run, never CPU-only).
#   THREADS        Total miner threads (default: 8).
#   FERMAT_THREADS Consumer threads for --fermat-threads (default: 2).
#   DURATION_SEC   Per-batch-size run duration in seconds (default: 1200 =
#                  20 min; needs to be long enough for gpu_flushes to
#                  accumulate a stable average batch/throughput reading).
#   BATCHES        Comma-separated --gpu-batch values to sweep (default:
#                  512,1024,2048,4096,8192,16384,24576,32768 — spans the
#                  adaptive tuner's default [min_batch=512,max_batch=32768]
#                  range and brackets the shift>=768 profile default of
#                  16384; see g_crt_gpu_batch_adapt_cfg in src/main.c).
#   REPS           Repeats per batch size (default: 1; raise if GPU clocks
#                  are noisy/thermal-throttling on your box).
#   HEADER         Fixed 64-hex-char header so runs are reproducible and
#                  RPC-free (default: all zeros).
#   LOG_DIR        Output root (default: logs/bench_crt_gpu_batch_sweep).
#
# The (batch, rep) run order is randomized (via `shuf`, when available) to
# reduce confounding with thermal drift / clock ramp-up over the sweep.
# After the sweep, plot tested_per_s (and gpu_batch_avg, as a sanity check
# that the accumulator actually reached close to the requested size) against
# the swept --gpu-batch value; a peak-then-regression shape (rather than
# monotonic increase) would mirror the GapMiner-Unified finding and justify
# lowering this project's phase1 profile defaults for the affected shift
# bands.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/gap_miner}"
FILE="${FILE:-crt/crt_s768_m23.txt}"
CUDA_DEVICES="${CUDA_DEVICES:-0}"
THREADS="${THREADS:-8}"
FERMAT_THREADS="${FERMAT_THREADS:-2}"
DURATION_SEC="${DURATION_SEC:-1200}"
BATCHES="${BATCHES:-512,1024,2048,4096,8192,16384,24576,32768}"
REPS="${REPS:-1}"
HEADER="${HEADER:-0000000000000000000000000000000000000000000000000000000000000000}"
LOG_DIR="${LOG_DIR:-logs/bench_crt_gpu_batch_sweep}"

if [[ ! -x "$BIN" ]]; then
  echo "error: missing executable $BIN" >&2
  echo "hint: build with WITH_CUDA=1 first (see /memories/repo/cpugapminer-build-and-patch.md)" >&2
  exit 1
fi

if [[ ! -f "$FILE" ]]; then
  echo "error: CRT file not found: $FILE" >&2
  exit 1
fi

if [[ -z "$CUDA_DEVICES" ]]; then
  echo "error: CUDA_DEVICES must be set (this sweep only makes sense with --cuda)" >&2
  exit 1
fi

if (( FERMAT_THREADS < 1 )); then
  echo "error: FERMAT_THREADS must be >= 1 (GPU accumulator needs a consumer thread)" >&2
  exit 1
fi

shift_val=$(awk '$1=="shift"{print $2; exit}' "$FILE")
if [[ -z "$shift_val" ]]; then
  echo "error: could not parse shift from header of $FILE" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$LOG_DIR/$TS"
mkdir -p "$OUT_DIR"

summary_file="$OUT_DIR/summary.tsv"
printf "gpu_batch\trep\ttested_per_s\twindows_per_s\tfalse_gaps\tgpu_flushes\tgpu_batched\tgpu_batch_avg\tgpu_direct_batch_cap\n" > "$summary_file"

echo "output dir: $OUT_DIR"
echo "file: $FILE (shift=$shift_val)"
echo "cuda: $CUDA_DEVICES  threads=$THREADS fermat_threads=$FERMAT_THREADS duration=${DURATION_SEC}s"
echo "batches: $BATCHES  reps: $REPS"
echo "adaptive batch tuner: off (fixed --gpu-batch per run)"

IFS=',' read -r -a batch_list <<< "$BATCHES"
plan=()
for b in "${batch_list[@]}"; do
  for ((r=1; r<=REPS; r++)); do
    plan+=("$b:$r")
  done
done

if command -v shuf >/dev/null 2>&1; then
  mapfile -t plan < <(printf '%s\n' "${plan[@]}" | shuf)
else
  echo "note: shuf not found; running arms in fixed order (batch x rep)" >&2
fi

echo "run order (randomized where possible): ${plan[*]}"

for item in "${plan[@]}"; do
  batch="${item%%:*}"
  rep="${item##*:}"
  log_file="$OUT_DIR/batch${batch}_rep${rep}.log"
  echo
  echo "== gpu-batch=$batch rep=$rep =="
  echo "  log: $log_file"

  set +e
  stdbuf -oL -eL timeout "${DURATION_SEC}s" "$BIN" --shift "$shift_val" \
    --threads "$THREADS" --crt-file "$FILE" --fermat-threads "$FERMAT_THREADS" \
    --cuda "$CUDA_DEVICES" --crt-gpu-consumer --gpu-batch "$batch" --header "$HEADER" \
    >"$log_file" 2>&1
  rc=$?
  set -e
  # timeout exits 124 by design; treat as success for a timed benchmark.
  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "  warning: run failed rc=$rc, see $log_file" >&2
  fi

  # print_stats() emits STATS + the CRT windows/GPU-accum block as one
  # unbroken write (no newline between log_msg calls), so all counters
  # below live on the same log line.
  last_stats="$(grep "STATS:" "$log_file" | tail -n 1 || true)"

  tested_per_s="$(echo "$last_stats" | sed -n 's/.*tested=[0-9]\+ (\([0-9.]\+\)\/s).*/\1/p')"
  # Require the literal two-space prefix so this doesn't match unrelated
  # "..._windows=" counters (partial_auto/adaptive_presieve/consumer_windows).
  windows_per_s="$(echo "$last_stats" | sed -n 's/.*  windows=[0-9]\+ (\([0-9.]\+\)\/s).*/\1/p')"
  false_gaps="$(echo "$last_stats" | sed -n 's/.*false_gaps=\([0-9]\+\).*/\1/p')"
  gpu_flushes="$(echo "$last_stats" | sed -n 's/.*gpu_flushes=\([0-9]\+\).*/\1/p')"
  gpu_batched="$(echo "$last_stats" | sed -n 's/.*gpu_batched=\([0-9]\+\).*/\1/p')"
  gpu_batch_avg="$(echo "$last_stats" | sed -n 's/.*gpu_batch=\([0-9.]\+\).*/\1/p')"
  gpu_direct_batch_cap="$(echo "$last_stats" | sed -n 's/.*gpu_direct_batch_cap=\([0-9]\+\).*/\1/p')"

  tested_per_s="${tested_per_s:-NA}"
  windows_per_s="${windows_per_s:-NA}"
  false_gaps="${false_gaps:-NA}"
  gpu_flushes="${gpu_flushes:-NA}"
  gpu_batched="${gpu_batched:-NA}"
  gpu_batch_avg="${gpu_batch_avg:-NA}"
  gpu_direct_batch_cap="${gpu_direct_batch_cap:-NA}"

  if [[ "$gpu_flushes" == "NA" ]]; then
    echo "  warning: no gpu_flushes=... line found (GPU accumulator never flushed within ${DURATION_SEC}s?)" >&2
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$batch" "$rep" "$tested_per_s" "$windows_per_s" "$false_gaps" \
    "$gpu_flushes" "$gpu_batched" "$gpu_batch_avg" "$gpu_direct_batch_cap" \
    >> "$summary_file"

  echo "  tested/s=$tested_per_s windows/s=$windows_per_s false_gaps=$false_gaps gpu_flushes=$gpu_flushes gpu_batch_avg=$gpu_batch_avg"
done

echo
echo "done. summary: $summary_file"
column -t -s $'\t' "$summary_file"
echo
echo "next: plot tested_per_s against gpu_batch (mean across reps); check"
echo "gpu_batch_avg is reasonably close to the requested --gpu-batch value"
echo "(if it's much lower, the accumulator is flushing early due to"
echo "backpressure/slow_flush_ms/slow_collect_ms before reaching the target"
echo "size, and the swept value isn't actually being exercised). Look for a"
echo "peak-then-regression shape rather than assuming larger is always"
echo "better."
