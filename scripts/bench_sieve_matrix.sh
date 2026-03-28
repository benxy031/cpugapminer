#!/usr/bin/env bash
set -euo pipefail

# Benchmark sieve-size/sieve-primes matrix for cpugapminer.
#
# Usage examples:
#   MINER_ARGS="--rpc-url http://127.0.0.1:31397 --user benxy031 --pass xx --cuda 0 --threads 8" \
#   DURATION_SEC=300 TARGET=20.5607 CASES="A,B,C" ./scripts/bench_sieve_matrix.sh
#
# Env knobs:
#   MINER_ARGS     Extra args passed to gap_miner (RPC/pool/GPU/thread config).
#   DURATION_SEC   Per-case duration in seconds (default: 300).
#   TARGET         Merit target passed to --target (default: 20.5607).
#   CASES          Comma-separated case labels to run (default: A).
#   LOG_DIR        Output dir for logs/summaries (default: logs/bench).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/gap_miner}"
MINER_ARGS="${MINER_ARGS:--o 127.0.0.1 -p 31397 -u benxy031 --pass xx --shift 64 --threads 3 --fast-fermat --cuda --sample-stride 5 --partial-sieve-auto --adaptive-presieve}"
DURATION_SEC="${DURATION_SEC:-100}"
TARGET="${TARGET:-20.5607}"
CASES="${CASES:-A,B,C,D,E,F,G,H}"
LOG_DIR="${LOG_DIR:-logs/bench}"

if [[ ! -x "$BIN" ]]; then
  echo "error: missing executable $BIN" >&2
  echo "hint: build first with make WITH_RPC=1 WITH_CUDA=1" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$LOG_DIR/$TS"
mkdir -p "$OUT_DIR"

# 8-case matrix around baseline.
CASE_NAMES=(A B C D E F G H)
# CASE_SIEVE_SIZE=(33554432 33554432 33554432 67108864 67108864 67108864 134217728 134217728)
CASE_SIEVE_SIZE=(33554432 67108864 33554432 67108864 33554432 67108864 33554432 67108864)
CASE_SIEVE_PRIMES=(1800000 1000000 2000000 2000000 2200000 2200000 2800000 2800000)

want_case() {
  local c="$1"
  IFS=',' read -r -a sel <<< "$CASES"
  for x in "${sel[@]}"; do
    if [[ "$x" == "$c" ]]; then
      return 0
    fi
  done
  return 1
}

summary_file="$OUT_DIR/summary.tsv"
printf "case\tcrt_mode\tsieve_size\tsieve_primes\ttested_per_s\tpps\test\tbest_merit\tsurv_per_msieved\tpairs_per_msieved\tfalse_gaps\tfalse_gap_pct\taccepted\tsubmitted\tpartial_auto_windows\tpartial_auto_activations\tpartial_auto_adjusts\tpartial_auto_limit\tpartial_auto_avg\tsieve_keep\tsieve_boost\tsieve_limit\tconsumer_windows\tconsumer_last_gap\tconsumer_last_qual_gap\n" > "$summary_file"

echo "benchmark output: $OUT_DIR"
echo "duration per case: ${DURATION_SEC}s"
echo "target merit: $TARGET"
echo "cases: $CASES"

auto_timeout_cmd="timeout"
if ! command -v timeout >/dev/null 2>&1; then
  echo "error: timeout command not found" >&2
  exit 1
fi

for i in "${!CASE_NAMES[@]}"; do
  case_name="${CASE_NAMES[$i]}"
  if ! want_case "$case_name"; then
    continue
  fi

  ss="${CASE_SIEVE_SIZE[$i]}"
  sp="${CASE_SIEVE_PRIMES[$i]}"
  log_file="$OUT_DIR/${case_name}.log"

  echo
  echo "== Case $case_name: --sieve-size $ss --sieve-primes $sp =="
  echo "log: $log_file"

  # shellcheck disable=SC2086
  cmd=("$BIN" $MINER_ARGS --target "$TARGET" --sieve-size "$ss" --sieve-primes "$sp")

  set +e
  stdbuf -oL -eL "$auto_timeout_cmd" "${DURATION_SEC}s" "${cmd[@]}" >"$log_file" 2>&1
  rc=$?
  set -e

  # timeout exits 124 by design; treat as success for timed benchmark.
  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "case $case_name failed (rc=$rc); see $log_file" >&2
  fi

  last_stats="$(grep "STATS:" "$log_file" | tail -n 1 || true)"
  if [[ -z "$last_stats" ]]; then
    last_stats="NO_STATS_LINE"
  fi

  sieve_model_line="$(grep "sieve_model:" "$log_file" | tail -n 1 || true)"
  if [[ -z "$sieve_model_line" ]]; then
    sieve_model_line="NA"
  fi

  crt_mode_line="$(grep "CRT mode:" "$log_file" | tail -n 1 || true)"
  if [[ -z "$crt_mode_line" ]]; then
    crt_mode_line="NA"
  fi

  consumer_line="$(grep "consumer_windows=" "$log_file" | tail -n 1 || true)"
  if [[ -z "$consumer_line" ]]; then
    consumer_line="NA"
  fi

  partial_auto_line="$(grep "partial_auto=on" "$log_file" | tail -n 1 || true)"
  if [[ -z "$partial_auto_line" ]]; then
    partial_auto_line="NA"
  fi

  partial_auto_windows="$(echo "$partial_auto_line" | sed -n 's/.*windows=\([0-9]\+\).*/\1/p')"
  partial_auto_activations="$(echo "$partial_auto_line" | sed -n 's/.*activations=\([0-9]\+\).*/\1/p')"
  partial_auto_adjusts="$(echo "$partial_auto_line" | sed -n 's/.*adjusts=\([0-9]\+\).*/\1/p')"
  partial_auto_limit="$(echo "$partial_auto_line" | sed -n 's/.*limit=\([0-9]\+\).*/\1/p')"
  partial_auto_avg="$(echo "$partial_auto_line" | sed -n 's/.*avg=\([0-9]\+\).*/\1/p')"

  sieve_keep="$(echo "$sieve_model_line" | sed -n 's/.*keep~\([0-9.eE+-]\+\).*/\1/p')"
  sieve_boost="$(echo "$sieve_model_line" | sed -n 's/.*boost~\([0-9.eE+-]\+\)x.*/\1/p')"
  sieve_limit="$(echo "$sieve_model_line" | sed -n 's/.*limit=\([0-9]\+\)).*/\1/p')"

  crt_mode="$(echo "$crt_mode_line" | sed -n 's/.*CRT mode: \(.*\)$/\1/p')"

  consumer_windows="$(echo "$consumer_line" | sed -n 's/.*consumer_windows=\([0-9]\+\).*/\1/p')"
  consumer_last_gap="$(echo "$consumer_line" | sed -n 's/.*last_gap=\([0-9]\+\).*/\1/p')"
  consumer_last_qual_gap="$(echo "$consumer_line" | sed -n 's/.*last_qual_gap=\([0-9]\+\).*/\1/p')"

  cpu_line="$(grep "cpu:" "$log_file" | tail -n 1 || true)"

  tested_per_s="$(echo "$last_stats" | sed -n 's/.*tested=[0-9]\+ (\([0-9.]\+\)\/s).*/\1/p')"
  pps="$(echo "$last_stats" | sed -n 's/.* pps=\([0-9.]\+\).*/\1/p')"
  est="$(echo "$last_stats" | sed -n 's/.* est=\([^ ]*\).*/\1/p')"
  best_merit="$(echo "$last_stats" | sed -n 's/.* best=\([0-9]\+\.[0-9]\+\).*/\1/p')"
  accepted="$(echo "$last_stats" | sed -n 's/.* accepted=\([0-9]\+\).*/\1/p')"
  submitted="$(echo "$last_stats" | sed -n 's/.* submitted=\([0-9]\+\).*/\1/p')"

  surv_per_msieved="$(echo "$cpu_line" | sed -n 's/.*surv\/Msieved=\([0-9]\+\.[0-9]\+\).*/\1/p')"
  pairs_per_msieved="$(echo "$cpu_line" | sed -n 's/.*pairs\/Msieved=\([0-9]\+\.[0-9]\+\).*/\1/p')"
  false_gaps="$(echo "$cpu_line" | sed -n 's/.*false_gaps=\([0-9]\+\).*/\1/p')"
  false_gap_pct="$(echo "$cpu_line" | sed -n 's/.*false_gaps=[0-9]\+ (\([0-9]\+\.[0-9]\+\)%).*/\1/p')"

  tested_per_s="${tested_per_s:-NA}"
  pps="${pps:-NA}"
  est="${est:-NA}"
  best_merit="${best_merit:-NA}"
  surv_per_msieved="${surv_per_msieved:-NA}"
  pairs_per_msieved="${pairs_per_msieved:-NA}"
  false_gaps="${false_gaps:-NA}"
  false_gap_pct="${false_gap_pct:-NA}"
  accepted="${accepted:-NA}"
  submitted="${submitted:-NA}"
  partial_auto_windows="${partial_auto_windows:-NA}"
  partial_auto_activations="${partial_auto_activations:-NA}"
  partial_auto_adjusts="${partial_auto_adjusts:-NA}"
  partial_auto_limit="${partial_auto_limit:-NA}"
  partial_auto_avg="${partial_auto_avg:-NA}"
  sieve_keep="${sieve_keep:-NA}"
  sieve_boost="${sieve_boost:-NA}"
  sieve_limit="${sieve_limit:-NA}"
  crt_mode="${crt_mode:-NA}"
  consumer_windows="${consumer_windows:-NA}"
  consumer_last_gap="${consumer_last_gap:-NA}"
  consumer_last_qual_gap="${consumer_last_qual_gap:-NA}"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$case_name" "$crt_mode" "$ss" "$sp" "$tested_per_s" "$pps" "$est" "$best_merit" \
    "$surv_per_msieved" "$pairs_per_msieved" "$false_gaps" "$false_gap_pct" \
    "$accepted" "$submitted" "$partial_auto_windows" "$partial_auto_activations" \
    "$partial_auto_adjusts" "$partial_auto_limit" "$partial_auto_avg" \
    "$sieve_keep" "$sieve_boost" "$sieve_limit" \
    "$consumer_windows" "$consumer_last_gap" "$consumer_last_qual_gap" >> "$summary_file"
done

echo
echo "done. summary: $summary_file"
cat "$summary_file"
