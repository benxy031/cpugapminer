#!/usr/bin/env bash
# Copyright (C) 2026  cpugapminer contributors
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Benchmark GPU-sieve A/B env profiles for non-CRT runs.
#
# Usage:
#   MINER_ARGS="--header abtest --shift 46 --threads 3 --cuda --fast-euler \
#               --sieve-primes 900000 --sieve-size 33554432 --gpu-sieve" \
#   DURATION_SEC=120 PROFILES="A0,A1,B1,A2,A3" ./scripts/bench_gpu_sieve_ab.sh
#
# Env knobs:
#   BIN          Miner binary path (default: ./bin/gap_miner)
#   MINER_ARGS   Base args passed to miner.
#   DURATION_SEC Per-profile runtime in seconds (default: 120)
#   PROFILES     Comma-separated profile list (default: A0,A1,B1,A2,A3)
#   LOG_DIR      Output root directory (default: logs/bench_gpu_sieve_ab)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/gap_miner}"
MINER_ARGS="${MINER_ARGS:---header abtest --shift 46 --threads 3 --cuda --fast-euler --sieve-primes 900000 --sieve-size 33554432 --gpu-sieve}"
DURATION_SEC="${DURATION_SEC:-120}"
PROFILES="${PROFILES:-A0,A1,B1,A2,A3}"
LOG_DIR="${LOG_DIR:-logs/bench_gpu_sieve_ab}"

if [[ ! -x "$BIN" ]]; then
  echo "error: missing executable $BIN" >&2
  echo "hint: build first with make WITH_CUDA=1" >&2
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
printf "profile\tmin_ph2\tmin_segment\tdirect_bits\tsieved_per_s\ttested_per_s\tpps\tgpu_sieve_calls\tgpu_sieve_primes_per_call\tgpu_sieve_fallback\tsurv_calls\tk0_inc_pct\tmark_us\tpack_us\tbits_dl_us\tfalse_gaps\tfalse_gaps_pct\n" > "$summary_file"

profile_env() {
  local profile="$1"
  case "$profile" in
    A0)
      export GPU_SIEVE_MIN_PH2=0
      export GPU_SIEVE_MIN_SEGMENT=1
      export GPU_SIEVE_DIRECT_BITS=1
      ;;
    A1)
      export GPU_SIEVE_MIN_PH2=16384
      export GPU_SIEVE_MIN_SEGMENT=262144
      export GPU_SIEVE_DIRECT_BITS=1
      ;;
    A2)
      export GPU_SIEVE_MIN_PH2=65536
      export GPU_SIEVE_MIN_SEGMENT=524288
      export GPU_SIEVE_DIRECT_BITS=1
      ;;
    A3)
      export GPU_SIEVE_MIN_PH2=8192
      export GPU_SIEVE_MIN_SEGMENT=131072
      export GPU_SIEVE_DIRECT_BITS=1
      ;;
    B1)
      export GPU_SIEVE_MIN_PH2=16384
      export GPU_SIEVE_MIN_SEGMENT=262144
      export GPU_SIEVE_DIRECT_BITS=0
      ;;
    *)
      echo "error: unknown profile '$profile'" >&2
      return 1
      ;;
  esac
}

echo "benchmark output: $OUT_DIR"
echo "duration per profile: ${DURATION_SEC}s"
echo "profiles: $PROFILES"

IFS=',' read -r -a profile_list <<< "$PROFILES"

for profile in "${profile_list[@]}"; do
  profile_env "$profile"
  log_file="$OUT_DIR/${profile}.log"

  echo
  echo "== Profile $profile =="
  echo "env: GPU_SIEVE_MIN_PH2=$GPU_SIEVE_MIN_PH2 GPU_SIEVE_MIN_SEGMENT=$GPU_SIEVE_MIN_SEGMENT GPU_SIEVE_DIRECT_BITS=$GPU_SIEVE_DIRECT_BITS"
  echo "log: $log_file"

  # shellcheck disable=SC2086
  cmd=("$BIN" $MINER_ARGS)

  set +e
  stdbuf -oL -eL timeout "${DURATION_SEC}s" "${cmd[@]}" >"$log_file" 2>&1
  rc=$?
  set -e

  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "profile $profile failed (rc=$rc); see $log_file" >&2
  fi

  last_stats="$(grep '^STATS:' "$log_file" | tail -n 1 || true)"
  gpu_line="$(grep 'gpu_sieve_calls=' "$log_file" | tail -n 1 || true)"
  k0_line="$(grep 'gpu_sieve_k0_mode:' "$log_file" | tail -n 1 || true)"
  timing_line="$(grep 'gpu_sieve_us/call:' "$log_file" | tail -n 1 || true)"
  cpu_line="$(grep 'cpu:' "$log_file" | tail -n 1 || true)"

  sieved_per_s="$(echo "$last_stats" | sed -n 's/.*sieved=[0-9]* (\([0-9]*\)\/s).*/\1/p' | head -1)"
  tested_per_s="$(echo "$last_stats" | sed -n 's/.*tested=[0-9]* (\([0-9]*\)\/s).*/\1/p' | head -1)"
  pps="$(echo "$last_stats" | sed -n 's/.*pps([^)]*)=\([0-9.]*\).*/\1/p' | head -1)"
  if [[ -z "$pps" ]]; then
    pps="$(echo "$last_stats" | sed -n 's/.* pps=\([0-9.]*\).*/\1/p' | head -1)"
  fi

  gpu_sieve_calls="$(echo "$gpu_line" | sed -n 's/.*gpu_sieve_calls=\([0-9]\+\).*/\1/p')"
  gpu_sieve_primes_per_call="$(echo "$gpu_line" | sed -n 's/.*gpu_sieve_primes\/call=\([0-9]\+\).*/\1/p')"
  gpu_sieve_fallback="$(echo "$gpu_line" | sed -n 's/.*gpu_sieve_fallback=\([0-9]\+\).*/\1/p')"
  surv_calls="$(echo "$gpu_line" | sed -n 's/.*surv_calls=\([0-9]\+\).*/\1/p')"
  k0_inc_pct="$(echo "$k0_line" | sed -n 's/.*(inc=\([0-9.]\+\)%).*/\1/p')"

  mark_us="$(echo "$timing_line" | sed -n 's/.* mark=\([0-9.]*\).*/\1/p')"
  pack_us="$(echo "$timing_line" | sed -n 's/.* pack=\([0-9.]*\).*/\1/p')"
  bits_dl_us="$(echo "$timing_line" | sed -n 's/.* bits_dl=\([0-9.]*\).*/\1/p')"

  false_gaps="$(echo "$cpu_line" | sed -n 's/.*false_gaps=\([0-9]\+\).*/\1/p')"
  false_gaps_pct="$(echo "$cpu_line" | sed -n 's/.*false_gaps=[0-9]\+ (\([0-9.]\+\)%).*/\1/p')"

  sieved_per_s="${sieved_per_s:-NA}"
  tested_per_s="${tested_per_s:-NA}"
  pps="${pps:-NA}"
  gpu_sieve_calls="${gpu_sieve_calls:-NA}"
  gpu_sieve_primes_per_call="${gpu_sieve_primes_per_call:-NA}"
  gpu_sieve_fallback="${gpu_sieve_fallback:-NA}"
  surv_calls="${surv_calls:-NA}"
  k0_inc_pct="${k0_inc_pct:-NA}"
  mark_us="${mark_us:-NA}"
  pack_us="${pack_us:-NA}"
  bits_dl_us="${bits_dl_us:-NA}"
  false_gaps="${false_gaps:-NA}"
  false_gaps_pct="${false_gaps_pct:-NA}"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$profile" "$GPU_SIEVE_MIN_PH2" "$GPU_SIEVE_MIN_SEGMENT" "$GPU_SIEVE_DIRECT_BITS" \
    "$sieved_per_s" "$tested_per_s" "$pps" \
    "$gpu_sieve_calls" "$gpu_sieve_primes_per_call" "$gpu_sieve_fallback" "$surv_calls" \
    "$k0_inc_pct" "$mark_us" "$pack_us" "$bits_dl_us" "$false_gaps" "$false_gaps_pct" \
    >> "$summary_file"

  echo "  sieved/s=$sieved_per_s tested/s=$tested_per_s pps=$pps gpu_calls=$gpu_sieve_calls fallback=$gpu_sieve_fallback false_gaps=$false_gaps"
done

echo
echo "done. summary: $summary_file"
column -t -s $'\t' "$summary_file"
