#!/usr/bin/env bash
set -euo pipefail

# Run gen_crt in series for a merit band, with CRT-only defaults.
#
# Default focus:
#   - shifts: 450, 512, 768, 1001
#   - merit range: 30..40
#   - output names: crt/crt_s<shift>_m<merit>_phase3.txt
#
# Examples:
#   ./scripts/gen_crt_series.sh
#   ./scripts/gen_crt_series.sh --shift 450 --merit-start 30 --merit-end 40
#   ./scripts/gen_crt_series.sh --shifts 450,512,768,1001 --merit-start 30 --merit-end 40 --dry-run
#   ./scripts/gen_crt_series.sh --shift 768 --ctr-strength 10000 --ctr-ivs 1000 --phase3

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GEN_CRT_BIN="${GEN_CRT_BIN:-./bin/gen_crt}"
OUT_DIR="${OUT_DIR:-crt}"
LOG_DIR="${LOG_DIR:-logs/crt_series}"

MERIT_START=30
MERIT_END=40
MERIT_STEP=1
MERIT_OFFSET=0

SHIFTS=()
CTR_PRIMES=""
CTR_BITS=""
CTR_RANGE="${CTR_RANGE:-0}"
CTR_STRENGTH="${CTR_STRENGTH:-10000}"
CTR_IVS="${CTR_IVS:-10000}"
CTR_FIXED=""
FITNESS_MODE="${FITNESS_MODE:-candidate}"
PHASE3=1
PHASE3_DELTA="${PHASE3_DELTA:-2}"
PHASE3_MEAN_EPS="${PHASE3_MEAN_EPS:-0.0005}"
OVERWRITE=0
DRY_RUN=0
KEEP_GOING=0

usage() {
  cat <<'EOF'
Usage: scripts/gen_crt_series.sh [options]

Options:
  --shift N               Add one shift to generate (repeatable)
  --shifts A,B,C          Comma-separated list of shifts
  --merit-start N         First merit label (default: 30)
  --merit-end N           Last merit label (default: 40)
  --merit-step N          Merit step (default: 1)
  --merit-offset N        Offset added to ctr-merit (default: 0; use -1 if desired)
  --ctr-primes N          Override CRT prime count for all shifts
  --ctr-bits N            Override CRT bits for all shifts
  --ctr-fixed N           Override fixed-prime count for all shifts
  --ctr-range N           Pass through to gen_crt (default: 0)
  --ctr-strength N        Greedy restarts (default: 10000)
  --ctr-ivs N             Evolution population (default: 1000)
  --fitness-mode MODE     candidate|probability (default: probability)
  --phase3 / --no-phase3  Enable or disable phase3 (default: on)
  --phase3-delta N        Phase3 delta (default: 2)
  --phase3-mean-eps E     Phase3 mean epsilon (default: 0.0005)
  --out-dir DIR           Output directory for CRT files (default: crt)
  --log-dir DIR           Log directory (default: logs/crt_series)
  --overwrite             Replace existing outputs
  --dry-run               Print commands only, do not run gen_crt
  --keep-going            Continue after a failed gen_crt run
  -h, --help              Show this help

Defaults are tuned for CRT-only high-merit work at shifts 450+.
EOF
}

default_ctr_primes_for_shift() {
  case "$1" in
    450) echo 68 ;;
    512) echo 75 ;;
    768) echo 104 ;;
    1001) echo 129 ;;
    *) return 1 ;;
  esac
}

default_ctr_bits_for_shift() {
  case "$1" in
    450) echo 0 ;;
    512) echo 2 ;;
    768) echo 1 ;;
    1001) echo 1 ;;
    *) return 1 ;;
  esac
}

default_ctr_fixed_for_primes() {
  local n="$1"
  if (( n <= 23 )); then
    echo 8
  elif (( n <= 33 )); then
    echo 10
  elif (( n <= 49 )); then
    echo 11
  elif (( n <= 73 )); then
    echo 12
  elif (( n <= 95 )); then
    echo 13
  elif (( n <= 118 )); then
    echo 14
  else
    echo 15
  fi
}

make_shift_list_from_csv() {
  local csv="$1"
  local cleaned="${csv// /}"
  IFS=',' read -r -a parts <<< "$cleaned"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] && SHIFTS+=("$part")
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shift)
      [[ $# -ge 2 ]] || { echo "error: --shift needs a value" >&2; exit 2; }
      SHIFTS+=("$2")
      shift 2
      ;;
    --shifts)
      [[ $# -ge 2 ]] || { echo "error: --shifts needs a value" >&2; exit 2; }
      make_shift_list_from_csv "$2"
      shift 2
      ;;
    --merit-start)
      [[ $# -ge 2 ]] || { echo "error: --merit-start needs a value" >&2; exit 2; }
      MERIT_START="$2"
      shift 2
      ;;
    --merit-end)
      [[ $# -ge 2 ]] || { echo "error: --merit-end needs a value" >&2; exit 2; }
      MERIT_END="$2"
      shift 2
      ;;
    --merit-step)
      [[ $# -ge 2 ]] || { echo "error: --merit-step needs a value" >&2; exit 2; }
      MERIT_STEP="$2"
      shift 2
      ;;
    --merit-offset)
      [[ $# -ge 2 ]] || { echo "error: --merit-offset needs a value" >&2; exit 2; }
      MERIT_OFFSET="$2"
      shift 2
      ;;
    --ctr-primes)
      [[ $# -ge 2 ]] || { echo "error: --ctr-primes needs a value" >&2; exit 2; }
      CTR_PRIMES="$2"
      shift 2
      ;;
    --ctr-bits)
      [[ $# -ge 2 ]] || { echo "error: --ctr-bits needs a value" >&2; exit 2; }
      CTR_BITS="$2"
      shift 2
      ;;
    --ctr-fixed)
      [[ $# -ge 2 ]] || { echo "error: --ctr-fixed needs a value" >&2; exit 2; }
      CTR_FIXED="$2"
      shift 2
      ;;
    --ctr-range)
      [[ $# -ge 2 ]] || { echo "error: --ctr-range needs a value" >&2; exit 2; }
      CTR_RANGE="$2"
      shift 2
      ;;
    --ctr-strength)
      [[ $# -ge 2 ]] || { echo "error: --ctr-strength needs a value" >&2; exit 2; }
      CTR_STRENGTH="$2"
      shift 2
      ;;
    --ctr-ivs)
      [[ $# -ge 2 ]] || { echo "error: --ctr-ivs needs a value" >&2; exit 2; }
      CTR_IVS="$2"
      shift 2
      ;;
    --fitness-mode)
      [[ $# -ge 2 ]] || { echo "error: --fitness-mode needs a value" >&2; exit 2; }
      FITNESS_MODE="$2"
      shift 2
      ;;
    --phase3)
      PHASE3=1
      shift
      ;;
    --no-phase3)
      PHASE3=0
      shift
      ;;
    --phase3-delta)
      [[ $# -ge 2 ]] || { echo "error: --phase3-delta needs a value" >&2; exit 2; }
      PHASE3_DELTA="$2"
      shift 2
      ;;
    --phase3-mean-eps)
      [[ $# -ge 2 ]] || { echo "error: --phase3-mean-eps needs a value" >&2; exit 2; }
      PHASE3_MEAN_EPS="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || { echo "error: --out-dir needs a value" >&2; exit 2; }
      OUT_DIR="$2"
      shift 2
      ;;
    --log-dir)
      [[ $# -ge 2 ]] || { echo "error: --log-dir needs a value" >&2; exit 2; }
      LOG_DIR="$2"
      shift 2
      ;;
    --overwrite)
      OVERWRITE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --keep-going)
      KEEP_GOING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${#SHIFTS[@]} -eq 0 ]]; then
  SHIFTS=(450 512 768 1001)
fi

if [[ "$DRY_RUN" -eq 0 && ! -x "$GEN_CRT_BIN" ]]; then
  echo "error: missing executable $GEN_CRT_BIN" >&2
  echo "hint: build it first with: make gen_crt" >&2
  exit 1
fi

mkdir -p "$OUT_DIR" "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="$LOG_DIR/$TS"
mkdir -p "$RUN_DIR"

summary_file="$RUN_DIR/summary.tsv"
printf "shift\tmerit\tctr_merit\tctr_primes\tctr_bits\tctr_fixed\tstatus\tout_file\tlog_file\n" > "$summary_file"

echo "CRT series output dir: $OUT_DIR"
echo "CRT series log dir: $RUN_DIR"
echo "merit range: ${MERIT_START}..${MERIT_END} step ${MERIT_STEP}"
echo "default fitness: ${FITNESS_MODE}"
if [[ "$PHASE3" -eq 1 ]]; then
  echo "phase3: on"
else
  echo "phase3: off"
fi

for shift in "${SHIFTS[@]}"; do
  shift_ctr_primes="$CTR_PRIMES"
  shift_ctr_bits="$CTR_BITS"
  if [[ -z "$shift_ctr_primes" ]]; then
    if ! shift_ctr_primes="$(default_ctr_primes_for_shift "$shift")"; then
      echo "error: no default ctr-primes for shift $shift; pass --ctr-primes" >&2
      exit 2
    fi
  fi
  if [[ -z "$shift_ctr_bits" ]]; then
    if ! shift_ctr_bits="$(default_ctr_bits_for_shift "$shift")"; then
      echo "error: no default ctr-bits for shift $shift; pass --ctr-bits" >&2
      exit 2
    fi
  fi

  shift_ctr_fixed="$CTR_FIXED"
  if [[ -z "$shift_ctr_fixed" ]]; then
    shift_ctr_fixed="$(default_ctr_fixed_for_primes "$shift_ctr_primes")"
  fi

  merit="$MERIT_START"
  while (( merit <= MERIT_END )); do
    ctr_merit=$(( merit + MERIT_OFFSET ))
    if (( ctr_merit <= 0 )); then
      echo "error: computed ctr-merit <= 0 for shift $shift merit $merit" >&2
      exit 2
    fi

    out_file="$OUT_DIR/crt_s${shift}_m${merit}"
    if [[ "$PHASE3" -eq 1 ]]; then
      out_file+="_phase3"
    fi
    out_file+=".txt"
    log_file="$RUN_DIR/shift${shift}_m${merit}.log"

    if [[ -e "$out_file" && "$OVERWRITE" -eq 0 ]]; then
      echo "skip existing: $out_file"
      printf "%s\t%s\t%s\t%s\t%s\t%s\tSKIP\t%s\t%s\n" \
        "$shift" "$merit" "$ctr_merit" "$shift_ctr_primes" "$shift_ctr_bits" "$shift_ctr_fixed" \
        "$out_file" "$log_file" >> "$summary_file"
      merit=$(( merit + MERIT_STEP ))
      continue
    fi

    cmd=(
      "$GEN_CRT_BIN"
      --calc-ctr
      --ctr-primes "$shift_ctr_primes"
      --ctr-merit "$ctr_merit"
      --ctr-bits "$shift_ctr_bits"
      --ctr-strength "$CTR_STRENGTH"
      --ctr-evolution
      --ctr-fixed "$shift_ctr_fixed"
      --ctr-ivs "$CTR_IVS"
      --ctr-file "$out_file"
    )

    if [[ -n "$CTR_RANGE" && "$CTR_RANGE" != "0" ]]; then
      cmd+=(--ctr-range "$CTR_RANGE")
    fi
    if [[ -n "$FITNESS_MODE" ]]; then
      cmd+=(--fitness-mode "$FITNESS_MODE")
    fi
    if [[ "$PHASE3" -eq 1 ]]; then
      cmd+=(--phase3 --phase3-delta "$PHASE3_DELTA" --phase3-mean-eps "$PHASE3_MEAN_EPS")
    fi

    echo
    echo "== shift=$shift merit=$merit ctr-merit=$ctr_merit =="
    printf 'cmd:'
    printf ' %q' "${cmd[@]}"
    echo

    if [[ "$DRY_RUN" -eq 1 ]]; then
      printf "%s\t%s\t%s\t%s\t%s\t%s\tDRY-RUN\t%s\t%s\n" \
        "$shift" "$merit" "$ctr_merit" "$shift_ctr_primes" "$shift_ctr_bits" "$shift_ctr_fixed" \
        "$out_file" "$log_file" >> "$summary_file"
    else
      set +e
      "${cmd[@]}" >"$log_file" 2>&1
      rc=$?
      set -e
      if [[ $rc -eq 0 ]]; then
        status="OK"
      else
        status="FAIL($rc)"
        echo "error: gen_crt failed for shift=$shift merit=$merit (rc=$rc); log=$log_file" >&2
        if [[ "$KEEP_GOING" -eq 0 ]]; then
          printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$shift" "$merit" "$ctr_merit" "$shift_ctr_primes" "$shift_ctr_bits" "$shift_ctr_fixed" \
            "$status" "$out_file" "$log_file" >> "$summary_file"
          exit "$rc"
        fi
      fi
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$shift" "$merit" "$ctr_merit" "$shift_ctr_primes" "$shift_ctr_bits" "$shift_ctr_fixed" \
        "$status" "$out_file" "$log_file" >> "$summary_file"
    fi

    merit=$(( merit + MERIT_STEP ))
  done
done

echo
echo "summary: $summary_file"
if command -v column >/dev/null 2>&1; then
  column -t -s $'\t' "$summary_file"
else
  cat "$summary_file"
fi