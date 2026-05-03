#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN="$DIR/bin/maxgap_scan"
OUTDIR="$DIR/bin"
SPEED_LOG="$OUTDIR/maxgap_speed.log"
START=18000000000000000000
SLICE=8400000000000
THREADS=7
MONITOR_SEC=30

mkdir -p "$OUTDIR"
: > "$SPEED_LOG"

log_speed() {
    msg="$1"
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    printf "%s %s\n" "$ts" "$msg" >> "$SPEED_LOG"
    printf "%s\n" "$msg" >&2
}

if [ ! -x "$SCAN" ] && [ -x "$DIR/maxgap_scan" ]; then
    SCAN="$DIR/maxgap_scan"
fi

START_TS=$(date +%s)
declare -a PIDS
declare -a STARTS
declare -a SPANS
declare -a DONE
DONE_POS=0
TOTAL_POS=0

for i in $(seq 0 $((THREADS - 1))); do
    S=$(python3 -c "print($START + $i * $SLICE)")
    E=$(python3 -c "print($START + ($i + 1) * $SLICE)")
    SPAN=$((E - S))
    STARTS[$i]=$S
    SPANS[$i]=$SPAN
    TOTAL_POS=$((TOTAL_POS + SPAN))
    DONE[$i]=0

    "$SCAN" \
        --start $S --end $E \
        --mingap 1600 --skip 700 --threshold 70 \
        --dual-pass \
        --checkpoint "$OUTDIR/ckpt_${i}.txt" \
        --progress 30 \
        > "$OUTDIR/gaps_${i}.txt" 2> "$OUTDIR/prog_${i}.log" &
    PIDS[$i]=$!
    echo "worker $i: $S .. $E  (pid $!)"
done

while :; do
    ALIVE=0
    FINISHED=0
    EST_DONE_POS=0
    for i in $(seq 0 $((THREADS - 1))); do
        pid=${PIDS[$i]}
        worker_start=${STARTS[$i]}
        worker_span=${SPANS[$i]}
        ckpt_file="$OUTDIR/ckpt_${i}.txt"

        if kill -0 "$pid" 2>/dev/null; then
            ALIVE=$((ALIVE + 1))

            # Estimate in-progress work from checkpoint current_p when available.
            worker_done=0
            if [ -f "$ckpt_file" ]; then
                current_p=$(awk '/^current_p[[:space:]]+/ {print $2; exit}' "$ckpt_file")
                if [[ "$current_p" =~ ^[0-9]+$ ]]; then
                    worker_done=$((current_p - worker_start))
                    if [ "$worker_done" -lt 0 ]; then
                        worker_done=0
                    elif [ "$worker_done" -gt "$worker_span" ]; then
                        worker_done=$worker_span
                    fi
                fi
            fi
            EST_DONE_POS=$((EST_DONE_POS + worker_done))
        else
            if [ "${DONE[$i]}" -eq 0 ]; then
                DONE[$i]=1
                DONE_POS=$((DONE_POS + SPANS[$i]))
            fi
            FINISHED=$((FINISHED + 1))
            EST_DONE_POS=$((EST_DONE_POS + worker_span))
        fi
    done

    NOW_TS=$(date +%s)
    ELAPSED=$((NOW_TS - START_TS))
    if [ "$ELAPSED" -lt 1 ]; then
        ELAPSED=1
    fi

    RATE_DONE=$(awk -v d="$DONE_POS" -v t="$ELAPSED" 'BEGIN { printf "%.2f", d / t }')
    RATE_EST=$(awk -v d="$EST_DONE_POS" -v t="$ELAPSED" 'BEGIN { printf "%.2f", d / t }')
    log_speed "[speed] finished=${FINISHED}/${THREADS} done=${DONE_POS}/${TOTAL_POS} done_avg=${RATE_DONE} pos/s est=${EST_DONE_POS}/${TOTAL_POS} est_avg=${RATE_EST} pos/s elapsed=${ELAPSED}s"

    if [ "$ALIVE" -eq 0 ]; then
        break
    fi
    sleep "$MONITOR_SEC"
done

FAIL=0
for i in $(seq 0 $((THREADS - 1))); do
    if ! wait "${PIDS[$i]}"; then
        FAIL=1
    fi
done

NOW_TS=$(date +%s)
TOTAL_ELAPSED=$((NOW_TS - START_TS))
if [ "$TOTAL_ELAPSED" -lt 1 ]; then
    TOTAL_ELAPSED=1
fi
FINAL_RATE=$(awk -v d="$TOTAL_POS" -v t="$TOTAL_ELAPSED" 'BEGIN { printf "%.2f", d / t }')
log_speed "[speed] final scanned=${TOTAL_POS} elapsed=${TOTAL_ELAPSED}s avg=${FINAL_RATE} pos/s"

echo "--- done ---"
cat "$OUTDIR"/gaps_*.txt | sort -t '=' -k2 -n

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi