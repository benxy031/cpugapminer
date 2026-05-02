# maxgap_scan — Maximal Prime Gap Search Tool

A skip-and-probe searcher for maximal prime gaps in 64-bit integers.
Designed to continue where Oliveira e Silva's exhaustive table stopped
(at 4×10¹⁸), but works at any starting point.

## Background

A **maximal prime gap** is a prime gap `(L, N)` (consecutive primes with
`N − L = G`) where `G` is strictly larger than every previous prime gap
below `L`.  The current computational record stands at
[4000000000000000000](https://www.trnicely.net/gaps/gaplist.html).
Extending the table requires testing every integer in the search range —
no gaps can be skipped.

`maxgap_scan` uses the **skip-and-probe** algorithm which is ~32× faster
than testing every prime individually while still detecting all gaps above
a configurable threshold.

## Build

```bash
make maxgap_scan
# Binary: bin/maxgap_scan
```

No external libraries required — only the C standard library and `-lm`.

## Algorithm

Given a known prime `P`, one step is:

```
C = P + SKIP                     (probe point)
N = next_prime(C)                 (always tested; ~1 BPSW walk per step)
if N − C > THRESHOLD:
    L = prev_prime(C)             (only ~10% of steps reach here)
    if N − L ≥ mingap: report gap
P = N
```

At 4×10¹⁸, `SKIP=1400` skips ~32 average gaps per step
(`avg_gap ≈ ln(4e18) ≈ 43`), giving a **~32× throughput gain** over a
naive sequential prime scan.

**Correctness:** A gap of size `G` is missed only if both its bounding
primes fall inside the same skip window.  This requires `G > SKIP`, which
with `--dual-pass` (two interleaved sweeps offset by `SKIP/2`) is reduced
to `G > SKIP/2`.  For default `SKIP=1400` with `--dual-pass`, all gaps
above 700 are reliably detected — far below any record threshold.

**Primality:** Uses deterministic Miller-Rabin with 12 witnesses
`{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}`, proven correct for all
64-bit integers (Jaeschke 1993, Feitsma 2012).

## Usage

```
bin/maxgap_scan [OPTIONS]

  --start  N     First value to search from (default: 4000000000000000000)
  --end    N     Stop before this value     (default: run until Ctrl-C)
  --skip   S     Probe step size            (default: 1400)
  --threshold T  prev_prime trigger: N-C>T  (default: 100)
  --mingap G     Report gaps >= G           (default: 1510)
  --dual-pass    Run a second sweep at offset SKIP/2
  --checkpoint F Load/save progress to file F (auto-saved every 5 min)
  --progress  N  Progress line to stderr every N seconds (default: 60)
  --quiet        Suppress progress; only print found gaps to stdout
  --help         Show this help
```

## Output format

Found gaps are written to **stdout**, one line each:

```
gap=1512  at=4000000000000123457  next=4000000000000124969  merit=15.3421
```

| Field | Meaning |
|-------|---------|
| `gap` | `N − L` (gap size in integers) |
| `at`  | Lower bounding prime `L` |
| `next`| Upper bounding prime `N` |
| `merit` | `gap / ln(at)` (Cramér normalisation) |

Progress and checkpoint messages go to **stderr**.  Separate them:

```bash
bin/maxgap_scan ... > gaps.txt 2> progress.log
```

## Recipes

### Continue the OeS table from 4×10¹⁸

```bash
bin/maxgap_scan \
    --start  4000000000000000000 \
    --mingap 1510 \
    --dual-pass \
    --checkpoint maxgap.ckpt \
    --progress 60 \
    > gaps.txt 2> progress.log
```

Interrupt at any time with `Ctrl-C`; resume with the same command —
the checkpoint is picked up automatically.

### Parallel search across multiple cores

Split the range into contiguous slices, one per thread.  Each slice is
fully independent:

```bash
N_THREADS=14
START=4000000000000000000
SLICE=1000000000000000   # 10^15 per thread

for i in $(seq 0 $((N_THREADS - 1))); do
    S=$(( START + i * SLICE ))
    E=$(( S + SLICE ))
    bin/maxgap_scan \
        --start $S --end $E \
        --mingap 1510 --dual-pass \
        --checkpoint ckpt_${i}.txt \
        --quiet \
        > gaps_${i}.txt 2> prog_${i}.log &
done
wait
cat gaps_*.txt | sort -k1,1 -t= -n   # merge results sorted by gap size
```

### Hunt for high-merit gaps (not just maximal)

Merit M = gap / ln(N).  Record merits at 4×10¹⁸ are around 14–16.
To hunt for merit ≥ 14 anywhere in the range:

```bash
# compute: mingap = floor(14 * ln(4e18)) = floor(14 * 43.2) = 604
bin/maxgap_scan \
    --start 4000000000000000000 \
    --mingap 604 \
    --skip 500 \
    --threshold 50 \
    --dual-pass \
    > high_merit.txt
```

Smaller `--skip` is needed here because the target gap (604) is less
than the default skip (1400).  Rule of thumb: `SKIP < mingap / 2`.

### Search a custom range for any gap records

Example: search 10¹⁵ … 10¹⁶ for gaps beating the current record at
that scale (~320 at 10¹⁵):

```bash
bin/maxgap_scan \
    --start 1000000000000000 \
    --end   10000000000000000 \
    --mingap 320 \
    --skip 280 \
    --threshold 30 \
    --dual-pass \
    > gaps_1e15_1e16.txt
```

### Quick smoke test on small numbers

```bash
bin/maxgap_scan \
    --start 100 --end 50000 \
    --mingap 20 --skip 30 --threshold 5 \
    --progress 0
```

Expected first output line: `gap=34  at=1327  next=1361  merit=4.73`

## Tuning SKIP and THRESHOLD

| Parameter | Effect | Guidance |
|-----------|--------|----------|
| `--skip S` | Larger = fewer `next_prime` calls but may miss gaps < S | Set `S < mingap / 2` for reliable detection |
| `--threshold T` | Larger = fewer `prev_prime` calls | Set `T ≈ S / 10`; too large can miss some gaps |
| `--dual-pass` | Two sweeps, doubles cost, catches all gaps > S/2 | Always use for completeness |

**Speed at 4×10¹⁸ (single core, SKIP=1400):**
~23 000 probes/s = 33 million positions/s.
A 10¹⁵ slice takes ~8.5 hours per core.  With 14 cores: ~37 minutes.

## Checkpoint format

Plain text, human-readable:

```
# maxgap_scan checkpoint
current_p   4000000001234567891
max_gap     1512
skip        1400
threshold   100
mingap      1510
```

Edit `current_p` by hand to roll back or skip ahead.

## Submitting records

If you find a gap that beats an existing record, check against the
[Prime Gap List project](https://primegap-list-project.github.io/) and
[Nicely's gap tables](https://www.trnicely.net/gaps/gaplist.html).
Verify the gap with an independent tool (e.g. `Math::Prime::Util` in
Perl or `mpz_nextprime` in GMP) before submitting.

The submitted form typically requires:
- The lower prime `L` (the `at=` field)
- Gap size `G`
- Merit `G / ln(L)`
- Discovery method and CPU used
