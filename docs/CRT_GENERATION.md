# CRT File Generation Guide

How to generate CRT (Chinese Remainder Theorem) sieve files for
cpugapminer, covering shifts from 64 to 1024.

## Overview

CRT files pre-compute optimal prime offsets so the miner can constrain
which `nAdd` values to test, replacing the normal windowed sieve with
a much smaller set of CRT-aligned candidates.

The `gen_crt` tool uses a three-phase algorithm compatible with GapMiner --calc-ctr parameters:

1. **Greedy phase** — assigns each CRT prime an offset that covers the
   most uncovered positions in the target gap range. Repeated many times
   with random tie-breaking (`--ctr-strength`).
2. **Evolutionary phase** — refines the greedy population through
   tournament selection, crossover, mutation, and local-search
   (`--ctr-evolution`).  Includes pair local-search (jointly optimises
   two free primes at once) in 50% of refinement steps.
3. **Iterated Local Search (ILS)** — takes the best solution from phase 2,
   applies full single-prime and pair sweep passes, then repeatedly
   perturbs 3–5 random offsets and re-sweeps.  Typically shaves a further
   5–20 candidates off the evolutionary best.  Runs automatically after
   evolution; no extra flag needed.

The output is a text file listing `prime offset` pairs, which the miner
loads via `--crt-file`.  The header also records `shift`, `gap_target`,
and `n_candidates` for reference.

### How CRT mining works

When a text CRT file is loaded, the miner bypasses the normal sieve loop
entirely. Instead:

1. **CRT alignment** — for each base hash, solve
   `nAdd ≡ -(base + offset_i) (mod prime_i)` for all CRT primes
   simultaneously using the CRT. This yields a unique `nAdd0 (mod primorial)`.
2. **Iterate** — step through `nAdd = nAdd0, nAdd0 + primorial, …` up to
   `adder_max = 2^shift`. At shift 64 / 15 primes (primorial ≈ 2^59),
   this gives only **~15 candidate nAdd values** per hash.
3. **Fermat test** — each `base + nAdd` is tested for primality directly.
4. **Gap check** — for each confirmed prime, a small forward sieve
   (~10 000 positions) finds the next prime to measure the gap.
5. **Submit** — qualifying gaps (merit ≥ target) are submitted via the
   normal block assembly path.

Because CRT replaces the sieve, `--sieve-size` and `--sample-stride`
have no effect in CRT mode. However, `--sieve-primes` **is** used for
the forward gap-check sieve that measures the gap after each confirmed
prime (auto-computed via PNT if not specified).

## Key Formula

```
min_shift  = ceil( log2(p1 × p2 × … × pN) )    # = ceil(log2(N#))
ctr-bits   = desired_shift - min_shift
gap_target = ceil( merit × (256 + shift) × ln(2) )
```

Where `N#` is the primorial (product of the first N primes).

## Parameter Reference Table

| Shift | Primes | Largest Prime | log2(primorial) | ctr-bits | Gap (m=21) | Gap (m=22) | Gap (m=25) |
|------:|-------:|--------------:|----------------:|---------:|-----------:|-----------:|-----------:|
|    26 |      8 |            19 |            23.2 |        2 |       4105 |       4299 |       4887 |
|    37 |     10 |            29 |            32.6 |        4 |       4265 |       4467 |       5074 |
|    64 |     15 |            47 |            59.1 |        4 |       4658 |       4880 |       5546 |
|    68 |     16 |            53 |            64.8 |        3 |       4717 |       4941 |       5615 |
|    96 |     21 |            73 |            95.0 |        0 |       5124 |       5368 |       6100 |
|   110 |     23 |            83 |           107.7 |        2 |       5328 |       5582 |       6343 |
|   128 |     26 |           101 |           127.5 |        0 |       5592 |       5856 |       6655 |
|   133 |     26 |           101 |           127.5 |        5 |       5663 |       5932 |       6741 |
|   160 |     30 |           113 |           154.5 |        5 |       6052 |       6344 |       7209 |
|   192 |     35 |           149 |           189.9 |        2 |       6512 |       6832 |       7764 |
|   256 |     43 |           191 |           249.2 |        6 |       7432 |       7808 |       8873 |
|   384 |     60 |           281 |           383.3 |        0 |       9312 |       9760 |      11091 |
|   512 |     75 |           379 |           509.0 |        2 |      11168 |      11712 |      13309 |
|   640 |     89 |           461 |           631.2 |        8 |      13028 |      13664 |      15527 |
|   720 |     98 |           521 |           711.6 |        8 |      14207 |      14884 |      16913 |
|   768 |    104 |           569 |           766.2 |        1 |      14888 |      15616 |      17745 |
|   896 |    118 |           647 |           895.8 |        0 |      16748 |      17568 |      19963 |
|  1024 |    131 |           739 |          1018.5 |        5 |      18632 |      19520 |      22181 |

**Primes** = maximum CRT primes that fit in the shift.
**ctr-bits** = shift - ceil(log2(primorial)), the leftover bits.
**Gap** = minimum gap length needed for the given merit.

## Parameter Description

| Flag | Description |
|------|-------------|
| `--calc-ctr` | Enable CRT calculation mode (required) |
| `--ctr-primes N` | Number of CRT primes. More primes = better coverage but requires higher shift. Use the table above. |
| `--ctr-merit M` | Target merit. **Tip:** use `target_merit - 1` for best sieving results (per original GapMiner docs) |
| `--ctr-bits B` | Extra bits: `shift - ceil(log2(primorial))`. Use the table above. |
| `--ctr-strength S` | Number of greedy restarts. Higher = better results but slower. Quick test: 100, production: **10 000**. |
| `--ctr-evolution` | Enable evolutionary refinement (recommended for quality) |
| `--ctr-fixed F` | Number of small primes frozen during evolution. Scale with prime count: 8 for ≤23, 10 for 24–33, 11 for 34–49, 12 for 50–73, 13 for 74–95, 14 for 96–118, 15 for 119+. |
| `--ctr-ivs I` | Population size for evolution. Quick test: 20, production: **1 000**. |
| `--ctr-range R` | Percent deviation from `--ctr-primes`. Explores nearby prime counts for potentially better results. |
| `--ctr-file FILE` | Output file path (required) |

## How to Calculate ctr-bits

The shift you intend to mine with must be ≥ ceil(log2(primorial)).
The `ctr-bits` parameter is the difference:

```
ctr-bits = shift - ceil(log2(p1 × p2 × ... × pN))
```

### Example: shift 384 with 58 primes

Using Python:
```python
from sympy import primorial
from math import log2, ceil
ceil(log2(primorial(58)))   # 58th prime = 271
# = 368
# ctr-bits = 384 - 368 = 16
```

Or read it from the table: shift 384 → 60 max primes, log2 ≈ 383.3.
With 58 primes: log2(58#) ≈ 367.1, so ctr-bits = 384 - 368 = 16.

## Ready-to-Use Commands

### Shift 26 (merit 21)

Filename convention: `crt_s25_m21.txt` (shift is 26 due to ceil rounding).

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 8 --ctr-merit 21 --ctr-bits 2 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s25_m21.txt
```

Expected: ~690 candidates.

### Shift 37 (merit 21)

Filename convention: `crt_s34_m21.txt` (shift is 37 due to ceil rounding).

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 10 --ctr-merit 21 --ctr-bits 4 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s34_m21.txt
```

Expected: ~655 candidates.

### Shift 64 (merit 21)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 15 --ctr-merit 21 --ctr-bits 4 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s64_m21.txt
```

Expected: ~610 candidates.

### Shift 64 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 15 --ctr-merit 22 --ctr-bits 4 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s64_m22.txt
```

Expected: ~640 candidates.

### Shift 68 (merit 22–30)

16 primes fit in shift 68 (log₂(16#) ≈ 64.8, ctr-bits=3).

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 16 --ctr-merit 22 --ctr-bits 3 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s68_m22.txt
```

Expected: ~630 candidates.  For other merit targets, replace `--ctr-merit`:

| Merit | `--ctr-merit` | Expected candidates |
|------:|:-------------:|--------------------:|
|    22 | 22            | ~630                |
|    24 | 24            | ~692                |
|    26 | 26            | ~754                |
|    28 | 28            | ~813                |
|    30 | 30            | ~873                |

### Shift 96 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 21 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s96_m22.txt
```

Expected: ~620 candidates.

### Shift 110 (merit 21)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 23 --ctr-merit 21 --ctr-bits 2 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 8 --ctr-ivs 1000 \
  --ctr-file crt/crt_s110_m21.txt
```

Expected: ~587 candidates.

### Shift 128 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 10 --ctr-ivs 1000 \
  --ctr-file crt/crt_s128_m22.txt
```

Expected: ~610 candidates.

### Shift 133 (merit 30)

Same 26 primes as shift 128, but with ctr-bits=5 to reach shift 133.

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 30 --ctr-bits 5 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 10 --ctr-ivs 1000 \
  --ctr-file crt/crt_s133_m30.txt
```

Expected: ~871 candidates.

### Shift 160 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 30 --ctr-merit 22 --ctr-bits 5 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 10 --ctr-ivs 1000 \
  --ctr-file crt/crt_s160_m22.txt
```

### Shift 192 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 35 --ctr-merit 22 --ctr-bits 2 \
  --ctr-strength 10000 --crt-evolution --ctr-fixed 11 --ctr-ivs 1000 \
  --ctr-file crt/crt_s192_m22.txt
```

### Shift 256 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 43 --ctr-merit 22 --ctr-bits 6 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 11 --ctr-ivs 1000 \
  --ctr-file crt/crt_s256_m22.txt
```

Expected: ~680 candidates.

### Shift 384 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 60 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 12 --ctr-ivs 1000 \
  --ctr-file crt/crt_s384_m22.txt
```

Expected: ~750 candidates.

### Shift 512 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 75 --ctr-merit 22 --ctr-bits 2 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 13 --ctr-ivs 1000 \
  --ctr-file crt/crt_s512_m22.txt
```

Expected: ~800 candidates.

### Shift 640 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 89 --ctr-merit 22 --ctr-bits 8 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 13 --ctr-ivs 1000 \
  --ctr-file crt/crt_s640_m22.txt
```

### Shift 720 (merit 21)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 98 --ctr-merit 21 --ctr-bits 8 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 13 --ctr-ivs 1000 \
  --ctr-file crt/crt_s720_m21.txt
```

Expected: ~889 candidates.

### Shift 768 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 104 --ctr-merit 22 --ctr-bits 1 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 14 --ctr-ivs 1000 \
  --ctr-file crt/crt_s768_m22.txt
```

### Shift 896 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 118 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 14 --ctr-ivs 1000 \
  --ctr-file crt/crt_s896_m22.txt
```

### Shift 1024 (merit 21)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 131 --ctr-merit 21 --ctr-bits 5 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 15 --ctr-ivs 1000 \
  --ctr-file crt/crt_s1024_m21.txt
```

Expected: ~1027 candidates.

### Shift 1024 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 131 --ctr-merit 22 --ctr-bits 5 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 15 --ctr-ivs 1000 \
  --ctr-file crt/crt_s1024_m22.txt
```

## Merit Variants

For different merit targets, replace `--ctr-merit` with the desired value.
The gap target increases with merit, producing more candidates.  Example
for shift 128, merit 25:

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 25 --ctr-bits 0 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 10 --ctr-ivs 1000 \
  --ctr-file crt/crt_s128_m25.txt
```

Shift 133, merit 30 (26 primes, ctr-bits=5):

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 30 --ctr-bits 5 \
  --ctr-strength 10000 --ctr-evolution --ctr-fixed 10 --ctr-ivs 1000 \
  --ctr-file crt/crt_s133_m30.txt
```

## Using CRT Files with the Miner

```bash
./bin/gap_miner --shift 128 --crt-file crt/crt_s128_m22.txt \
  --rpc-url http://127.0.0.1:31397 \
  --rpc-user user --rpc-pass pass \
  --threads 14 --fast-fermat
```

The miner auto-detects the file format (binary template vs text
gap-solver). When a text CRT file is loaded, the miner enters
CRT-aligned mining mode — the normal sieve is bypassed entirely,
so `--sieve-size`, `--sieve-primes`, and `--sample-stride` are
ignored and do not need to be specified.

## Tips for Quality

1. **Higher `--ctr-strength`** gives better greedy solutions.
   Production CRT files should use **10 000** (per wizz's reference batch).
   Quick tests can use 100-200.
2. **Always use `--ctr-evolution`** for the best results. The evolutionary
   phase typically shaves 5-15 candidates off the greedy best.
3. **Scale `--ctr-fixed` with prime count:** 8 for ≤23 primes, 10 for
   24-33, 11 for 34-49, 12 for 50-73, 13 for 74-95, 14 for 96-118,
   15 for 119+. Small primes are almost always optimally placed by greedy.
   Note: the Phase 3 ILS also respects `--ctr-fixed` — frozen primes are
   never perturbed during ILS.
4. **`--ctr-ivs 1000`** for production, 20 for quick tests.
5. **`--ctr-merit` should be `target_merit - 1`** per original GapMiner
   recommendations. So for mining merit 22 blocks, use `--ctr-merit 21`.
   At higher shifts (≥384), `target_merit - 2` is viable and often better:
   the gap range is larger, so a slightly looser coverage still captures
   most qualifying gaps while keeping `n_candidates` lower.
6. **`--ctr-range 10`** explores ±10% prime counts around your target,
   which may find a slightly better solution at a different prime count.
7. **Lower `n_candidates` is better.** The file with the fewest candidates
   gives the miner the most positions it can skip.
8. **CRT becomes increasingly efficient relative to windowed sieve at higher
   shifts.** In CRT mode, total Fermat tests per hash ≈ `n_candidates × 2^ctr_bits`,
   which stays roughly constant regardless of shift. In windowed sieve mode,
   tests per hash scale as `2^shift / ln(base)` — exponential in shift. Above
   shift ~128 the windowed sieve is simply impractical; CRT is the only
   viable mode for shift 256 and beyond.

## Computing log2(primorial) with Python

```python
from math import log2

# First N primes
def nth_prime(n):
    """Return the first n primes."""
    primes = []
    candidate = 2
    while len(primes) < n:
        if all(candidate % p != 0 for p in primes):
            primes.append(candidate)
        candidate += 1
    return primes

def primorial_log2(n):
    """log2 of product of first n primes."""
    return sum(log2(p) for p in nth_prime(n))

# Examples
print(f"14 primes: log2 = {primorial_log2(14):.1f}")  # 53.5
print(f"24 primes: log2 = {primorial_log2(24):.1f}")  # 114.2
print(f"58 primes: log2 = {primorial_log2(58):.1f}")  # 367.1
```

## Build

```bash
make gen_crt
```
