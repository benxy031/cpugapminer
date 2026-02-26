# CRT File Generation Guide

How to generate CRT (Chinese Remainder Theorem) sieve files for
cpugapminer, covering shifts from 64 to 1024.

## Overview

CRT files pre-compute optimal prime offsets so the miner can constrain
which `nAdd` values to test, replacing the normal windowed sieve with
a much smaller set of CRT-aligned candidates.

The `gen_crt` tool uses a two-phase algorithm:

1. **Greedy phase** — assigns each CRT prime an offset that covers the
   most uncovered positions in the target gap range. Repeated many times
   with random tie-breaking (`--ctr-strength`).
2. **Evolutionary phase** — refines the greedy population through
   tournament selection, crossover, mutation, and local-search
   (`--ctr-evolution`).

The output is a text file listing `prime offset` pairs, which the miner
loads via `--crt-file`.

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

Because CRT replaces the sieve, `--sieve-size`, `--sieve-primes`, and
`--sample-stride` have no effect in CRT mode.

## Key Formula

```
min_shift  = ceil( log2(p1 × p2 × … × pN) )    # = ceil(log2(N#))
ctr-bits   = desired_shift - min_shift
gap_target = ceil( merit × (256 + shift) × ln(2) )
```

Where `N#` is the primorial (product of the first N primes).

## Parameter Reference Table

| Shift | Primes | Largest Prime | log2(primorial) | ctr-bits | Gap (m=22) | Gap (m=25) |
|------:|-------:|--------------:|----------------:|---------:|-----------:|-----------:|
|    64 |     15 |            47 |            59.1 |        4 |       4880 |       5546 |
|    96 |     21 |            73 |            95.0 |        0 |       5368 |       6100 |
|   128 |     26 |           101 |           127.5 |        0 |       5856 |       6655 |
|   160 |     30 |           113 |           154.5 |        5 |       6344 |       7209 |
|   192 |     35 |           149 |           189.9 |        2 |       6832 |       7764 |
|   256 |     43 |           191 |           249.2 |        6 |       7808 |       8873 |
|   384 |     60 |           281 |           383.3 |        0 |       9760 |      11091 |
|   512 |     75 |           379 |           509.0 |        2 |      11712 |      13309 |
|   640 |     89 |           461 |           631.2 |        8 |      13664 |      15527 |
|   768 |    104 |           569 |           766.2 |        1 |      15616 |      17745 |
|   896 |    118 |           647 |           895.8 |        0 |      17568 |      19963 |
|  1024 |    131 |           739 |          1018.5 |        5 |      19520 |      22181 |

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
| `--ctr-strength S` | Number of greedy restarts. Higher = better results but slower. 50-200 recommended. |
| `--ctr-evolution` | Enable evolutionary refinement (recommended for quality) |
| `--ctr-fixed F` | Number of small primes frozen during evolution (default: 8). The greedy algorithm already finds near-optimal offsets for small primes. |
| `--ctr-ivs I` | Population size for evolution. More = better but slower. 10-30 recommended. |
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

### Shift 64 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 15 --ctr-merit 22 --ctr-bits 4 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 6 --ctr-ivs 20 \
  --ctr-file crt_s64_m22.txt
```

Expected: ~640 candidates. Run time: seconds.

### Shift 96 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 21 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s96_m22.txt
```

Expected: ~620 candidates.

### Shift 128 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s128_m22.txt
```

Expected: ~610 candidates.

### Shift 160 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 30 --ctr-merit 22 --ctr-bits 5 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s160_m22.txt
```

### Shift 192 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 35 --ctr-merit 22 --ctr-bits 2 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s192_m22.txt
```

### Shift 256 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 43 --ctr-merit 22 --ctr-bits 6 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s256_m22.txt
```

Expected: ~680 candidates.

### Shift 384 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 60 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 10 --ctr-ivs 20 \
  --ctr-file crt_s384_m22.txt
```

Expected: ~750 candidates. Run time: ~30s with evolution.

### Shift 512 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 75 --ctr-merit 22 --ctr-bits 2 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 10 --ctr-ivs 20 \
  --ctr-file crt_s512_m22.txt
```

Expected: ~800 candidates.

### Shift 640 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 89 --ctr-merit 22 --ctr-bits 8 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 12 --ctr-ivs 20 \
  --ctr-file crt_s640_m22.txt
```

### Shift 768 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 104 --ctr-merit 22 --ctr-bits 1 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 12 --ctr-ivs 20 \
  --ctr-file crt_s768_m22.txt
```

### Shift 896 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 118 --ctr-merit 22 --ctr-bits 0 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 14 --ctr-ivs 20 \
  --ctr-file crt_s896_m22.txt
```

### Shift 1024 (merit 22)

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 131 --ctr-merit 22 --ctr-bits 5 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 14 --ctr-ivs 20 \
  --ctr-file crt_s1024_m22.txt
```

## Merit 25 Variants

For higher merit targets (e.g., merit 25), replace `--ctr-merit 22` with
`--ctr-merit 25`. The gap target increases, which generally produces more
candidates. Example:

```bash
./bin/gen_crt --calc-ctr \
  --ctr-primes 26 --ctr-merit 25 --ctr-bits 0 \
  --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \
  --ctr-file crt_s128_m25.txt
```

## Using CRT Files with the Miner

```bash
./bin/gap_miner --shift 128 --crt-file crt_s128_m22.txt \
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

1. **Higher `--ctr-strength`** (200+) gives better greedy solutions but
   takes longer. For production CRT files, use 200.
2. **Always use `--ctr-evolution`** for the best results. The evolutionary
   phase typically shaves 5-15 candidates off the greedy best.
3. **`--ctr-fixed 8`** is a good default. The first 8 primes (2..19) are
   almost always optimally placed by the greedy algorithm.
4. **`--ctr-merit` should be `target_merit - 1`** per original GapMiner
   recommendations. So for mining merit 22 blocks, use `--ctr-merit 21`.
5. **`--ctr-range 10`** explores ±10% prime counts around your target,
   which may find a slightly better solution at a different prime count.
6. **Lower `n_candidates` is better.** The file with the fewest candidates
   gives the miner the most positions it can skip.

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
