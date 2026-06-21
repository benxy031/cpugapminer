# gen_crt_exhaust — Exhaustive / Random-Restart CRT Offset Finder

An alternative to `gen_crt` for generating CRT sieve files.  Ported from
`primeinterval.cpp` by **ATH** (original author), using either **exhaustive
enumeration** (small prime counts) or **random restart** (large prime counts),
both with an incremental sieve that only rebuilds the layers that changed.

## When to use instead of gen_crt

| Situation | Use |
|-----------|-----|
| Small shift (64–128), few primes (≤ 7) | `gen_crt_exhaust` — finds the **exact global minimum** |
| Large shift (256+), many primes | `gen_crt` — greedy+evolution is faster at finding good solutions |
| No GMP available | `gen_crt` — `gen_crt_exhaust` requires libgmp for CRT output |
| Want to verify gen_crt output | `gen_crt_exhaust` — exhaustive result is the ground truth |

## Build

```bash
make gen_crt_exhaust
# Binary: bin/gen_crt_exhaust
```

## Usage

```
gen_crt_exhaust --ctr-primes N --ctr-merit M [--ctr-bits B]
                [--ctr-file FILE] [--ctr-exhaust] [--ctr-random]
                [--phase3] [--phase3-delta N] [--phase3-mean-eps E]

  --ctr-primes N   Number of CRT primes (1..40).  Primes used: 3,5,7,...
  --ctr-merit  M   Target merit (gap_size = ceil(M × (256+bits) × ln2)).
  --ctr-bits   B   Shift parameter in bits (default: 1024).
  --ctr-file   F   Output file (default: crt_exhaust.txt).
  --ctr-exhaust    Force exhaustive even for large n_primes (slow).
  --ctr-random     Force random even for small n_primes.
    --phase3         Enable feature-gated hybrid production selection (default: off).
    --phase3-delta N Candidate tolerance window for phase3 (default: 2).
    --phase3-mean-eps E  Minimum phase1 mean improvement (default: 0.0005).
```

**Automatic mode selection:**
- `n_primes ≤ 7` → exhaustive (exact minimum, fast)
- `n_primes > 7` → random restart (run until Ctrl-C, saves every new min)

The output file is **overwritten** each time a new minimum is found, so the
file always holds exactly one solution — the best found so far.  This makes
it directly loadable by the miner with `--crt-file`.

When `--phase3` is enabled, the selected production best may differ from the
absolute minimum candidate-count solution, but only inside a conservative
window (`min_candidates + phase3-delta`). Outside that window, candidate-count
minimum still wins.

**Note on n_primes:** The file's `n_primes` header is N+1 (includes prime 2
as the first entry `2 1`).  This is required by the miner to set `adj=1` in
the CRT alignment, which is the correct parity for gen_crt_exhaust's
odd-only sieve convention.

## Key difference from gen_crt

`gen_crt_exhaust` uses **incremental sieve evaluation**: the sieve is built
as N stacked layers `buf[0..n_primes-1]`.  When the odometer counter
increments prime `k`, only layers `k..n_primes-1` are rebuilt.  For the
innermost prime (most frequent change), this is O(interval / p_last) instead
of O(n × interval), giving ~10–30× speedup over a naive full re-evaluation.

## Phase Reporting and Selection

`gen_crt_exhaust` reports:

1. **Minimum candidates** observed (`min=...`) during search.
2. **Phase 1 diagnostics** for the selected production best.
3. **Phase 2 shadow** (`phase2(shadow)`) as a comparison-only tracker by
    phase1 kernel quality.

The phase1 kernel is:

```
exp(-a * |x/scale|^b)
```

with defaults `a=5.8`, `b=3.3`.

Selection rules:
- Default (`--phase3` off): production best = strict minimum `n_candidates`.
- With `--phase3`: hybrid ranking uses phase1 score inside `delta`, while
    preserving a hard guard so selected best never exceeds
    `min_candidates + phase3-delta`.

---

## Sample commands — all common shifts

Replace `--ctr-file` with your desired output path.

### shift 25  (log2(primorial) ≈ 23.2 with 7 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 7 --ctr-merit 21 --ctr-bits 25 \
    --ctr-file crt/crt_s25_m21_exhaust.txt
# Exhaustive: 2×4×6×10×12×16×18 = ~13.4M combos; use --ctr-random for speed
# Random restart is faster here:
bin/gen_crt_exhaust \
    --ctr-primes 7 --ctr-merit 21 --ctr-bits 25 --ctr-random \
    --ctr-file crt/crt_s25_m21_exhaust.txt
```

### shift 34  (log2(primorial) ≈ 32.6 with 9 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 9 --ctr-merit 21 --ctr-bits 34 --ctr-random \
    --ctr-file crt/crt_s34_m21_exhaust.txt
```

### shift 64  (log2(primorial) ≈ 59.1 with 14 primes)

```bash
# merit 21
bin/gen_crt_exhaust \
    --ctr-primes 14 --ctr-merit 21 --ctr-bits 64 --ctr-random \
    --ctr-file crt/crt_s64_m21_exhaust.txt

# merit 22
bin/gen_crt_exhaust \
    --ctr-primes 14 --ctr-merit 22 --ctr-bits 64 --ctr-random \
    --ctr-file crt/crt_s64_m22_exhaust.txt

# merit 22, phase3 enabled (A/B testing only)
bin/gen_crt_exhaust \
    --ctr-primes 14 --ctr-merit 22 --ctr-bits 64 --ctr-random \
    --phase3 --phase3-delta 2 --phase3-mean-eps 0.0005 \
    --ctr-file crt/crt_s64_m22_exhaust_phase3.txt
```

### shift 68  (log2(primorial) ≈ 64.8 with 15 primes)

```bash
# merit 22
bin/gen_crt_exhaust \
    --ctr-primes 15 --ctr-merit 22 --ctr-bits 68 --ctr-random \
    --ctr-file crt/crt_s68_m22_exhaust.txt

# merit 24
bin/gen_crt_exhaust \
    --ctr-primes 15 --ctr-merit 24 --ctr-bits 68 --ctr-random \
    --ctr-file crt/crt_s68_m24_exhaust.txt

# merit 26
bin/gen_crt_exhaust \
    --ctr-primes 15 --ctr-merit 26 --ctr-bits 68 --ctr-random \
    --ctr-file crt/crt_s68_m26_exhaust.txt

# merit 28
bin/gen_crt_exhaust \
    --ctr-primes 15 --ctr-merit 28 --ctr-bits 68 --ctr-random \
    --ctr-file crt/crt_s68_m28_exhaust.txt

# merit 30
bin/gen_crt_exhaust \
    --ctr-primes 15 --ctr-merit 30 --ctr-bits 68 --ctr-random \
    --ctr-file crt/crt_s68_m30_exhaust.txt
```

### shift 96  (log2(primorial) ≈ 95.0 with 20 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 20 --ctr-merit 22 --ctr-bits 96 --ctr-random \
    --ctr-file crt/crt_s96_m22_exhaust.txt
```

### shift 110  (log2(primorial) ≈ 107.7 with 22 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 22 --ctr-merit 21 --ctr-bits 110 --ctr-random \
    --ctr-file crt/crt_s110_m21_exhaust.txt
```

### shift 128  (log2(primorial) ≈ 127.5 with 25 primes)

```bash
# merit 22
bin/gen_crt_exhaust \
    --ctr-primes 25 --ctr-merit 22 --ctr-bits 128 --ctr-random \
    --ctr-file crt/crt_s128_m22_exhaust.txt

# merit 25
bin/gen_crt_exhaust \
    --ctr-primes 25 --ctr-merit 25 --ctr-bits 128 --ctr-random \
    --ctr-file crt/crt_s128_m25_exhaust.txt
```

### shift 133  (log2(primorial) ≈ 127.5 with 25 primes; 5 extra ctr-bits → 32 nAdd/hash)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 25 --ctr-merit 30 --ctr-bits 133 --ctr-random \
    --ctr-file crt/crt_s133_m30_exhaust.txt
```

### shift 160  (log2(primorial) ≈ 154.5 with 29 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 29 --ctr-merit 22 --ctr-bits 160 --ctr-random \
    --ctr-file crt/crt_s160_m22_exhaust.txt
# Run for 10–30 minutes, Ctrl-C when satisfied
```

### shift 192  (log2(primorial) ≈ 189.9 with 34 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 34 --ctr-merit 22 --ctr-bits 192 --ctr-random \
    --ctr-file crt/crt_s192_m22_exhaust.txt
```

### shift 256  (log2(primorial) ≈ 234.1 with 40 primes)

```bash
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 256 --ctr-random \
    --ctr-file crt/crt_s256_m22_exhaust.txt
```

### shift 384 / 512 / 640 / 768 / 1024  (primorial maxes out at 40 primes)

For these shifts the full 40-prime table (log2 ≈ 234 bits) is smaller than
`2^shift`, so the miner iterates `2^(shift−233)` candidate nAdd values
per hash (e.g. 512 → 2^279 iterations — these are effectively infinite
from CRT's perspective; use `gen_crt` instead for large shifts).

```bash
# shift 384
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 384 --ctr-random \
    --ctr-file crt/crt_s384_m22_exhaust.txt

# shift 512
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 512 --ctr-random \
    --ctr-file crt/crt_s512_m22_exhaust.txt

# shift 640
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 640 --ctr-random \
    --ctr-file crt/crt_s640_m22_exhaust.txt

# shift 768
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 768 --ctr-random \
    --ctr-file crt/crt_s768_m22_exhaust.txt

# shift 1024
bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 21 --ctr-bits 1024 --ctr-random \
    --ctr-file crt/crt_s1024_m21_exhaust.txt

bin/gen_crt_exhaust \
    --ctr-primes 40 --ctr-merit 22 --ctr-bits 1024 --ctr-random \
    --ctr-file crt/crt_s1024_m22_exhaust.txt
```

---

## Choosing n_primes

`--ctr-primes N` covers odd primes 3, 5, … up to `PRIMES[N-1]`.  Every
output file also includes a hardcoded `2 1` entry, so the effective
primorial is `2 × 3 × 5 × … × PRIMES[N-1]`.  Choose the largest N
where `ceil(log2(total primorial)) ≤ shift`.

| shift | --ctr-primes | log2(2 × odd primorial) | Largest odd prime |
|-------|-------------|------------------------|-------------------|
| 25    | 7           | 23.2                   | 19                |
| 34    | 9           | 32.6                   | 29                |
| 37    | 9           | 32.6                   | 29                |
| 42    | 10          | 37.5                   | 31                |
| 47    | 11          | 42.8                   | 37                |
| 53    | 12          | 48.1                   | 41                |
| 58    | 13          | 53.5                   | 43                |
| 64    | 14          | 59.1                   | 47                |
| 68    | 15          | 64.8                   | 53                |
| 96    | 20          | 95.0                   | 73                |
| 110   | 22          | 107.7                  | 83                |
| 128   | 25          | 127.5                  | 101               |
| 133   | 25          | 127.5                  | 101               |
| 160   | 29          | 154.5                  | 113               |
| 192   | 34          | 189.9                  | 149               |
| 256   | 40          | 234.1                  | 179               |
| 384+  | 40          | 234.1                  | 179               |

For shifts > 233 bits the full 40-prime table is used; the miner iterates
`2^(shift - 233)` candidate `nAdd` values per hash instead of just one.
More primes than needed only adds search space without further reducing
candidates once the primorial exceeds `2^shift`.

## Output format

Same as `gen_crt`.  Load with the miner:

```bash
gap_miner ... --crt-file crt/crt_s128_m22_exhaust.txt
```

Each block in the output file is one solution:

```
# CRT sieve file generated by gen_crt_exhaust
n_primes 7
merit 22.00
shift 128
gap_target 1953
n_candidates 614
# phase1_kernel exp(-a*|x/scale|^b)
# phase1_a 5.800000
# phase1_b 3.300000
# phase1_scale 976.000000
# phase1_remaining 614
# phase1_score_raw 545.123456789
# phase1_score_mean 0.887823219
3 2
5 1
7 3
...
# CRT:123456789...
```

The file always contains exactly **one solution** — the current best.
Each time a new minimum is found the file is overwritten, so it is always
directly loadable by the miner with `--crt-file` without any splitting.
