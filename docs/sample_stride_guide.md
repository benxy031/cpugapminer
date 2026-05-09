# `--sample-stride` Reference Guide

## What is sample-stride?

In **GPU smart-scan mode** (`--cuda`), the sieve produces a sorted array of survivors.
Instead of testing every survivor in phase-1, the GPU tests only every K-th element
(`--sample-stride K`). Survivors clumped too densely in a region will all be sampled
exactly once per stride, and if an entire stride-width gap is empty of sampled primes
it is flagged as a **candidate gap region** and filled in during phase-2.

The stride must be ≤ `gap_survivors / 2` — i.e., at least 2 sampled candidates must
fall inside every qualifying gap, or the gap will be missed entirely.

## Formula

```
ln_N          = (256 + shift) × ln(2)          # log of the number being tested
needed_gap    = target_merit × ln_N             # minimum qualifying gap (numbers)
avg_spacing   ≈ ln_N                            # average gap between confirmed primes
                                                # (PNT; independent of sieve-primes)

gap_survivors = needed_gap / avg_spacing        # ≈ target_merit (shift-cancels!)
safe_stride   = floor(gap_survivors / 2)        # ≥ 2 sampled primes per gap guaranteed
              = floor(target_merit / 2)         # simplified form
```

Derived from first principles:
- Phase 1 samples 1-in-K sieve survivors.  Among K consecutive survivors, on average
  `K × (1/keep_rate) × (1/ln_N)` = `K × ln_N / ln_N` = K are tested to confirm 1 prime.
- Therefore sampled confirmed primes have average spacing `K × ln_N` in integer space.
- A qualifying gap of `target × ln_N` contains `target × ln_N / (K × ln_N)` = `target/K`
  sampled primes on average.
- For ≥ 2 sampled primes per gap: `K ≤ target/2`.

> **Key insight 1**: `avg_spacing ≈ ln_N` depends on **shift** (grows with N), not on
> sieve-primes.  The stride table below reflects this; the column values increase
> proportionally to `ln_N` only to account for the larger `needed_gap`.
>
> **Key insight 2**: The simplified formula `safe_stride = floor(target_merit / 2)`
> is **independent of both shift and sieve-primes** and is the **maximum safe** stride.
> Empirically the **optimal** stride is roughly `floor(target_merit / 4)` to
> `floor(target_merit / 3)` — see [Phase 2 overhead](#phase-2-overhead) below.
> For the current network target (~20.97), use **stride 5–7**.
>
> **Key insight 3**: Sieve-size affects GPU batch size (candidates per window) but
> not stride.  See the [sieve-primes section](#effect-of-sieve-primes) below.

---

## Stride Reference Table

Target merit = 20.7 (safe floor for current network).  
`avg_spacing = ln_N = (256+shift)×ln(2)` — shift-dependent, sieve-primes-independent.

| Shift | Bits  | ln(N)  | min gap | gap_surv | **Safe stride** | GPU limbs | GPU works? |
|------:|------:|-------:|--------:|---------:|:---------------:|----------:|:----------:|
|    64 |   320 |  221.8 |   4 591 |     20.7 | **10**          |         5 | ✓          |
|    96 |   352 |  243.9 |   5 049 |     20.7 | **10**          |         6 | ✓          |
|   110 |   366 |  253.7 |   5 252 |     20.7 | **10**          |         6 | ✓          |
|   128 |   384 |  266.1 |   5 509 |     20.7 | **10**          |         6 | ✓          |
|   133 |   389 |  269.7 |   5 583 |     20.7 | **10**          |         7 | ✓          |
|   160 |   416 |  288.3 |   5 968 |     20.7 | **10**          |         7 | ✓          |
|   192 |   448 |  310.4 |   6 426 |     20.7 | **10**          |         7 | ✓          |
|   256 |   512 |  354.9 |   7 346 |     20.7 | **10**          |         8 | ✓          |
|   320 |   576 |  399.2 |   8 264 |     20.7 | **10**          |         9 | ✓          |
|   384 |   640 |  443.6 |   9 183 |     20.7 | **10**          |        10 | ✓          |
|   512 |   768 |  532.3 |  11 019 |     20.7 | **10**          |        12 | ✓          |
|   640 |   896 |  621.0 |  12 855 |     20.7 | **10**          |        14 | ✓          |
|   768 | 1 024 |  709.7 |  14 691 |     20.7 | **10**          |        16 | ✓ (max)    |
|   896 | 1 152 |  798.5 |  16 529 |     20.7 | **10**          |        18 | ✗ CPU only |
| 1 024 | 1 280 |  887.2 |  18 365 |     20.7 | **10**          |        20 | ✗ CPU only |

`gap_surv = needed_gap / avg_spacing = (target × ln_N) / ln_N = target_merit` — constant.

> **GPU limbs** = `ceil((256 + shift) / 64)`.  
> The kernel is compiled with `NL = 16` (1 024-bit capacity).  
> Shifts > 768 exceed this limit and fall back to CPU Fermat automatically.

**Quick rule:** `safe_stride = floor(target_merit / 2)` prevents false negatives.  
**Optimal throughput** in practice: `floor(target_merit / 4)` to `floor(target_merit / 3)`.  
For target 20.7–21.5 the safe maximum is **10** but benchmark optimum is **5–7**.
For target 22.0+ safe max is **11**, optimum **6–8**.

---

---

## Phase 2 Overhead

The safe-maximum formula prevents correctness failures but does not predict optimal
throughput.  Phase 2 cost grows with stride because sparser Phase 1 sampling creates
more and wider surviving gap regions to fill.  Empirically (shift=68, RTX 3060,
`sieve-primes≈1M`, `sieve-size=25.5M`, target≈21):

| stride | sieved/s | tested/s | est   | surv/Msieved | note |
|-------:|---------:|---------:|------:|-------------:|------|
|      1 |  199 M/s |  6.68 M  | 26.1m |       4 426  | no Phase 2 (baseline) |
|      2 |  387 M/s |  6.49 M  | 12.1m |       2 216  | Phase 2 light |
|    **5** |  **751 M/s** |  **6.31 M**  | **6.7m** |   **1 113**  | **optimal** |
|      9 |  545 M/s |  6.73 M  |  8.8m |       1 632  | Phase 2 growing |
|     10 |  470 M/s |  6.46 M  | 10.5m |       1 816  | below safe max |
|     15 |  340 M/s |  6.72 M  | 14.0m |       2 617  | Phase 2 dominant |
|     20 |  286 M/s |  6.76 M  | 16.6m |       3 132  | near stride=1 again |

`pairs/Msieved ≈ 4440` is flat for all strides (total confirmed primes = Phase1+Phase2 combined
= PNT constant), confirming the formula.  `sieved/s` peaks at stride=5 because:

- **Below 5**: Phase 1 tests too many candidates → window loop is Fermat-bound
- **At 5**: Phase 2 fills only a small number of tight regions → minimal overhead
- **Above 5**: Phase 2 regions grow in number and width → more filling work per window

The GPU Fermat throughput cap (~6.5 M tests/s) is hit in all cases; the difference is
how many windows/second the CPU can dispatch.  High-stride Phase 2 effectively turns
the GPU back into a near-full-scan, cancelling the speedup.

**Rule of thumb:** Start at `stride = floor(target/4)` and tune up by 1–2 if `est`
improves; stop when `est` starts rising.  For target≈21: start at **5**.

The safe stride formula `floor(target / 2)` is **independent of sieve-primes** because
both the candidate density and the Fermat pass rate vary in opposite directions with
`P_max`, leaving the confirmed prime density (and hence `avg_spacing = ln_N`) unchanged.

What **does** change with sieve-primes (for shift=68, sieve-size=25.5 M):

| sieve-primes | P_max    | keep% | prime% (Fermat pass) | Cands / window | Primes / window | Safe stride |
|-------------:|---------:|------:|---------------------:|---------------:|----------------:|:-----------:|
|      500 000 |   7.37 M |  3.54 |                 12.6 |        ~903 K  |         ~114 K  | **10**      |
|    1 000 000 |  15.49 M |  3.38 |                 13.2 |        ~862 K  |         ~114 K  | **10**      |
|    2 000 000 |  32.45 M |  3.23 |                 13.8 |        ~824 K  |         ~114 K  | **10**      |
|    3 300 000 |  61.39 M |  3.10 |                 14.2 |        ~790 K  |         ~112 K  | **10**      |
|    5 000 000 |  86.03 M |  3.03 |                 14.7 |        ~773 K  |         ~114 K  | **10**      |
|    8 000 000 | 145.84 M |  2.97 |                 15.0 |        ~757 K  |         ~114 K  | **10**      |
|   16 000 000 | 300.00 M |  2.86 |                 15.6 |        ~730 K  |         ~114 K  | **10**      |

`keep%` ≈ 3.10 × ln(61.4 M) / ln(P_max) (Mertens scaling from empirical reference at 3.3 M primes).  
`Primes/window` ≈ `sieve_size / ln_N` — set by N alone, nearly constant across all sieve depths.

**Trade-offs:**
- More primes → fewer Fermat candidates → lower GPU occupancy, but higher Fermat pass rate.
- More primes → longer sieve marking time on CPU.
- For shift=68 the optimum is typically 2–4 M primes; beyond that sieve overhead grows
  faster than Fermat savings.
- `false_gaps` are already 0 at 3.3 M primes for this shift; deeper sieving adds no benefit.

## Window Survivors by Sieve-Size

All configs use `sieve-primes = 3 300 000` (P_max ≈ 61 M) → candidate rate ≈ 3.10%.
`Primes / window ≈ sieve_size / ln_N`.

| Sieve-size   | Cands / window | Primes / window | Batch memory (u64) |
|-------------:|---------------:|----------------:|-------------------:|
|   12 000 000 |        ~372 K  |         ~53 K   | 2.98 MB            |
|   22 000 000 |        ~682 K  |         ~97 K   | 5.46 MB            |
|   25 500 000 |        ~791 K  |         ~113 K  | 6.33 MB            |
|   33 500 000 |       ~1 039 K |         ~149 K  | 8.31 MB            |

The larger sieve-size means more candidates per flush but the same stride.
Check that your GPU has enough VRAM to hold the batch (all sizes are fine for a 4 GB card).

---

## Mining for Higher Merit Targets

The safe stride scales directly with target merit:

```
safe_stride_max  = floor(target_merit / 2)   # correctness upper bound
optimal_stride   = floor(target_merit / 4)   # empirical throughput optimum
```

| Target merit | Safe max | Optimal start | GPU works? |
|-------------:|:--------:|:-------------:|:----------:|
|         20.7 | **10**   | **5**         | ✓          |
|         21.0 | **10**   | **5**         | ✓          |
|         22.0 | **11**   | **5–6**       | ✓          |
|         24.0 | **12**   | **6**         | ✓          |
|         26.0 | **13**   | **6–7**       | ✓          |
|         30.0 | **15**   | **7–8**       | ✓          |

Both columns are independent of shift and sieve-primes.

---

## Example Commands

### Shift 64 — GPU, sieve-size 22M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 64 --threads 12 --fast-fermat \
  --sieve-size 22000000 --sieve-primes 4000000 \
  --sample-stride 5 --cuda
```

### Shift 128 — GPU, sieve-size 33.5M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 128 --threads 10 --fast-fermat \
  --sieve-size 33500000 --sieve-primes 4000000 \
  --sample-stride 5 --cuda
```

### Shift 384 — GPU, sieve-size 22M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 384 --threads 8 --fast-fermat \
  --sieve-size 22000000 --sieve-primes 4000000 \
  --sample-stride 5 --cuda
```

### Shift 768 — GPU (max supported), sieve-size 12M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 768 --threads 6 --fast-fermat \
  --sieve-size 12000000 --sieve-primes 4000000 \
  --sample-stride 5 --cuda
```

### Shift 1024 — CPU only (exceeds GPU NL=16)
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 1024 --threads 14 --fast-fermat \
  --sieve-size 12000000 --sieve-primes 4000000
```

---

## Notes

- **`--sample-stride` has different meaning in non-GPU mode.**  In CPU mode the
  specific numeric value does not matter — only whether it is `> 1` (default 8).
  `stride > 1` enables the **backward-scan** algorithm; `stride = 1` disables it
  and falls back to cooperative full-test (useful only for benchmarking).
  The CPU backward-scan uses a hardcoded `BKSCAN_SAMPLE = 200` seed internally
  and is not sensitive to the stride value.
- At **shift ≤ 68**, CPU backward-scan typically outperforms GPU smart-scan
  because the per-test cost (300-bit modular exponentiation) is low enough that
  the algorithm efficiency advantage of backward-scan beats GPU raw throughput.
- At **shift ≥ 128**, GPU starts to win as individual Fermat cost dominates.
- The **default stride = 8** in the source is well-tuned for shifts up to ~96 with
  target ≈20.7 (`floor(20.7/2)=10`; 8 is safe and slightly conservative).
  For any shift or sieve depth, the safe upper bound is `floor(target_merit/2)`.
- **`--sample-stride 1`** disables smart-scan entirely (full test of every sieve
  survivor); use this as the correctness baseline or when Option C
  `qual_prob` calibration is needed.
