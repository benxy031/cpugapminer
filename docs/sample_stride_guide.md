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
ln_N         = (256 + shift) × ln(2)       # log of the number being tested
needed_gap   = target_merit × ln_N          # minimum qualifying gap (numbers)
avg_spacing  = 1 / survival_rate            # distance between sieve survivors
               ≈ 245  (for sieve-primes = 4 000 000, P_max ≈ 61 M)

gap_survivors = needed_gap / avg_spacing    # how many survivor indices span the gap
safe_stride   = floor(gap_survivors / 2)    # ≥ 2 samples per gap guaranteed
```

> **Key insight**: `avg_spacing` depends only on sieve-primes (not sieve-size).  
> Therefore the safe stride **is the same for all three sieve sizes** when
> `sieve-primes = 4 000 000`.  Sieve-size affects how many survivors are
> produced per window (GPU batch size), but not the stride.

---

## Stride Reference Table — `sieve-primes = 4 000 000`

Target merit = 20.7 (current network minimum).  
`avg_spacing ≈ 245` (observed: 49 K survivors per 12 M window).

| Shift | Bits  | ln(N)  | min gap | gap_surv | **Rec. stride** | GPU limbs | GPU works? |
|------:|------:|-------:|--------:|---------:|:---------------:|----------:|:----------:|
|    64 |   320 |  221.8 |   4 591 |     18.7 | **9**           |         5 | ✓          |
|    96 |   352 |  243.9 |   5 049 |     20.6 | **10**          |         6 | ✓          |
|   110 |   366 |  253.7 |   5 252 |     21.4 | **10**          |         6 | ✓          |
|   128 |   384 |  266.1 |   5 509 |     22.5 | **11**          |         6 | ✓          |
|   133 |   389 |  269.7 |   5 583 |     22.8 | **11**          |         7 | ✓          |
|   160 |   416 |  288.3 |   5 968 |     24.4 | **12**          |         7 | ✓          |
|   192 |   448 |  310.4 |   6 426 |     26.2 | **13**          |         7 | ✓          |
|   256 |   512 |  354.9 |   7 346 |     30.0 | **15**          |         8 | ✓          |
|   320 |   576 |  399.2 |   8 264 |     33.7 | **16**          |         9 | ✓          |
|   384 |   640 |  443.6 |   9 183 |     37.5 | **18**          |        10 | ✓          |
|   512 |   768 |  532.3 |  11 019 |     44.9 | **22**          |        12 | ✓          |
|   640 |   896 |  621.0 |  12 855 |     52.5 | **26**          |        14 | ✓          |
|   768 | 1 024 |  709.7 |  14 691 |     59.9 | **29**          |        16 | ✓ (max)    |
|   896 | 1 152 |  798.5 |  16 529 |     67.5 | **33**          |        18 | ✗ CPU only |
| 1 024 | 1 280 |  887.2 |  18 365 |     74.9 | **37**          |        20 | ✗ CPU only |

> **GPU limbs** = `ceil((256 + shift) / 64)`.  
> The kernel is compiled with `NL = 16` (1 024-bit capacity).  
> Shifts > 768 exceed this limit and fall back to CPU Fermat automatically.

---

## Window Survivors by Sieve-Size

All three configs use `sieve-primes = 4 000 000` → survival rate ≈ 0.41%.

| Sieve-size  | Survivors / window | Avg GPU batch size | Survivors occupy |
|------------:|-------------------:|-------------------:|-----------------|
|  12 000 000 |           ~49 000  |           ~49 000  | 384 KB (u64)    |
|  22 000 000 |           ~90 000  |           ~90 000  | 703 KB          |
|  33 500 000 |          ~137 000  |          ~137 000  | 1.04 MB         |

The larger sieve-size means more survivors per flush but the same stride.
Check that your GPU has enough VRAM to hold the batch (all three sizes are fine
for a 4 GB card).

---

## Mining for Higher Merit Targets

If targeting merit ≥ 22.0 (CRT file merit target) rather than ≥ 20.7:

```
stride_merit22 = stride_merit20.7 × (22.0 / 20.7) ≈ stride × 1.063
```

In practice add 1–2 to the table values above; this rarely matters.

---

## Example Commands

### Shift 64 — GPU, sieve-size 22M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 64 --threads 12 --fast-fermat \
  --sieve-size 22000000 --sieve-primes 4000000 \
  --sample-stride 9 --cuda
```

### Shift 128 — GPU, sieve-size 33.5M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 128 --threads 10 --fast-fermat \
  --sieve-size 33500000 --sieve-primes 4000000 \
  --sample-stride 11 --cuda
```

### Shift 384 — GPU, sieve-size 22M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 384 --threads 8 --fast-fermat \
  --sieve-size 22000000 --sieve-primes 4000000 \
  --sample-stride 18 --cuda
```

### Shift 768 — GPU (max supported), sieve-size 12M
```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 768 --threads 6 --fast-fermat \
  --sieve-size 12000000 --sieve-primes 4000000 \
  --sample-stride 29 --cuda
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
- The **default stride = 8** in the source is well-tuned for shift ≈ 44–64.
  For higher shifts use the table above.
