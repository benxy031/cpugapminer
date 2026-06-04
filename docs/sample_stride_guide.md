# Gap-Finding Tuning Guide

## Overview: two completely different scan algorithms

The miner has **two scan algorithms**, selected automatically based on whether
`--cuda`/`--opencl` is active and whether a `--crt-file` is loaded.

| Mode | Algorithm | Fermat tests per window | False-gap risk |
|------|-----------|------------------------|----------------|
| **GPU non-CRT** | Two-phase smart-scan | ~1/K of full | Yes — verified post-hoc |
| **CPU non-CRT** | Backward-scan (bkscan) | ~1/8 of full | None |
| **CRT (any)** | Full Fermat on all CRT candidates | 100% of filtered set | None |

`--sample-stride` means something **different** in each mode — do not apply GPU
rules to CPU runs or vice-versa.

---

## GPU non-CRT: two-phase smart-scan

### What it does

1. **Phase 1** — the GPU tests every K-th sieve survivor (K = `--sample-stride`).
   This produces a sparse set of confirmed primes.
2. **Gap analysis** — consecutive Phase-1 primes separated by ≥ `target × ln(N)`
   become **candidate gap regions**.  The gap-detection threshold is always the
   network `--target` merit, not `--scan-merit`.
3. **RGM filtering** *(after ≥50 k calibration samples, default)* — regions whose interior
   density is ≥30% below the RGM baseline are skipped as uniformly-dense.
4. **Phase 2** — the GPU tests all non-sampled sieve survivors inside surviving
   regions.  The surviving Phase-1 + Phase-2 primes are merged and sorted.
5. **False-gap verification** — every gap that passes the merit threshold is
   scanned for interior primes by `bn_candidate_is_prime()`.  This catches any
   prime that was on a sampled index and still happened to be missed.

### Key insight: `--scan-merit` is IGNORED by the GPU path

The code sets `gpu_rth = (size_t)(target_local * logbase)` (network merit) for
gap-region detection, not the `--scan-merit` value.  Setting `--scan-merit` does
nothing useful in GPU mode; omit it.

### What is sample-stride?

In **GPU smart-scan mode** (`--cuda`), the sieve produces a sorted array of survivors.
Instead of testing every survivor in phase-1, the GPU tests only every K-th element
(`--sample-stride K`). At least 2 sampled candidates must fall inside every
qualifying gap, or the gap will be missed entirely.

### Formula

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
>
> **Key insight 4 (NEW)**: `--scan-merit` is **ignored** by the GPU smart-scan path.
> Gap regions are detected at the network `--target` threshold.  Only CPU backward-scan
> uses `--scan-merit` to set the backward-jump distance.
>
> **Key insight 5 (NEW)**: `--fast-euler` is **enabled by default**.  You do not need
> to pass it explicitly.  It halves the cost of CPU boundary probes (left/right edge
> of each gap region) even in GPU mode.  Passing `--fast-fermat` overrides it and
> costs ~29% more pps.
>
> **Key insight 6 (NEW)**: With `WITH_CGBN_FERMAT=1` at build time, the GPU Fermat
> kernel runs at ~1.9× the throughput for 768-bit candidates (AL=12, TPI=8).  This
> raises effective GPU Fermat capacity from ~6.5 M to ~12 M tests/s, shifting the
> pipeline bottleneck back to the sieve.  When CGBN is active, more sieve-primes
> (deeper sieving) pays off more than before because GPU becomes less of a bottleneck.

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

## CGBN Shift Support Table

`WITH_CGBN_FERMAT=1` does not mean every shift uses the CGBN kernel.
Runtime uses CGBN only when `active_limbs = ceil((256 + shift)/64)` is one of:

- `AL = 2, 4, 6, 8, 12, 16, 20`

All other `AL` values (1,3,5,7,9,10,11,13,14,15,17,18,19,...) fall back to the
scalar CUDA Fermat kernel.

The table below shows practical shift ranges (`shift >= 1`) that actually run on CGBN.

| Build (`GPU_BITS`) | `NL` | CGBN shift ranges |
|--------------------|-----:|-------------------|
| `512`              |    8 | `65-128` (AL=6), `193-256` (AL=8) |
| `768`              |   12 | `65-128` (AL=6), `193-256` (AL=8), `449-512` (AL=12) |
| `1024`             |   16 | `65-128` (AL=6), `193-256` (AL=8), `449-512` (AL=12), `705-768` (AL=16) |
| `1280`             |   20 | `65-128` (AL=6), `193-256` (AL=8), `449-512` (AL=12), `705-768` (AL=16), `961-1024` (AL=20) |

Notes:

- Common shifts: `64` is scalar (AL=5), `68` is CGBN (AL=6), `512` is CGBN (AL=12), `768` is CGBN only if `GPU_BITS >= 1024`.
- If a candidate needs more limbs than compiled `NL`, GPU path cannot represent it and falls back to CPU primality checks.

## Upstream GapMiner Metric Mapping

The original GapMiner status line prints `gaps/s`, `tests/s`, and `pps`, but those labels do not line up cleanly with our miner's CRT counters.

| Upstream GapMiner | Meaning | Closest cpugapminer CRT stat |
|-------------------|---------|-------------------------------|
| `gaps/s` | Gap candidates processed by the sieve / Fermat pipeline | `gaps` / gap-event rate |
| `tests/s` | Fermat tests performed on candidates | `tested/s` |
| `pps` | Pairs-per-second style throughput inside the sieve pipeline | `pairs/s` |
| accepted share output | Submitted work that passed validation | `accepted` |

In other words, upstream `gaps/s` is a runtime mining throughput metric, not an accepted-share metric. For CRT-path comparisons in this codebase, the useful trio is `gaps`, `tested/s`, and `accepted`, with `est_model` vs `est_observed` kept separate to avoid confusing the predicted rate with the measured one.

**Quick rule:** `safe_stride = floor(target_merit / 2)` prevents false negatives.  
**Optimal throughput** in practice: `floor(target_merit / 4)` to `floor(target_merit / 3)`.  
For target 20.7–21.5 the safe maximum is **10** but benchmark optimum is **5–7**.
For target 22.0+ safe max is **11**, optimum **6–8**.

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
- **With CGBN build**: GPU Fermat is ~1.9× faster, so optimal sieve depth shifts up.
  At shift=68 with CGBN, 4–6 M primes (vs 2–4 M scalar) keeps the GPU fully occupied.

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

## GPU non-CRT: example commands

Notes on these examples:
- `--fast-euler` is the default and is **not** shown; omit `--fast-fermat`.
- `--sieve-primes` is **optional for GPU non-CRT** — the miner auto-scales it
  as `900000 × (shift/64)^1.5` (capped at 10 M).  Set it explicitly only if
  you want to override the auto value.
- With `WITH_CGBN_FERMAT=1` build: increase sieve-primes by ~1.5–2× vs the
  values below because the GPU Fermat bottleneck is reduced by ~1.9×.

### Shift 64 — GPU non-CRT

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 64 --threads 12 \
  --sieve-size 22000000 \
  --sample-stride 5 --cuda
# sieve-primes auto-scales to ~900K (shift=64, scale=1.0)
```

With CGBN build (deeper sieve pays off):

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 64 --threads 12 \
  --sieve-size 22000000 --sieve-primes 2000000 \
  --sample-stride 5 --cuda
```

### Shift 128 — GPU non-CRT

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 128 --threads 8 \
  --sieve-size 33500000 \
  --sample-stride 5 --cuda
# sieve-primes auto-scales to ~2.55M (shift=128, scale=2.83)
```

### Shift 384 — GPU non-CRT

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 384 --threads 6 \
  --sieve-size 22000000 \
  --sample-stride 5 --cuda
# sieve-primes auto-scales to ~8.2M (shift=384, scale=9.19, capped at 10M)
```

### Shift 512 — GPU non-CRT (CGBN build, GPU_BITS=768)

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 512 --threads 6 \
  --sieve-size 22000000 \
  --sample-stride 5 --cuda
# sieve-primes auto-scales to 10M (capped)
```

### Shift 768 — GPU (max, AL=12, GPU_BITS=768)

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 768 --threads 6 \
  --sieve-size 12000000 \
  --sample-stride 5 --cuda
```

### Shift >768 — CPU only (exceeds GPU capacity at GPU_BITS=768)

```bash
./gap_miner -o HOST -p PORT -u USER --pass PASS \
  -s 1024 --threads 14 \
  --sieve-size 12000000 --sieve-primes 4000000
# stride=8 (default) enables backward-scan automatically
```

---

## CPU non-CRT: backward-scan algorithm

### How it works (actual code, not summary)

The backward-scan algorithm (`gap_scan.c: backward_scan_segment`) works as follows:

1. Find the **first prime** in the window (forward scan from start).
2. Compute `target_pos = current_prime + needed_gap` where  
   `needed_gap = scan_target × ln(N)`.
3. Binary-search for the first candidate > `target_pos`, then **scan backward**
   from that point looking for the next prime.
4. If a prime is found → new `current_prime`, jump to step 2.
5. If **no prime** is found between `current_prime` and `target_pos` → qualifying
   gap found.  Record it, then forward-scan for the next prime after `target_pos`.
6. Repeat until end of window.

This algorithm tests only ~8 candidates per confirmed prime (prime density in
sieve survivors ≈ 12–15%), for an ~8× reduction in Fermat tests vs. full scan.
**No false gaps are possible** — every candidate in a gap region IS tested.

### `--sample-stride` meaning in CPU mode

`stride > 1` enables backward-scan.  `stride = 1` disables it (full cooperative
test, ~8× slower — benchmarking baseline only).

The **numeric value of stride** affects the adaptive best-merit sampling pass
only (a leading sample of `max(cnt/32, stride×8, 64)` capped at 320 candidates
is tested before the backward scan).  A higher stride slightly enlarges this
sample.  **Gap-finding quality and speed are not affected by the stride number**
as long as `stride > 1`.

### `--scan-merit` in CPU mode

`--scan-merit M` sets `scan_target = M` for the backward-scan jump distance:
```
needed_gap = scan_target × ln(N)
```
If `M < submit_target`, the backward scan catches gaps slightly below the
submit threshold (useful for merit tracking / stats display).  If `M > submit_target`,
the code silently clamps it to `submit_target` and warns once.

**Recommendation**: omit `--scan-merit`; the default (`submit_target`) is correct.

### CPU vs GPU crossover

| Shift | Recommended mode | Why |
|------:|:----------------:|-----|
| ≤ 64  | **CPU bkscan** | Per-test cost (300-bit Fermat) is low; bkscan algorithm overhead is zero; GPU launch overhead dominates |
| 64–128 | Depends on GPU | Benchmark both; GPU wins when CGBN is active |
| ≥ 128 | **GPU smart-scan** | Individual Fermat cost (768-bit+) dominates; GPU parallelism wins |

### CPU threading

The window is split into overlapping LEFT and RIGHT halves.  The worker thread
processes the backward scan on LEFT; the helper thread sieves the next window
**and** backward-scans RIGHT concurrently.  Overlap requires `--threads ≥ 2`.
This gives ~1.5× speedup on hyperthreaded CPUs.  At shift ≤ 64 sieve time ≈
scan time, so the overlap is near-perfect.

---

## CRT mode: full Fermat on filtered candidates

CRT modes (`--crt-file`) do **not** use backward-scan or GPU smart-scan.  Every
CRT-filtered candidate is Fermat-tested.  The sieve-primes and GPU batch size
are set automatically per shift band:

| Shift range | sieve-primes (CPU) | sieve-primes (GPU) | gpu-batch |
|------------:|-------------------:|-------------------:|----------:|
| ≥ 768       | 5 000 000          | 300 000            | 16 384    |
| ≥ 384       | 3 000 000          | 300 000            | 8 192     |
| ≥ 128       | 2 000 000          | 500 000            | 4 096     |
| < 128       | 900 000            | 900 000            | 2 048     |

Note: **GPU CRT uses far fewer sieve-primes than CPU CRT**.  In GPU CRT mode,
the GPU Fermat test is the bottleneck, not candidate density; deeper sieving
reduces candidates but the GPU can handle them anyway.  Shallow sieving lets
the sieve run faster and keeps the GPU fed.

With `WITH_CGBN_FERMAT=1` you may benefit from slightly deeper sieving in GPU
CRT mode at shift 128–384 (the GPU bottleneck is reduced ~1.9×).

### CRT recommended command (shift 512, GPU monolithic)

```bash
bin/gap_miner -o HOST -p PORT -u USER --pass PASS \
  --shift 512 --threads 8 \
  --cuda 0 \
  --crt-file crt/crt_s512_m22.txt
# sieve-primes auto: 300K (GPU CRT profile)
# gpu-batch auto: 8192
```

---

## Sieve auto-scaling reference (GPU non-CRT)

The miner automatically scales `--sieve-primes` based on shift when `--cuda`
is active and no explicit `--sieve-primes` is given:

```
scale      = (shift / 64) ^ 1.5
auto_count = min(900000 × scale, 10000000)
```

| Shift | scale | auto sieve-primes | P_max (approx) |
|------:|------:|------------------:|---------------:|
|    64 |  1.00 |           900 000 |       14 M     |
|   128 |  2.83 |         2 547 000 |       42 M     |
|   192 |  5.20 |         4 682 000 |       82 M     |
|   256 |  8.00 |         7 200 000 |      130 M     |
|   320 | 11.31 |        10 000 000 |      186 M     |
|   384 | 15.59 |        10 000 000 | (capped)       |
|   512 | 22.63 |        10 000 000 | (capped)       |
|   768 | 42.43 |        10 000 000 | (capped)       |

**With CGBN build**: the GPU can handle more candidates per second, so the
optimal sieve depth shifts toward denser sieving.  Consider adding
`--sieve-primes 10000000` explicitly at shifts ≥ 256 even without auto-cap.

---

## Effect of sieve-primes on GPU non-CRT throughput

From measurements at shift=68, sieve-size=25.5 M.  `Primes/window` (confirmed
primes from PNT) is nearly constant; candidate count falls with more sieving.

| sieve-primes | keep% | Cands / window | Primes / window | Safe stride |
|-------------:|------:|---------------:|----------------:|:-----------:|
|      500 000 |  3.54 |        ~903 K  |         ~114 K  | **10**      |
|    1 000 000 |  3.38 |        ~862 K  |         ~114 K  | **10**      |
|    2 000 000 |  3.23 |        ~824 K  |         ~114 K  | **10**      |
|    3 300 000 |  3.10 |        ~790 K  |         ~112 K  | **10**      |
|    5 000 000 |  3.03 |        ~773 K  |         ~114 K  | **10**      |
|    8 000 000 |  2.97 |        ~757 K  |         ~114 K  | **10**      |
|   16 000 000 |  2.86 |        ~730 K  |         ~114 K  | **10**      |

Primes/window ≈ `sieve_size / ln_N` — constant.  Safe stride is always determined
by confirmed-prime density (≈ target_merit), not by candidate density.

---

## RGM calibration and region scoring

After accumulating enough calibration samples (default: **50 000**, configurable via
`--rgm-cal-min N`), the GPU smart-scan path uses RGM scoring to **skip
uniformly-dense regions** (threshold: ≥30% below RGM baseline, sigma=0.7). This
reduces Phase-2 work in windows too dense to contain a qualifying gap.

**Important:** RGM accumulation only happens with `--sample-stride 1` (full scan).
In smart-scan mode the confirmed-prime array is biased, so accumulation is
skipped there. You must run briefly with stride 1 to build the baseline.

### Warm-up estimate (shift≈68, ~114 k primes/window)

| cal-min | Windows needed | Wall time |
|---------|---------------|----------|
| 50 000 (default) | ~5 windows | ~2–3 s |
| 100 000 | ~10 windows | ~5 s |
| 500 000 (old hardcoded) | ~48 windows | ~24 s |

### Persisting the baseline across restarts

Use `--rgm-state-file PATH` to load the prior baseline on startup and save
it on clean exit. This eliminates the warm-up wait entirely on subsequent runs.

```bash
# First run: stride 1 for a few seconds to build baseline, then exit.
./gap_miner --cuda --shift 68 --target 21 --sample-stride 1 \
            --rgm-state-file rgm_baseline.txt

# Production run: loads pre-warmed baseline instantly, mines at stride 5.
./gap_miner --cuda --shift 68 --target 21 --sample-stride 5 \
            --rgm-state-file rgm_baseline.txt
```

The state file is a small human-readable text file (~3 lines). It is safe to
delete at any time; the miner will recreate it on the next clean exit.

Key options:
- `--rgm-cal-min N` — minimum samples before scoring activates (default: 50 000).
  Lower = faster warmup but noisier early baseline; below 10 000 not recommended.
- `--rgm-state-file FILE` — persist baseline across restarts (load + save on exit).

---

## Quick decision guide

| Goal | Mode | Key flags | Stride |
|------|------|-----------|--------|
| Record hunting, GPU, shift 64–128 | GPU non-CRT | `--cuda --sample-stride 5` | 5 |
| Record hunting, GPU, shift 128–512 | GPU non-CRT (CGBN build recommended) | `--cuda --sample-stride 5` | 5 |
| Record hunting, GPU, shift 512–768 | GPU non-CRT, GPU_BITS=768 build | `--cuda --sample-stride 5` | 5 |
| Record hunting, CPU only, shift ≤ 64 | CPU bkscan | *(default, no --cuda)* | 8 (default) |
| Record hunting, CPU only, shift > 768 | CPU bkscan | *(no --cuda)* | 8 (default) |
| CRT gap-solving, GPU | GPU CRT monolithic | `--cuda 0 --crt-file ...` | N/A |
| CRT gap-solving, CPU | CPU CRT monolithic | `--crt-file ...` | N/A |
| Correctness baseline / RGM cal | GPU full scan | `--cuda --sample-stride 1` | 1 |

### Common mistakes

| Mistake | Effect | Fix |
|---------|--------|-----|
| Using `--fast-fermat` on GPU runs | Costs ~29% more pps on boundary probes | Remove it; `--fast-euler` is default |
| Setting `--scan-merit` in GPU mode | No effect on gap detection | Remove it |
| Manual `--sieve-primes` lower than auto | Leaves GPU under-utilized | Omit or increase it |
| `--sample-stride > 10` at target≈21 | Gap regions missed → false low merit | Keep stride ≤ 10 |
| `--sample-stride 1` in production | 8× more Fermat tests, same gap quality | Use stride 5 instead |
| Not specifying `GPU_BITS=768` at shift 512 | Extra registers, lower occupancy | `make GPU_BITS=768` |
| `--threads 1` with GPU | No helper sieves next window; GPU stalls | Use `--threads ≥ 2` |
