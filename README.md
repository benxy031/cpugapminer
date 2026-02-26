# Gap CPU Miner (C implementation)

A high-performance CPU miner for the Gapcoin proof-of-work variant that
searches for large prime gaps and builds blocks via live `getblocktemplate`
(GBT) RPC calls.  Every JSON-RPC POST and every raw block byte sequence is
saved to `/tmp` for forensic inspection.

## Repository layout

```
src/
  main.c            - core miner: sieve, primality, gap scan, CRT mining,
                      block assembly
  rpc_cwrap.cpp     - C-callable wrapper around the C++ RPC layer
  rpc_globals.cpp   - shared RPC state (URL, credentials, rate limiting)
  rpc_stubs.cpp     - stub implementations for optional RPC paths
  rpc_json.c        - lightweight JSON helpers (also used by tests)
  rpc_json.h
  Rpc.cpp / Rpc.h   - C++ RPC class (libcurl + JSON-RPC)
  Opts.h            - option singleton header
  parse_block.c     - raw block parsing utilities
  utils.h           - small shared helpers
tools/
  gen_crt.c         - CRT gap-solver: greedy + evolutionary algorithm to
                      generate optimised CRT sieve files
docs/
  CRT_GENERATION.md - parameter reference for generating CRT files
                      (shifts 64–1024)
tests/
  test_rpc_json.c   - unit tests for rpc_json helpers
scripts/
  inspect_tx.py     - Python utility to decode raw block/transaction hex
                      files written to /tmp by the miner
crt/
  crt_s64_m21.txt   - production CRT file: 15 primes, shift 64, merit 21
  crt_7.bin          - legacy binary CRT template (7 primes)
  crt_8.bin          - legacy binary CRT template (8 primes)
  crt_s512_m22.txt   - CRT file: 75 primes, shift 512, merit 22
  crt_s640_m22.txt   - CRT file: 89 primes, shift 640, merit 22
Makefile
```

## Building

The miner is written in plain C11 with optional RPC support in C++17.
Compiled with `-O3 -march=native -flto` for maximum throughput.

Required dependencies on Linux:

| Library           | Debian/Ubuntu package        |
|-------------------|------------------------------|
| gcc / g++         | `build-essential`            |
| libcurl           | `libcurl4-openssl-dev`       |
| libjansson        | `libjansson-dev`             |
| libssl / libcrypto| `libssl-dev`                 |
| libgmp            | `libgmp-dev`                 |
| pthreads          | included in glibc            |

Install them in one go:

```sh
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev libgmp-dev
```

### With RPC (recommended)

Fetches block templates from, and submits blocks to, a running `gapcoind`:

```sh
make clean
make WITH_RPC=1
```

### Without RPC (test / offline build)

```sh
make clean
make
```

The binary is placed at `bin/gap_miner`.

### Custom GMP build (optional)

To link against a custom GMP installation (e.g. built with `--enable-fat`
for portable runtime CPU detection):

```sh
make clean
make WITH_RPC=1 GMP_PREFIX=/path/to/gmp
```

This statically links `GMP_PREFIX/lib/libgmp.a` and uses headers from
`GMP_PREFIX/include`.  Without `GMP_PREFIX`, the system `-lgmp` is used.

### CRT gap-solver tool

```sh
make gen_crt
```

Produces `bin/gen_crt`.  See [docs/CRT_GENERATION.md](docs/CRT_GENERATION.md)
for parameter tables and ready-to-use commands for shifts 64–1024.

### Unit tests

```sh
make test
./tests/test_rpc_json
```

## Quick start

The simplest invocation lets the miner pick its own work header from the node:

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 28 \
  --threads 6 \
  --fast-fermat
```

With CRT gap-solver acceleration (shift 64):

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 64 \
  --threads 6 \
  --fast-fermat \
  --crt-file crt/crt_s64_m21.txt
```

Capture output to a file as well:

```sh
bin/gap_miner ... --log-file miner.log
```

## How it works

### Header hash and the adder

The miner derives a prime candidate from:

```
p = SHA256(header) * 2^shift + adder
```

`SHA256(header)` is taken from either the `--header` string you supply or the
`previousblockhash` returned by `getblocktemplate` (auto-selected when
`--header` is omitted and `--rpc-url` is provided).

`adder` runs from `0` up to `adder-max` (default `2^shift`), sliding the
search window through the neighbourhood of the header hash.  The constraint
`adder < 2^shift` prevents proof-of-work reuse.  The adder is a **local**
concept -- the node knows nothing about it; fetching a new template resets it
to zero.

When `adder` reaches `adder-max` the loop wraps and continues (default
`--keep-going` behaviour).  Use `--stop-after-block` to exit instead.

### Sieve and gap scan

The segmented sieve pre-filters candidates using up to `--sieve-primes` small
primes (default 900 000).  The sieve reuses a thread-local buffer for
primes and their logarithms to avoid repeated allocation overhead.

Qualifying candidates are passed to `scan_candidates()`, which:

1. Identifies the starting prime `pstart`.
2. Computes `max_length = target * log(pstart)` to bound the gap window.
3. Scans forward through primes in `(pstart, pstart + max_length)`.

Forward scanning is usually faster than a reverse search in tight prime
clusters.  Pre-computing `log()` values in the sieve avoids repeated calls
during the gap loop.

### Block assembly

`getblocktemplate` supplies `previousblockhash`, `curtime`, `version`, `bits`,
`coinbasevalue`, `height`, and the transaction list.  The miner builds a valid
coinbase transaction, computes the merkle root, and assembles the full block
header.  `bits` sets the network difficulty target; merit (`gap / log(p)`) is
computed locally and is not reported to the node.

### Primality testing

After sieving, each candidate undergoes a probabilistic primality test using
**GMP** (`libgmp`) for all big-number arithmetic:

- **Default** -- full probable-prime test via `mpz_probab_prime_p` with 10
  Miller-Rabin rounds.
- `--fast-fermat` -- raw base-2 Fermat test via `mpz_powm` (computes
  `2^(n-1) mod n`).  Bypasses GMP's internal trial-division (redundant for
  candidates that already survived a million-prime sieve), yielding the
  fastest possible primality path.  False-positive composites are rejected
  by the network.
- `--no-primality` -- skip testing entirely (benchmarking / sieve trust).

The GMP backend replaces the original OpenSSL `BN_is_prime_fasttest_ex` path.
GMP's hand-tuned x86-64 assembly (Montgomery multiplication, Karatsuba) is
5-10× faster than OpenSSL's generic C for 284-bit modular exponentiation.

### Cooperative Fermat testing

Each worker thread has a companion "sieve helper" thread.  While the worker
runs primality tests on window N, the helper sieves window N+1 into a
double-buffered slot.  Since sieving is ~25× faster than primality testing,
the helper finishes early and would otherwise idle.

After sieving, the helper **joins the worker** to test the current window's
candidates via a shared lock-free atomic work index
(`__sync_fetch_and_add`).  The worker stores confirmed primes in-place; the
helper stores its finds in a separate buffer.  Results are merged and sorted
before gap scanning.  On hyperthreaded CPUs, this turns idle HT siblings
into productive Fermat workers.

For large sieve windows (e.g. 33 554 432), the helper enters a **fermat-only
mode** (state=3) on the last window of each pass—skipping the sieve entirely
and going straight to cooperative Fermat assist.  Without this, the helper
would idle for the entire last window (~50% of total time with 2-window passes).

### CRT gap-solver mining

When a **text CRT file** is loaded with `--crt-file`, the miner switches to
a completely different mining strategy that replaces the normal windowed sieve.

**CRT files** are generated by `bin/gen_crt` (see `tools/gen_crt.c`).  They
contain prime:offset pairs optimised by a greedy + evolutionary algorithm
to maximise gap coverage for a target merit and shift.  The algorithm is
compatible with the original GapMiner `--calc-ctr` approach.

The CRT mining loop:

1. **Compute primorial** = product of all CRT primes (e.g. 2×3×5×…×47 ≈ 2^59
   for 15 primes).
2. **CRT alignment** — solve `nAdd ≡ -(base + o_i) (mod p_i)` for each CRT
   prime `p_i` with offset `o_i`, combining via incremental CRT.  This
   positions each prime's composites inside the gap region starting at
   `base + nAdd`.
3. **Iterate** `nAdd = nAdd0, nAdd0 + primorial, …` up to `adder_max`.
   At shift 64 with 15 primes, primorial ≈ 2^59 gives only **~15 candidate
   nAdd values** per hash.
4. **Fermat-test** each `base + nAdd`.  If composite, skip immediately.
5. **Gap check** — for each confirmed prime, sieve a small forward region
   (2 × gap_target ≈ 10 000 positions) and Fermat-test survivors to measure
   the gap.
6. **Report** — qualifying gaps (merit ≥ target) are passed to the standard
   `scan_candidates` path for block assembly and submission.

Because the normal windowed sieve is bypassed entirely, `--sieve-size`,
`--sieve-primes`, and `--sample-stride` have no effect in CRT mode.  The
only relevant flags are `--shift`, `--threads`, `--fast-fermat`, `--target`,
and `--crt-file`.

Two CRT file formats are supported:

| Format | Extension | Mode | Description |
|--------|-----------|------|-------------|
| Legacy binary | `.bin` | `CRT_MODE_TEMPLATE` | Bitmap tiling, ≤10 primes (old format) |
| Text (gen_crt) | `.txt` | `CRT_MODE_SOLVER` | Prime:offset pairs, CRT-aligned mining |

The format is auto-detected on load.

### Two-phase smart gap scanning

Controlled by `--sample-stride K` (default 8; set to 1 to disable).
Used in the normal (non-CRT) mining path.

Instead of testing every sieve survivor, the miner uses a two-phase approach
that skips survivors in regions where no qualifying gap can exist:

**Phase 1 – Sampling.**  Test every Kth survivor for primality.  The
"sampled primes" form a sparse skeleton of confirmed primes across the
window.

**Gap analysis.**  Measure distance between consecutive sampled primes.
Only regions where the gap between two sampled primes is ≥ `target × log(base)`
can possibly contain a qualifying gap—any sampled prime *inside* a candidate
gap would break it.  Survivors outside these regions are skipped entirely.

**Phase 2 – Verification.**  Test the remaining (unsampled) survivors only
within candidate regions.  Both phases use cooperative Fermat (worker +
helper).

The correctness guarantee is exact: every gap with merit ≥ target is found.
Proof: if a qualifying gap `[P, Q]` exists with `Q − P ≥ needed_gap`, then
no sampled prime can lie strictly between P and Q (it would split the gap).
Therefore P and Q lie within the same sampled-prime interval, which is
identified as a candidate region.

At production parameters (shift=37, target≈20.89), this typically **skips
~68% of Fermat tests**, yielding a **3.4× effective speedup** in
block-finding rate.  The benefit grows with higher targets and shifts.

## Performance

Benchmarked on an Intel i3-10100 (4 cores / 8 threads, 3.6 GHz) with
`--shift 28 --sieve-size 33554432 --sieve-primes 900000 --threads 6 --fast-fermat`:

### Optimization progression

| Stage | Sieve rate | Primality rate | Cumulative speedup |
|-------|-----------|---------------|-------------------|
| Original (OpenSSL BN, -O2) | 535 K/s | 20.5 K tests/s | 1.0× |
| + GMP backend + cached sieve residues + vectorized extraction | 3,844 K/s | 150.9 K/s | 7.4× |
| + raw Fermat (`mpz_powm`) + batched atomics | 6,920 K/s | 277.7 K/s | 13.5× |
| + cooperative Fermat + -O3/LTO + mpz pre-alloc | 8,513 K/s | 342.6 K/s | **16.7×** |

### Smart scanning impact (shift=37, target=20.89, 2 threads)

| Mode | Sieve rate | ETA | Tests skipped |
|------|-----------|-----|---------------|
| Full (`--sample-stride 1`) | 12 M/s | 8.2 h | 0% |
| Smart (`--sample-stride 8`) | 32 M/s | **2.4 h** | **68%** |

Smart scanning processes **2.7× more sieve windows per second** by
skipping Fermat tests in regions that provably cannot contain a qualifying
gap.  The block-finding rate improves by **3.4×**.

### Key optimizations

1. **GMP primality backend** -- Replaced OpenSSL `BIGNUM` with GMP `mpz_t`.
   Thread-local `mpz_t` variables pre-allocated to 384 bits avoid all
   internal reallocation.  `mpz_add_ui` is O(1) for small offsets.

2. **Cached `base_mod_p[]`** -- Precompute `(hash << shift) % p` for all
   sieve primes once per mining pass, stored in a thread-local array.
   Eliminates ~78,000 calls to 256-bit modular reduction per sieve window.

3. **Vectorized extraction** -- Process sieve bitmap 64 bits at a time using
   `__builtin_ctzll` (compiles to `TZCNT` on x86 BMI1).  ~8× fewer loop
   iterations than per-bit scanning.

4. **Raw Fermat test** -- Direct `mpz_powm(2, n-1, n)` instead of
   `mpz_probab_prime_p(n, 1)`, bypassing GMP's internal trial-division
   of ~700 small primes (redundant after our million-prime sieve).

5. **Cooperative Fermat** -- Helper threads assist with primality testing
   after finishing their sieve work, utilizing otherwise-idle HT siblings.

6. **Two-phase smart scanning** -- Sample every Kth survivor, identify
   candidate regions, verify only those.  Skips ~68% of Fermat tests at
   production parameters for a 3.4× block-finding speedup.

7. **CRT gap-solver mining** -- Chinese Remainder Theorem alignment
   constrains which nAdd values to test, reducing the search space to
   only primorial-aligned candidates.  Instead of sieving millions of
   values per window, only ~15 CRT candidates are tested per hash (at
   shift 64 / 15 primes).  Each prime found triggers a small targeted
   gap-check sieve.

8. **-O3 + LTO** -- Aggressive compiler optimization with link-time
   optimization enables cross-module inlining and auto-vectorization.

9. **Incremental atomic stats** -- `stats_tested` counter updated every
   4 096 candidates (not per-candidate, not per-window).  With large sieve
   windows (33M) this keeps the display moving smoothly instead of freezing
   for 20+ seconds between window boundaries.

> **Historical note:** an earlier Barrett-reduction path for fast modular
> exponentiation contained a correctness bug for large moduli and was
> disabled.  All arithmetic now uses GMP's assembly-optimized paths.

## Usage reference

### Key flags

| Flag                  | Default       | Description |
|-----------------------|---------------|-------------|
| `--header TEXT`       | *(from GBT)*  | Text whose SHA256 seeds the prime search |
| `--hash-hex`          | off           | Treat `--header` as a hex string |
| `--shift N`           | 20            | Left-shift exponent applied to the hash.  Minimum 14, practical limit 512–1024 (per network).  Shifts > 62 are supported (`adder_max` capped at `INT64_MAX`). |
| `--adder-max M`       | `2^shift`     | Upper bound for the adder loop (`<= 2^shift`) |
| `--sieve-size S`      | 33554432      | Odd candidates per sieve segment |
| `--sieve-primes P`    | 900000        | Small primes used for pre-sieving |
| `--target T`          | *(node bits)* | Minimum merit `gap/log(p)` to build a block |
| `--threads N`         | 1             | Worker threads; each thread runs the full sieve + primality (Fermat/Miller-Rabin) + gap-scan pipeline over its own disjoint slice of the adder range (`tid, tid+N, tid+2N, …`) |
| `--rpc-url URL`       | --            | JSON-RPC endpoint of `gapcoind` |
| `--rpc-user USER`     | --            | RPC username |
| `--rpc-pass PASS`     | --            | RPC password |
| `--rpc-method METH`   | `getwork`     | Submission method |
| `--rpc-rate MS`       | 0             | Minimum ms between submissions |
| `--rpc-retries N`     | 3             | Retry attempts on failure |
| `--rpc-sign-key KEY`  | --            | HMAC key to sign payloads |
| `--log-file FILE`     | --            | Append all log messages to FILE |
| `--fast-fermat`       | off           | Fast single-base Fermat primality test |
| `--sample-stride K`   | 8             | Smart scan: test every Kth survivor, skip regions that can't contain qualifying gaps.  Set to 1 to disable. |
| `--crt-file FILE`     | --            | Load a CRT sieve file (binary `.bin` or text `.txt`).  Text files enable CRT-aligned mining; binary files enable template tiling. |
| `--no-primality`      | off           | Skip primality testing entirely |
| `--build-only`        | off           | Fetch template and build one block, then exit |
| `--no-opreturn`       | off           | Omit OP_RETURN from coinbase |
| `--force-solution`    | off           | Treat every candidate as valid (debug) |
| `--keep-going`        | on            | Continue after a found block (default) |
| `--stop-after-block`  | off           | Exit after submitting a valid block |
| `--selftest`          | off           | Run internal prime checks and exit |
| `--p P --q Q`         | --            | Force primes for `--build-only` runs |

### Minimal RPC invocation

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 28 \
  --threads 6 \
  --fast-fermat
```

The header is selected automatically from `getblocktemplate`.
Default `--sieve-size` (33 554 432) and `--sieve-primes` (900 000) match
the original GapMiner and work well for most setups.

## Forensics and logging

| Output                    | Location |
|---------------------------|----------|
| RPC submission payloads   | `/tmp/gap_miner_submit_*.json` |
| Assembled block (hex)     | `/tmp/gap_miner_block_*.hex` |
| Assembled block (binary)  | `/tmp/gap_miner_block_*.bin` |
| Miner stats               | console / `--log-file` |

The helper script `scripts/inspect_tx.py` can decode any of the `.hex` files
written above into a human-readable transaction/block dump:

```sh
python3 scripts/inspect_tx.py /tmp/gap_miner_block_<timestamp>.hex
```

## Reading the stats output

Every 5 s the miner prints a line like:

```
STATS: elapsed=30.0s  sieved=520000000 (34666667/s)  tested=4561182 (304079/s)  gaps=0 (0.000/s)  built=0  submitted=0  accepted=0  prob=8.46e-10/pair  est=7.0h (target=20.89)
```

| Field | Meaning |
|-------|---------|
| `sieved` | Odd candidates eliminated by the segmented sieve |
| `tested` | Primality tests (Fermat / Miller-Rabin) actually run |
| `gaps` | Gaps found whose merit ≥ `--target` |
| `built` | Full blocks assembled from a GBT template after a qualifying gap |
| `submitted` | Blocks whose header hash also met the network `bits` difficulty and were sent to the node |
| `accepted` | Node confirmed the block |
| `prob` | Per-pair probability of a qualifying gap (`e^(-target)`, Cramér–Granville heuristic) |
| `est` | Estimated time to find a qualifying gap at current rate |

### Why `gaps=0` and `submitted=0` are normal early on

Getting to `submitted=0` requires clearing **two independent gates**:

1. **Merit gate** – `gap / log(p) >= target` (default `--target 20.0`).  For a
   prime `p` around 2^281 (shift=25), `log(p) ≈ 195`, so a merit-20 gap requires
   a prime gap of ~3 900.  Such gaps exist but are rare; finding one is a
   Poisson process and can easily take many minutes or hours.

2. **Difficulty gate** – the double-SHA256 of the assembled block header must be
   below the network target encoded in `bits`.  A gap can pass the merit gate
   but still fail this check; in that case `built` increments but `submitted`
   does not.

`gaps=0` after ~10 minutes at ~300 K tests/s and ~30 M sieved/s is completely
normal.  The miner is working correctly if sieve and test rates are non-zero.
The `est` field gives a running estimate of time to find a qualifying gap.

### Troubleshooting low rates

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `sieved/s` very low | `--sieve-primes` too high | Reduce to 100 000–500 000 |
| `tested/s` dominates CPU | `--sieve-primes` too low | Increase (sieve does more, primality less) |
| `gaps=0` for hours | `--target` too high for your shift | Lower `--target` (e.g. 15) or verify shift |
| `built=0` despite gaps | No RPC / GBT not returning a template | Check `--rpc-url` / node connectivity |
| `submitted=0` despite built | Block hash not meeting difficulty | Normal on mainnet; use `--force-solution` to test submission path |

To verify the **submission path** end-to-end without waiting for a real gap use `--force-solution`:

```sh
bin/gap_miner --rpc-url http://127.0.0.1:31397/ --rpc-user USER --rpc-pass PASS \
  --force-solution --build-only
```

## Notes

* A share (`submitblock`) is sent **only** when:
  1. a gap with sufficient merit has been found,
  2. a block has been assembled from the current GBT template, and
  3. the resulting header hash meets the network difficulty.

  Each submission is counted in `stats_submits` / `stats_success` and logged
  with the message `submitting share (block candidate) to node`.

* Use `--force-solution` to exercise the submission path without waiting for a
  real qualifying gap (useful for integration testing).

* The `--sieve-primes` trade-off: a higher value moves work into the sieve
  (cheaper) and reduces primality-test load; a lower value speeds up the sieve
  at the cost of more Fermat/Miller-Rabin calls.  On slow machines start with
  100 000 and increase until the primality stage no longer dominates.

## CRT file generation

The `gen_crt` tool generates optimised CRT sieve files using a greedy +
evolutionary algorithm (compatible with GapMiner's `--calc-ctr` approach).

```sh
make gen_crt
./bin/gen_crt --calc-ctr \
  --ctr-primes 15 --ctr-merit 21 --ctr-bits 4 \
  --ctr-strength 200 --ctr-evolution --ctr-ivs 30 \
  --ctr-range 0 --ctr-file crt/crt_s64_m21.txt
```

Key parameters:

| Flag | Description |
|------|-------------|
| `--ctr-primes N` | Number of small primes (2, 3, 5, …) to use |
| `--ctr-merit M` | Target merit for gap computation |
| `--ctr-bits B` | Shift bits = `log2(primorial) - shift` (auto-computed) |
| `--ctr-strength S` | Greedy iterations per prime |
| `--ctr-evolution` | Enable evolutionary refinement |
| `--ctr-ivs N` | Population size for evolution |
| `--ctr-file FILE` | Output file path |

See [docs/CRT_GENERATION.md](docs/CRT_GENERATION.md) for a complete
parameter reference table with ready-to-use commands for shifts 64–1024.

Happy mining!
