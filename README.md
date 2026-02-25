# Gap CPU Miner (C implementation)

A high-performance CPU miner for the Gapcoin proof-of-work variant that
searches for large prime gaps and builds blocks via live `getblocktemplate`
(GBT) RPC calls.  Every JSON-RPC POST and every raw block byte sequence is
saved to `/tmp` for forensic inspection.

## Repository layout

```
src/
  main.c            - core miner: sieve, primality, gap scan, block assembly
  rpc_cwrap.cpp     - C-callable wrapper around the C++ RPC layer
  rpc_globals.cpp   - shared RPC state (URL, credentials, rate limiting)
  rpc_stubs.cpp     - stub implementations for optional RPC paths
  rpc_json.c        - lightweight JSON helpers (also used by tests)
  rpc_json.h
  Rpc.cpp / Rpc.h   - C++ RPC class (libcurl + JSON-RPC)
  Opts.h            - option singleton header
  parse_block.c     - raw block parsing utilities
  utils.h           - small shared helpers
tests/
  test_rpc_json.c   - unit tests for rpc_json helpers
scripts/
  inspect_tx.py     - Python utility to decode raw block/transaction hex
                      files written to /tmp by the miner
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
  --sieve-size 262144 \
  --sieve-primes 1000000 \
  --threads 6 \
  --fast-fermat
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
primes (default 1 000 000).  The sieve reuses a thread-local buffer for
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

## Performance

Benchmarked on an Intel i3-10100 (4 cores / 8 threads, 3.6 GHz) with
`--shift 28 --sieve-size 262144 --sieve-primes 1000000 --threads 6 --fast-fermat`:

### Optimization progression

| Stage | Sieve rate | Primality rate | Cumulative speedup |
|-------|-----------|---------------|-------------------|
| Original (OpenSSL BN, -O2) | 535 K/s | 20.5 K tests/s | 1.0× |
| + GMP backend + cached sieve residues + vectorized extraction | 3,844 K/s | 150.9 K/s | 7.4× |
| + raw Fermat (`mpz_powm`) + batched atomics | 6,920 K/s | 277.7 K/s | 13.5× |
| + cooperative Fermat + -O3/LTO + mpz pre-alloc | 8,513 K/s | 342.6 K/s | **16.7×** |

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

6. **-O3 + LTO** -- Aggressive compiler optimization with link-time
   optimization enables cross-module inlining and auto-vectorization.

7. **Batched atomic stats** -- `stats_tested` counter updated once per
   window instead of once per candidate, reducing cross-core cache-line
   contention from ~278K atomic ops/s to ~100/s per thread.

> **Historical note:** an earlier Barrett-reduction path for fast modular
> exponentiation contained a correctness bug for large moduli and was
> disabled.  All arithmetic now uses GMP's assembly-optimized paths.

## Usage reference

### Key flags

| Flag                  | Default       | Description |
|-----------------------|---------------|-------------|
| `--header TEXT`       | *(from GBT)*  | Text whose SHA256 seeds the prime search |
| `--hash-hex`          | off           | Treat `--header` as a hex string |
| `--shift N`           | 20            | Left-shift exponent applied to the hash |
| `--adder-max M`       | `2^shift`     | Upper bound for the adder loop (`<= 2^shift`) |
| `--sieve-size S`      | 33554432      | Odd candidates per sieve segment |
| `--sieve-primes P`    | 1000000       | Small primes used for pre-sieving |
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
  --sieve-size 262144 \
  --sieve-primes 1000000 \
  --threads 6 \
  --fast-fermat
```

The header is selected automatically from `getblocktemplate`.

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

Every ~0.3 s the miner prints a line like:

```
STATS: elapsed=30.0s  sieved=255415634 (8513003/s)  tested=10279612 (342619/s)  gaps=0 (0.000/s)  built=0  submitted=0  accepted=0
```

| Field | Meaning |
|-------|---------|
| `sieved` | Odd candidates eliminated by the segmented sieve |
| `tested` | Primality tests (Fermat / Miller-Rabin) actually run |
| `gaps` | Gaps found whose merit ≥ `--target` |
| `built` | Full blocks assembled from a GBT template after a qualifying gap |
| `submitted` | Blocks whose header hash also met the network `bits` difficulty and were sent to the node |
| `accepted` | Node confirmed the block |

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

`gaps=0` after ~10 minutes at ~343 K tests/s and ~8.5 M sieved/s is completely
normal.  The miner is working correctly if sieve and test rates are non-zero.

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

Happy mining!
