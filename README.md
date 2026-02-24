# Gap CPU Miner (C implementation)

A CPU miner for the Gapcoin proof-of-work variant that searches for large
prime gaps and builds blocks via live `getblocktemplate` (GBT) RPC calls.
Every JSON-RPC POST and every raw block byte sequence is saved to `/tmp` for
forensic inspection.

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
Required dependencies on Linux:

| Library           | Debian/Ubuntu package        |
|-------------------|------------------------------|
| gcc / g++         | `build-essential`            |
| libcurl           | `libcurl4-openssl-dev`       |
| libjansson        | `libjansson-dev`             |
| libssl / libcrypto| `libssl-dev`                 |
| pthreads          | included in glibc            |

Install them in one go:

```sh
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev
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
  --shift 25 \
  --sieve-size 33554432 \
  --sieve-primes 1000000
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

After sieving, each candidate undergoes a probabilistic primality test:

- **Default** -- full trial division up to the sieve limit, then Miller-Rabin.
- `--fast-fermat` -- one Fermat base-2 modular exponentiation.  The chance of
  a composite surviving the sieve and passing base-2 Fermat is negligible; a
  second base can be re-enabled via `WITH_EXTRA_BASE` at compile time.
- `--no-primality` -- skip testing entirely (benchmarking / sieve trust).

> **Historical note:** an earlier Barrett-reduction path for fast modular
> exponentiation contained a correctness bug for large moduli and was
> disabled.  All arithmetic now uses the standard 128-bit `%` operator.  The
> Barrett code remains in the source as a reference.

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
| `--threads N`         | 1             | Worker threads for the sieve |
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
  --shift 25 \
  --sieve-size 33554432 \
  --sieve-primes 1000000
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
