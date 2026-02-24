# Gap CPU Miner (C implementation)

This repository contains a C miner for the Gapcoin proof‑of‑work variant that
searches for large prime gaps and builds blocks from live `getblocktemplate`
(GTB).  The code is designed for forensic transparency: every JSON‑RPC POST
and every raw block byte sequence is saved to `/tmp` for later inspection.

## Building

The miner is written in plain C with optional RPC support implemented in C++.
Dependencies (on a Linux system) include:

- `gcc`/`g++` (C11/C++17)
- `make`
- `libcurl` + development headers
- `libjansson` (JSON parser)
- `libssl` / `libcrypto` (OpenSSL)
- `pthread` (POSIX threads)

Build the miner with RPC enabled (recommended – it will fetch templates and
submit blocks).  Run from the repository root:

```sh
make clean           # wipe previous build artifacts
make WITH_RPC=1      # compile C core + RPC wrapper
```

The resulting binary is placed in `bin/gap_miner`.

On Debian/Ubuntu you can install the native dependencies with:

```sh
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev libpthread-stubs0-dev
```

To build without RPC support (simpler, test‑only), omit the variable:

```sh
make clean
make
```

Run the unit tests for the RPC/JSON helpers with:

```sh
make test
./tests/test_rpc_json
```

## Usage

The miner takes a seed string (`--header`) whose SHA256 hash is used as
a starting point for the prime‑gap search.  In mathematical terms the prime
candidate is computed as

```
p = SHA256(header) * 2^shift + adder
```

where `shift` is the number of left‑ward bit positions and `adder` is the
offset added on top.  The adder is bounded by `0 <= adder < 2^shift` to
prevent reuse of the same proof‑of‑work with different header values; the
implemented loop increments `adder` from 0 up to (but never including)
`adder_max`.

Internally the program shifts the 256‑bit hash and then adds the adder value
to define the numerical range it sieves for primes – see `--adder-max`
below.  **This adder is purely a local search parameter and has nothing to do
with the RPC work returned by the node.**  When mining against a live node you
always use the `previousblockhash` (or whatever header the node supplies);
the adder simply lets the miner slide around within that hash's neighbourhood
looking for interesting gaps.

To make life easier you can omit `--header` entirely if you supply an RPC URL;
in that case the program will query `getblocktemplate` and use the returned
`previousblockhash` as the header automatically.  A typical run with default
parameters looks like this:

You can also capture miner output in a file using `--log-file miner.log`.  The
log will contain the same messages printed to the console – sieving
progress, header updates, gap findings, and share submissions – allowing you
to distinguish your miner’s activity from the node’s own logs.

```sh
bin/gap_miner \
  --header "example header text" \
  --shift 25 \
  --sieve-size 33554432 \
  --sieve-primes 900000 \
  --rpc-url http://127.0.0.1:31397/ \
  --rpc-user USER --rpc-pass PASS
```

The important arguments are:

- `--header`: arbitrary text used as the base of the header hash; the miner
  takes the SHA256 of this string and then shifts it to generate the numerical
  range in which it searches for prime gaps.  If you do not specify `--header`
  but do provide `--rpc-url`, the miner will automatically pull the
  `previousblockhash` from the template and use that as the header.  In
  either case changing the header changes the work being performed.
- `--shift`: left‑shift applied to SHA256(header) to compute the prime region
- `--adder-max`: how many consecutive offsets (adders) to try within the
  shifted hash.  For each `adder` value the miner sieves the next chunk of
  odd numbers; the higher this is, the larger the search window.  The adder
  is purely local – the node does **not** know about it, and new work from the
  node simply resets the header hash, after which adder counting restarts.
  By default the miner picks the full legal range automatically, setting
  `adder-max=2^shift` so that all values `0 … 2^shift-1` are tried.  You can
  override this with the flag if you want a smaller window.  The adder must
  always satisfy `adder < 2^shift` to avoid re‑use of proof‑of‑work.

  When the adder reaches `adder-max` the miner normally would stop, but if
  you run with `--keep-going` (the default) the adder loop simply wraps and
  the search continues.  On RPC the header is refreshed whenever a gap-
  qualified block needs building (or at the end of a cycle), so the program
  will run indefinitely until you kill it.

  **Optimised gap scanning** – rather than checking every adjacent prime for a
  large gap, the miner uses an algorithm inspired by dcct’s improvements:
  after identifying the current prime `pstart` it computes the maximum gap
  (`max_length = target * log(pstart)`) that could still satisfy the merit
  threshold.  It then scans the list of primes **forward** within the window
  `(pstart,pstart+max_length)`, jumping ahead when no qualifying prime is
  found.  Forward scanning often finds the first good candidate more quickly
  than a reverse search, which makes a big difference when the sieve yields a
  tight cluster.  The code avoids repeated calls to `log()` by computing a
  parallel table of logarithms inside the sieve; this reduces the CPU cost of
  the gap loop considerably.  (The scanning logic lives in `scan_candidates()`.)

The miner obtains work from the node by calling `getblocktemplate` over RPC.
This returns a JSON object containing the previous block hash, current
`curtime`, the block `version`, the `bits` (compact difficulty), and the
`coinbasevalue` (reward), along with a list of transactions to include.  The
`bits` field sets the proof‑of‑work target against which the header hash is
checked; it does **not** control the mining merit.  Merit is a purely local
quantity derived from the gap between two probable primes (`gap/log(p)`) and
is used to decide which candidate gaps are worth assembling into blocks.

> **Note:** the node does not tell you anything about `adder` or the internal
search window.  Every time you fetch a new template the miner restarts the
adder count at zero with the new header.  The adder mechanism exists solely
because we are scanning successive integers in the neighbourhood of the header
hash; it is not part of the blockchain protocol or node work specification.
>
> When running with `--rpc-url` the miner will automatically log the
> `previousblockhash` returned by every `getblocktemplate` call.  This message
> appears on startup (if no header was supplied), whenever a qualifying gap
> triggers a block build, and (when `--keep-going` is active) once per adder
> cycle as the search repeats.  There is no independent polling – templates
> are only fetched when the code actually needs one.  The output looks like
> ``work header <hex>`` (followed by “(different from previous)” when the hash
> has changed) and simply confirms that the node has provided work.  You no
> longer need to wait for a change to see a message; a header is printed even
> if it is identical to the last one.

Because the node gives you `coinbasevalue` and `height`, the miner can build a
valid coinbase transaction and compute the merkle root for each candidate
block.  The actual gap search (and merit calculation) is independent of the
node and is what makes this a "gap miner" rather than an ordinary sha256
miner.
- `--sieve-size`: size of the segmented sieve window (default shown above)
- `--sieve-primes`: maximum number of small primes to use when pre‑sieving.
  A larger value increases sieve accuracy (fewer candidates) but also slows
  the sieve itself; the default is 1 000 000, which is a good compromise.  On
  slower machines you can drop this to 100 000 or even 50 000 to make the
  sieve faster at the cost of doing more primality checks.  If the
  primality stage dominates the runtime (see the log messages), try increasing
  this value – moving work into the sieve is usually cheaper than running
  millions of Fermat tests.  Alternatively, the `--no-primality` flag will
  bypass the testing entirely and send every sieved candidate to the scanning
  stage, which is useful for benchmarking or when you trust the sieve
  sufficiently.

Under the hood the segmented sieve now reuses a thread‑local buffer for
primes and their logarithms; this avoids repeated malloc/free cycles and
eliminates the stuttering you might otherwise see when the search window is
large.
- RPC options: URL/user/pass for communicating with a local Gapcoin node

Additional options include `--target` (merit threshold – not supplied by
  the node but computed locally from the gap: merit = gap/log(p)), `--threads N`,
  and `--fast-fermat` to trade an extremely small amount of correctness for
  speed.  When this flag is used the miner performs an aggressive primality
  filter: after a handful of trial divisions it runs **one** Fermat base (2) –
  a single modular exponentiation – against each candidate.  Because the sieve
  already filters by hundreds of thousands of small primes the odds of a
  composite surviving the sieve and then passing base‑2 Fermat are vanishingly
  small, so the extra base‑3 test was dropped earlier to halve the cost of the
  check.  The implementation uses the generic `modpow()` helper; an earlier
  attempt at a faster sliding‑window exponentiation contained a bug that caused
  all fast‑Fermat tests to fail, so the simpler routine was retained.  (If you
  need the extra safety of a second base you can rebuild the code with the
  `WITH_EXTRA_BASE` symbol or manually re-enable the second check in
  `fast_fermat_test()`; the option remains documented in the source.)

  **Historical note:** the codebase once attempted to speed up the exponentiations
  with Barrett reduction, eliminating the hardware divide from the inner loop.
  A correctness bug for large moduli was discovered and the reduction has been
  disabled; all arithmetic now uses the standard 128‑bit modulo operator.  The
  performance impact is minor compared with the sieve, but the Barrett code has
  been left in place as a reference for anyone wishing to reimplement it
  correctly.

  By default the miner **continues** mining after successfully submitting a
  block; the old `--keep-going` flag is still accepted but mostly exists for
  documentation.  If you prefer the previous behaviour of exiting upon
  finding a solution, use `--stop-after-block` to request that.  Run
  `bin/gap_miner --help` for the full list.

### Full command‑line options

For completeness, here are all of the flags currently supported by
`gap_miner`.  Many of these were discussed above; the list is reproduced
from the `main.c` argument parser and kept in sync manually.

```
--header <text>        text used to generate header hash (auto‑chosen from
                        getblocktemplate if omitted)
--hash-hex             treat header argument as hex rather than string
--shift N              exponent of two added to header hash (default 20)
--adder-max M          maximum adder value for segmented sieve (defaults
                        to 2^shift when omitted, otherwise must be ≤2^shift)
--sieve-size S         number of odd candidates to sieve per segment
--sieve-primes P       prefilter primes count for sieve (speed vs memory)
--target T             minimum merit value required to build block (a local
                        threshold; in the earliest Python gapminer the mining
                        target was fetched from the node, but our C rewrite
                        computes merit itself – the node has no knowledge of
                        gaps or merit).
--rpc-url URL          JSON‑RPC URL of gapcoind
--rpc-user USER        RPC username
--rpc-pass PASS        RPC password
--rpc-method METH      RPC method to use when submitting (default getwork)
--rpc-rate MS          minimum ms between RPC submissions (rate limit)
--rpc-retries N        number of retry attempts on failure
--rpc-sign-key KEY     HMAC key to sign payloads (for logging)
--log-file FILE        file to append miner messages to
--build-only           only fetch template and build a block (no sieving)
--no-opreturn          omit OP_RETURN payload from coinbase when building
--force-solution       pretend every candidate meets the target (debug)
--keep-going           explicitly enable continuation after a found block
                        (default behaviour, provided for backwards
                        compatibility).  With this flag (or default) the miner
                        never exits simply because it has tried all configured
                        adders; the search repeats and new node templates are
                        fetched as they appear.  To stop on completion use
                        `--stop-after-block`.
--stop-after-block     exit when a valid block has been submitted rather than
                        continuing to mine; the inverse of the default
                        behaviour
--fast-fermat          use a fast Fermat probable-prime test (bases 2 & 3)
                        instead of full Miller‑Rabin.  Faster, but there is
                        a tiny risk of misclassifying a composite as prime.
--no-primality         skip the probabilistic primality stage entirely
--selftest             run a few internal prime/composite checks and exit
--threads N            number of worker threads for the sieve
--p P --q Q            small/large primes for forced build-only runs
```

As shown earlier, a minimal invocation specifying defaults would be:
```sh
bin/gap_miner --rpc-url http://127.0.0.1:31397/ --rpc-user benxy031 \
    --rpc-pass xx --shift 25 --sieve-size 33554432 --sieve-primes 900000
```

(The header is picked automatically from `getblocktemplate`.)

### Forensics and logging

- JSON‑RPC submissions are written to `/tmp/gap_miner_submit_*.json`.
- Successfully assembled blocks (hex and raw binary) are written to
  `/tmp/gap_miner_block_*.hex` and `.bin` for audit.
- Miner statistics are printed periodically and on exit.

## Notes

* The miner will only call `submitblock` – we call it a *share* when
  talking pool‑style – when the constructed header’s hash actually meets the
  network difficulty.  Each share submission is preceded by a console/log
  message `submitting share (block candidate) to node`; watching for that line
  in your miner log proves the miner is doing work (as opposed to the node
  merely accepting peer blocks).
  A share is produced only after:
    1. a gap with sufficient merit has been found,
    2. a block has been assembled from the current GTB template, and
    3. the header produced by that block passes the difficulty check.
  Each share submission is logged to the console and counted in the
  `stats_submits`/`stats_success` counters; the raw JSON payload is also
  written under `/tmp` for forensics.
  Until a share is valid the miner simply continues searching prime gaps.
* Use `--force-solution` to pretend a candidate always meets the target –
  useful for testing the submission path.
* The `--keep-going` flag prevents the program from exiting after a found
  block, allowing continuous operation on test networks or during debugging.

Happy mining!
