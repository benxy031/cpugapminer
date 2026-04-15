# Gap CPU Miner (C implementation)

A high-performance CPU miner for the Gapcoin proof-of-work variant that
searches for large prime gaps and builds blocks via live `getblocktemplate`
(GBT) RPC calls or stratum pool connections.  Optional CUDA GPU acceleration
offloads Fermat primality testing to NVIDIA GPUs.  Every JSON-RPC POST and
every raw block byte sequence is saved to `/tmp` for forensic inspection.

## Repository layout

```
src/
  main.c            - core miner orchestration, worker loops, CLI/runtime
                      policy, block assembly glue
  compat_win32.h    - Windows compatibility helpers for 64-bit-safe code paths
  stats.h / .c      - shared mining statistics counters and stats thread
  sieve_cache.h / .c- sieve-prime and trial-division cache management
  wheel_sieve.h/.c  - optional wheel-presieve backend for non-CRT mining
  gap_scan.h / .c   - gap scanning helpers (backward scan/interior checks)
  crt_solver.h / .c - CRT file loading/parsing and solver orchestration
  crt_heap.h / .c   - CRT producer-consumer heap queue and work-item helpers
  crt_gap_scan.h/.c - CRT solver gap-window policy (mode parsing + window
                      sizing helpers)
  crt_runtime.h/.c  - shared CRT runtime policy helpers (adaptive controls)
  crt_runtime_worker.h/.c
                    - CRT runtime facade entrypoints and worker context glue
  crt_runtime_cpu.h/.c
                    - CRT CPU runtime loop implementation
  crt_runtime_gpu.c - CRT GPU runtime path and accumulator integration
  presieve_utils.h/.c
                    - pre-sieve buffer utilities for helper/worker pipeline
  mpresieve_avx512.h- AVX-512 presieve helpers/constants
  block_utils.h / .c- block serialization/encoding helpers (LE writes,
                      varint/pushdata, hex, double-SHA256)
  uint256_utils.h/.c
                    - 256-bit hash helpers and small-mod/log approximations
  primality_utils.h/.c
                    - 64-bit fast primality helpers (Montgomery MR/Fermat)
  rpc_cwrap.cpp     - C-callable wrapper around the C++ RPC layer
  rpc_globals.cpp   - shared RPC state (URL, credentials, rate limiting)
  rpc_stubs.cpp     - stub implementations for optional RPC paths
  rpc_json.c        - lightweight JSON helpers (also used by tests)
  rpc_json.h
  Rpc.cpp / Rpc.h   - C++ RPC class (libcurl + JSON-RPC)
  stratum.h / .c    - Gapcoin stratum pool client (TCP, auto-reconnect)
  gpu_fermat.h      - public C API for CUDA batch Fermat testing
  gpu_fermat.cu     - CUDA kernel: configurable-width Montgomery Fermat test
                      (default 1024-bit / 16 limbs, supports shift ≤ 768)
  gpu_fermat_opencl.c
                    - OpenCL Fermat backend implementation (experimental)
  gpu_fermat.def    - Windows export-definition file for GPU Fermat symbols
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
  test_rpc_json.c          - unit tests for rpc_json helpers
  test_wheel_sieve.c       - wheel presieve backend correctness tests
  test_wheel_compare.c     - wheel vs baseline presieve consistency checks
  test_crt_runtime_policy.c - CRT runtime policy tests (adaptive/backpressure)
scripts/
  inspect_tx.py     - Python utility to decode raw block/transaction hex
                      files written to /tmp by the miner
crt/
  crt_s*_m*.txt      - CRT sieve files: shifts 25–1024, merit targets 21–25
                      (e.g. crt_s128_m22.txt = shift 128, merit 22)
  crt_7.bin          - legacy binary CRT template (7 primes)
  crt_8.bin          - legacy binary CRT template (8 primes)
Makefile
```

## Building

The miner is written in plain C11 with optional RPC support in C++17.
Compiled with `-O3 -march=native -flto` for maximum throughput.

Required dependencies on Linux:

| Library           | Debian/Ubuntu package        | Required |
|-------------------|------------------------------|----------|
| gcc / g++         | `build-essential`            | yes      |
| libcurl           | `libcurl4-openssl-dev`       | yes      |
| libjansson        | `libjansson-dev`             | yes      |
| libssl / libcrypto| `libssl-dev`                 | yes      |
| libgmp            | `libgmp-dev`                 | yes      |
| pthreads          | included in glibc            | yes      |
| CUDA toolkit      | `nvidia-cuda-toolkit`        | optional (GPU Fermat) |

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

### Stable checkpoint build matrix

Before committing refactor slices, validate from a clean object state so
feature-flag object reuse cannot mask issues:

```sh
make clean
make -j4
make clean
make WITH_RPC=1 WITH_CUDA=1 -j4
```

### Custom GMP build (optional)

To link against a custom GMP installation (e.g. built with `--enable-fat`
for portable runtime CPU detection):

```sh
make clean
make WITH_RPC=1 GMP_PREFIX=/path/to/gmp
```

This statically links `GMP_PREFIX/lib/libgmp.a` and uses headers from
`GMP_PREFIX/include`.  Without `GMP_PREFIX`, the system `-lgmp` is used.

### With CUDA GPU acceleration (optional)

Offloads batch Fermat primality testing to an NVIDIA GPU using a
configurable-width Montgomery multiplication kernel (default 1024-bit /
16 limbs, supporting shifts up to 768).  Requires an NVIDIA GPU and the
CUDA toolkit (`nvcc`):

```sh
sudo apt-get install nvidia-cuda-toolkit
```

Build with CUDA enabled:

```sh
make clean
make WITH_RPC=1 WITH_CUDA=1
```

Build with OpenCL host scaffolding enabled (CLI + device/platform selection):

```sh
make clean
make WITH_RPC=1 WITH_OPENCL=1
```

Current status: OpenCL backend is experimental and functional for batch Fermat
testing.  It now uses CUDA-style arithmetic-limb dispatch (AL=5/6/8/10/12/16,
plus NL fallback) and vectorized limb loads (`ulong4`/`ulong2`) when aligned.
Performance is still generally behind the CUDA backend.

To target a specific GPU architecture (default `sm_61`):

```sh
make WITH_RPC=1 WITH_CUDA=1 CUDA_ARCH="-arch=sm_86"
```

If CUDA is installed outside `/usr/local/cuda`:

```sh
make WITH_RPC=1 WITH_CUDA=1 CUDA_PATH=/opt/cuda-12
```

Common `CUDA_ARCH` values: `sm_61` (Pascal / GTX 10xx), `sm_75` (Turing /
RTX 20xx), `sm_86` (Ampere / RTX 30xx), `sm_89` (Ada / RTX 40xx).

To change the GPU arithmetic width (e.g. for very high shifts):

```sh
make WITH_RPC=1 WITH_CUDA=1 GPU_BITS=1536
```

`GPU_BITS` sets the number of bits per candidate (`GPU_NLIMBS = GPU_BITS/64`).
Default is 1024 (16 limbs, shift ≤ 768).  Larger values support higher shifts
but use more GPU registers and reduce occupancy.

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
./tests/test_wheel_sieve
./tests/test_wheel_compare
./tests/test_crt_runtime_policy
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

With CRT gap-window floor tuning (example):

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 64 \
  --threads 6 \
  --fast-fermat \
  --crt-file crt/crt_s64_m21.txt \
  --crt-gap-scan original-floor=12000
```

With CRT at shift 512 (high-merit mining, default monolithic mode):

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 512 \
  --threads 6 \
  --fast-fermat \
  --crt-file crt/crt_s512_m22.txt
```

With CRT at shift 512 (producer-consumer, explicit split):

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 512 \
  --threads 16 \
  --fast-fermat \
  --fermat-threads 14 \
  --crt-file crt/crt_s512_m22.txt
```

Capture output to a file as well:

```sh
bin/gap_miner ... --log-file miner.log
```

### Recommended CRT CLI setup (April 2026)

Based on the latest 5x3 matrix (`shift` 64/160/384/512/768 across monolithic
CPU, monolithic GPU, and producer-consumer GPU-consumer), the practical
default on RTX 3060-class hardware is:

- use monolithic CRT with CUDA (`--cuda 0`)
- enable adaptive CRT GPU batch tuning (`--crt-gpu-batch-adaptive`)
- keep producer-consumer GPU-consumer as an advanced opt-in (near tie at
  shift 512; otherwise monolithic won)

`pps` in miner stats means **primes per second**.

Recommended mode by shift (matrix result):

| Shift | Recommended mode |
|---|---|
| 64 | Monolithic GPU |
| 160 | Monolithic GPU |
| 384 | Monolithic GPU |
| 512 | Monolithic GPU default (PC GPU-consumer is near-tie advanced option) |
| 768 | Monolithic GPU |

Recommended baseline command:

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 512 \
  --threads 8 \
  --fast-fermat \
  --cuda 0 \
  --crt-gpu-batch-adaptive \
  --crt-file crt/crt_s512_m22.txt
```

Optional advanced variant (only when you explicitly want producer-consumer
GPU consumers):

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 512 \
  --threads 8 \
  --fermat-threads 6 \
  --fast-fermat \
  --cuda 0 \
  --crt-gpu-consumer \
  --crt-gpu-batch-adaptive \
  --crt-file crt/crt_s512_m22.txt
```

## Recent changes (March-April 2026)

This section summarizes behavior that changed recently and may differ from
older logs, scripts, or command lines.

### CRT runtime/policy refactor (April 2026)

- CRT runtime loops were split into dedicated modules:
  - `src/crt_runtime_worker.c` (facade/entrypoints)
  - `src/crt_runtime_cpu.c` (CPU orchestration)
  - `src/crt_runtime_gpu.c` (GPU-specific runtime path)
  - shared policy module: `src/crt_runtime.c` + `src/crt_runtime.h`
- Single-thread and threaded CRT solver paths now share the same runtime worker
  context plumbing.
- New CRT runtime controls were added:
  - `--crt-gpu-consumer`
  - `--crt-gap-scan-adaptive`
  - `--crt-precision`, `--no-crt-precision`
  - `--crt-precision-rounds N`
  - `--crt-accum-soft-cap`, `--crt-accum-hard-cap`
  - `--crt-accum-backpressure`, `--no-crt-accum-backpressure`
  - `--crt-gpu-batch-adaptive`, `--no-crt-gpu-batch-adaptive`
  - `--crt-gpu-batch-min`, `--crt-gpu-batch-max`
- Added policy test coverage in `tests/test_crt_runtime_policy.c` for adaptive
  gap-window, accumulator preflush/backpressure, density drop, and adaptive GPU
  batch threshold policy functions.

### Correctness and platform safety

- 64-bit candidate offset additions now use a safe GMP path on platforms where
  `unsigned long` is 32-bit (notably Windows).  This avoids truncation in
  base+offset arithmetic and prevents false-gap style misclassification caused
  by offset overflow.

### Primality mode flags

- `--fast-euler` is available as a separate explicit mode (CPU path).
- `--fast-fermat` and `--fast-euler` are mutually exclusive.
- `--mr-verify` can still be layered on fast modes to re-check boundary
  candidates with MR base-3.

### Non-CRT adaptive sieve control

- `--partial-sieve-auto` automatically adjusts how many small primes are used
  by the non-CRT sieve.  It changes sieve depth.
- `--partial-sieve` is an alias for `--partial-sieve-auto`.

When `--partial-sieve-auto` is active, STATS now include
`partial_auto=on windows=... activations=... adjusts=...`, and the miner logs
each time the auto limit changes.

In short: `--partial-sieve-auto` decides how much sieving to do.

### Non-CRT wheel presieve backend

- `--wheel-sieve N` enables an alternate wheel presieve backend for the
  non-CRT sieve.
- Supported wheel sizes are `30`, `210`, `2310`, `30030`, `510510`, and `9699690`.
- This changes only the presieve initialization; CRT solver modes keep their
  existing CRT-specific sieve paths.

How to use it:

1. Build the miner as usual on Linux or Windows.
2. Run the binary with `--wheel-sieve 30`, `--wheel-sieve 210`,
  `--wheel-sieve 2310`, `--wheel-sieve 30030`, `--wheel-sieve 510510`, or
  `--wheel-sieve 9699690`.
3. Keep your normal mining flags (`--shift`, `--sieve-size`, `--target`,
   `--cuda`, `--rpc-url`, etc.) unchanged.

Examples:

- Linux non-CRT run with the 210 wheel:
  `./bin/gap_miner --shift 20 --sieve-size 33554432 --wheel-sieve 210 ...`
- Stronger wheel presieve with the 510510 cycle:
  `./bin/gap_miner --shift 20 --sieve-size 33554432 --wheel-sieve 510510 ...`
- Even stronger wheel presieve with the 9699690 cycle:
  `./bin/gap_miner --shift 20 --sieve-size 33554432 --wheel-sieve 9699690 ...`
- Windows build from GitHub Actions:
  the Windows workflow now compiles the wheel module and runs a smoke test
  with `--wheel-sieve 210 --selftest`.

Notes:

- `--wheel-sieve` is a presieve backend choice, not a change to the CRT
  solver or the Fermat stage.
- If you do not pass `--wheel-sieve`, the miner uses the existing generic
  pre-sieve path.

### CRT producer-consumer telemetry

In CRT producer-consumer mode (`--fermat-threads N`), STATS now include queue
telemetry:

- `gaplist`: current heap depth (pending windows)
- `hwm`: heap high-water mark (peak depth since start)
- `push`: windows accepted into heap
- `rep`: push-replace events (lower-priority entries evicted)
- `drop`: pushes dropped due to pressure (with percentage)
- `pop`: windows consumed by Fermat threads
- `wait%`: consumer wait ratio
- `stale`: stale windows dropped at pass transitions

Interpretation rule of thumb:

- `hwm` near heap cap plus non-zero `drop` means the queue is saturated and
  some work is being discarded.
- `gaplist` near zero with high `wait%` means consumers are starved and sieve
  production is too slow for the current split.

### CRT adaptive split

- `--crt-auto-split` enables pass-level adaptation of the
  sieve/fermat-thread split in CRT solver mode.
- The controller now uses queue pressure signals (`wait%`, empty-pop pressure,
  and `drop%`) to move the split conservatively.
- When persistent queue underfill is detected, the miner can trigger a
  controlled pass restart so a new split can take effect immediately instead of
  waiting for a naturally ending pass.

### CRT gap-window policy flags

Text CRT solver runs (`--crt-file ...txt`) now expose explicit gap-window
selection:

- `--crt-gap-scan fixed` (default): `max(2*gap_target,10000)`
- `--crt-gap-scan original`: `ceil(target*ln(start))`, clamped to `[8,gap_target]`
- `--crt-gap-scan original-floor`: `max(original,FLOOR)`

The floor can be set with `--crt-gap-scan-floor N` (default `10000`) or inline
as `--crt-gap-scan original-floor=N`.

Aliases are accepted for convenience:

- `orig`, `dynamic` -> `original`
- `orig-floor`, `dynamic-floor`, `hybrid` -> `original-floor`

### 8-at-a-time sieve inner-loop marking

The sieve Phase 1 inner block loop was rewritten to process **8 bit-marks per
iteration** using precomputed byte-offset/mask tables (Kim Walisch / danaj
style).  For each sieve prime `p`, the miner precomputes 8 `(offset, mask)`
pairs once before the loop; the main loop performs 8 `OR` operations and a
single pointer advance `s += p` — with no per-mark division.  A scalar tail
handles the remaining `< 8` marks.

Benchmarked on NVIDIA GeForce RTX 3060 at shift 64
(`--sieve-primes 1500000 --sieve-size 67108864 --cuda --fast-euler`):

| | Before | After | Change |
|---|---|---|---|
| Sieve throughput | 562 M/s | 633 M/s | **+12.6%** |
| Primes/s (pps) | 737 K | 924 K | **+25.4%** |

CPU-only runs show no measurable gain because Fermat testing dominates the
pipeline in CPU mode.  The improvement is visible when CUDA offloads Fermat
and exposes the sieve as the pipeline bottleneck.

### `--fast-euler` recommended with `--cuda`

In GPU (smart-scan) mode the sieve and GPU phases are CPU-free, but the
edge-probe phase between Phase 1 and Phase 2 calls CPU `bn_candidate_is_prime`
(up to 6 calls per gap region, left + right boundary).  `--fast-euler` halves
the cost of those calls by using a base-2 Euler–Plumb exponent `(n-1)/2`
instead of the full `(n-1)` Fermat exponent.  Without it, pps drops by ~29%
at typical shift-64 settings.

Recommended command line for RTX 3060, shift 64:

```sh
./gap_miner -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  -s 64 --threads 4 --fast-euler \
  --sieve-size 67108864 --sieve-primes 1500000 --cuda
```

### Stats output update

- The advisory `merit_trend(k=1): paper~... evt~... target_delta=...` segment
  has been removed from periodic STATS output.
- Logging writes are now synchronized across threads to prevent interleaved
  STATS and merit-event lines in console/log output.

### Benchmark script updates

- `scripts/bench_sieve_matrix.sh` was updated to improve default handling,
  environment overrides, and TSV extraction (including tested-per-second from
  current STATS formatting).
- Use this script for repeatable sieve/throughput matrices; keep generated
  `logs/` data out of commits unless you explicitly want to version benchmarks.

### With CUDA GPU acceleration

Add `--cuda` to offload Fermat testing to the GPU.  Works on the normal
sieve path and CRT **monolithic** mode.  In non-CRT mode, each sieve
window already produces thousands of candidates, so they are sent directly
to the GPU without accumulation.  In CRT monolithic mode, a batch
accumulator collects candidates from multiple windows and flushes them to
the GPU in large batches (default 4096) for efficient SM utilization.

> **Note:** CRT producer-consumer can use GPU consumers when you opt in with
> `--crt-gpu-consumer` (and `--cuda`).  Without `--crt-gpu-consumer`,
> producer-consumer remains CPU consumer mode and `--cuda` +
> `--fermat-threads` triggers the idle-GPU warning.

OpenCL scaffolding can be selected with `--opencl [DEV,...]` and
`--opencl-platform N`; this enables the OpenCL Fermat backend.

For high shifts in offline-header mode, pass `--adder-max` explicitly.
Example: `--shift 122 --adder-max 134217728`.

OpenCL single-device example:

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 122 \
  --threads 1 \
  --fast-fermat \
  --opencl 0
```

OpenCL with explicit platform + device:

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 122 \
  --threads 1 \
  --fast-fermat \
  --opencl-platform 0 \
  --opencl 0
```

OpenCL multi-device list:

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 122 \
  --threads 2 \
  --fast-fermat \
  --opencl 0,1
```

OpenCL equivalent of a CUDA baseline-style run (`shift=122`, non-CRT):

```sh
./bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  -s 122 \
  --threads 2 \
  --opencl 0 \
  --fast-fermat \
  --sieve-primes 100000
```

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 25 \
  --threads 2 \
  --fast-fermat \
  --cuda
```

CUDA with CRT gap-solver in monolithic mode (shift 512):

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 512 \
  --threads 3 \
  --fast-fermat \
  --cuda \
  --crt-file crt/crt_s512_m22.txt
```

> `--cuda` + `--fermat-threads` uses GPU in producer-consumer mode only when
> `--crt-gpu-consumer` is also set; otherwise consumers stay CPU-based.

Tune GPU batch size for larger flushes:

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 512 \
  --threads 2 \
  --fast-fermat \
  --cuda \
  --gpu-batch 8192 \
  --crt-file crt/crt_s512_m22.txt
```

Select a specific GPU device (0-based index):

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 25 --threads 4 --fast-fermat \
  --cuda 1
```

Multiple GPUs (round-robin dispatch across threads):

```sh
bin/gap_miner \
  -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  --shift 512 --threads 4 --fast-fermat \
  --cuda 0,1 \
  --crt-file crt/crt_s512_m22.txt
```

### With stratum pool

Connect to a Gapcoin stratum pool instead of a local node:

```sh
bin/gap_miner \
  --stratum pool.example.com:2434 \
  -u worker.1 --pass x \
  --shift 25 \
  --threads 4 \
  --fast-fermat
```

Stratum + CUDA:

```sh
bin/gap_miner \
  --stratum pool.example.com:2434 \
  -u worker.1 --pass x \
  --shift 25 \
  --threads 4 \
  --fast-fermat \
  --cuda
```

## Recent changes (April 2026)

### Async GPU Fermat pipeline (CUDA)

The CUDA Fermat path was rearchitected to eliminate `cudaStreamSynchronize`
as a ~47% CPU hotspot and to prevent candidates from being silently discarded
when the GPU was busy.

- **Async collector thread** — a dedicated `gpu_fermat_collector()` thread
  polls completed GPU slots via `cudaEventQuery` in a tight spin loop and
  signals results via a per-slot `pthread_cond_t`.  GPU completion is fully
  decoupled from the mining worker threads; workers never stall waiting for
  the GPU to finish.
- **Blocking submit** — `gpu_fermat_submit()` now blocks on
  `pthread_cond_wait()` when all GPU slots are busy instead of returning `-1`
  and silently dropping candidates.  Under peak GPU load, workers queue
  normally; no primality work is lost.
- **Broadcast wakeup** — the collector uses `pthread_cond_broadcast()` (not
  `pthread_cond_signal()`) to wake all waiters when a slot is freed.  Using
  `signal` caused a latent deadlock: a "collect waiter" could steal the wakeup
  intended for a "submit waiter", leaving the submit path permanently stuck.
- **GMP CPU fallbacks removed** — `bn_candidate_is_prime()` was called as a
  CPU fallback on every returned candidate inside `gpu_batch_filter()`.
  Removing this path dropped GMP CPU usage from **73.59% → 3.29%** of total
  CPU time, restoring GPU-based throughput to its intended level.

Before this fix the miner appeared to run but accepted very few (or zero)
blocks because the GPU results were re-tested serially on the CPU, defeating
the entire purpose of GPU offload.

Recommended command for RTX 3060, shift=160:

```sh
./bin/gap_miner -o 127.0.0.1 -p 31397 -u USER --pass PASS \
  -s 160 --threads 4 --fast-fermat \
  --sieve-size 33554432 --sieve-primes 1800000 \
  --sample-stride 5 --cuda
```

Typical output: ~353 M sieved/s, ~311k pps, est ~10m (merit target ~20.5).

### `--sample-stride` tuning with `--cuda`

The `--sample-stride K` parameter controls the two-phase GPU smart-scan for
the non-CRT path.  Choosing K well keeps the CPU sieve and GPU Fermat pipeline
overlapped:

- **Phase 1** tests every K-th sieve survivor (~cnt/K candidates) in a small
  fast GPU batch (~1–2 ms return time).
- **Phase 2** retests all survivors that fall inside the gap regions identified
  by Phase 1.

At **shift=160** with ~140k survivors per window, **K=5 is optimal**: Phase-1
batches of ~22k complete in ~1–2 ms, allowing the CPU to sieve the next window
while the GPU processes the current one.  The default K=8 produces smaller
Phase-1 batches with less gap-region coverage; K=1 disables smart-scan and
sends a single ~110k-candidate batch that stalls the sieve for ~8–10 ms per
window, degrading throughput.

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
primes (default 900 000).  A precomputed **presieve template** eliminates
multiples of the first 6 odd primes (3–17) via a single byte-level tile
copy, then the remaining sieve primes are applied on top.  The sieve
reuses a thread-local buffer for primes and their logarithms to avoid
repeated allocation overhead.

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
- `--mr-verify` -- opt-in Miller-Rabin base-3 verification of gap boundary
  primes.  When a qualifying gap is found, both boundary primes are re-tested
  with a single-round MR base-3 check before submission.  Catches rare Fermat
  base-2 pseudoprimes (Poulet numbers) with negligible overhead (~2-4 MR calls
  per qualifying gap instead of verifying every Fermat survivor).
- `--no-primality` -- skip testing entirely (benchmarking / sieve trust).

When built with `WITH_CUDA=1` and run with `--cuda`, the miner offloads
Fermat testing to the GPU on these paths:

- **CRT gap-solver (monolithic)** — A **batch accumulator** collects
  candidates from multiple CRT windows into a single large buffer (default
  4096 candidates, configurable via `--gpu-batch N`) before flushing to the
  GPU.  This dramatically improves GPU SM utilization — instead of launching
  a kernel with ~38 candidates per window (wasting 99% of SMs), the GPU
  receives thousands of candidates per launch.
- **Normal sieve (non-CRT)** — Each sieve window already produces thousands
  of candidates, so they are sent directly to the GPU via `gpu_batch_filter`
  without accumulation.  A dedicated `gpu_fermat_collector()` thread polls
  completed GPU slots via `cudaEventQuery` and signals results via per-slot
  `pthread_cond_t`; worker threads submit to available slots and block only
  when all slots are busy, ensuring no candidates are discarded under load.
  The GPU path uses two-phase smart-scan (Phase 1 sampling + Phase 2
  verification).  The CPU path uses a backward-scan algorithm that jumps
  ahead by the target gap and scans backward for primes, achieving ~8× fewer
  Fermat tests than full-test.  Cooperative Fermat is disabled
  (`coop.active=0`) so the helper thread only sieves the next window and does
  not waste CPU on redundant Fermat work.
- **CRT producer-consumer (`--fermat-threads N`)** — CPU consumers by default.
  With `--crt-gpu-consumer` + `--cuda`, consumer windows are routed through the
  CRT GPU accumulator path (experimental).  Without `--crt-gpu-consumer`,
  consumers remain CPU backward-scan (`crt_bkscan_and_submit`) and
  `--cuda` + `--fermat-threads` emits the idle-GPU warning.

Each candidate is exported as a configurable-width number (default 1024-bit
/ 16×64-bit limbs); the CUDA kernel performs Montgomery-form modular
exponentiation (`2^(n-1) mod n`) on all candidates in parallel.  Survivors
(probable primes) are returned to the CPU for gap scanning.  This is
transparent — `--fast-fermat` is implied when using `--cuda`.

Multiple GPUs are supported via `--cuda 0,1,2` — worker threads are assigned
to GPUs round-robin, each with an independent CUDA context and accumulator.

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

When `--cuda` is active, cooperative Fermat is bypassed entirely: the helper
thread only sieves the next window and does not assist with primality
testing, since all Fermat work is offloaded to the GPU.

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
   for 15 primes at shift 64, or 2×3×…×379 ≈ 2^510 for 75 primes at shift
   512).
2. **CRT alignment** — solve `nAdd ≡ -(base + o_i) (mod p_i)` for each CRT
   prime `p_i` with offset `o_i`, combining via incremental CRT.  This
   positions each prime's composites inside the gap region starting at
   `base + nAdd`.
3. **Iterate** `nAdd = nAdd0, nAdd0 + primorial, …` up to `adder_max`.
   At shift 64 with 15 primes, primorial ≈ 2^59 gives only **~15 candidate
   nAdd values** per hash.  At shift 512 with 75 primes, primorial ≈ 2^510
   ≈ 2^shift so there is effectively **one candidate per hash**.
4. **Sieve** a small forward region sized by the CRT gap-window policy (`--crt-gap-scan`, default `fixed`) using ~1M small primes, then **Fermat-test all survivors** (~683 at shift 512 in a representative setup) to find consecutive primes and measure the gap.
5. **Report** — qualifying gaps (merit ≥ target) are passed to the standard
   `scan_candidates` path for block assembly and submission.

CRT gap-window policies (`--crt-gap-scan MODE`, solver text files only):

- **fixed** (default): `max(2*gap_target,10000)`
- **original**: `ceil(target*ln(start))`, clamped to `[8,gap_target]`
- **original-floor**: `max(original,FLOOR)`, where `FLOOR` comes from
  `--crt-gap-scan-floor N` (default 10000)

Inline floor assignment is also accepted:
`--crt-gap-scan original-floor=12000`.

Accuracy-first CRT runs can use `--crt-precision`.  In solver mode this
switches CRT primality checks to stricter probable-prime rounds.

The normal large windowed sieve is bypassed, so `--sieve-size` and
`--sample-stride` have no effect in CRT mode.  `--sieve-primes` **is**
used — it controls how many small primes are applied to the gap-check sieve.

- **Monolithic mode** (no `--fermat-threads`): `--sieve-primes` is
  automatically capped to `gap_scan × 19` (where `gap_scan` is derived from
  the selected CRT gap-window mode; in default fixed mode this is
  ≈ 190 000 for shift 64, merit 22) since there is no gaplist to tune and
  primes beyond this add cost with no benefit.
- **Producer-consumer mode** (`--fermat-threads N`): `--sieve-primes` is
  passed through as-is for manual tuning via the gaplist saw-tooth (see
  below).

The relevant flags are `--shift`, `--threads`, `--fast-fermat`, `--target`,
`--crt-file`, `--crt-gap-scan`, `--crt-gap-scan-floor`,
`--fermat-threads`, and `--sieve-primes`.

#### Producer-consumer mode (gaplist)

With `--fermat-threads N` (or `-d N`, compatible with GapMiner), the miner
splits CRT work into a **producer-consumer** pipeline:

- **Sieve producer threads** iterate nonces, CRT-align, and sieve each
  window.  Completed windows (with their survivor lists) are pushed onto
  a priority **min-heap** (the "gaplist"), keyed by survivor count —
  windows with fewer survivors are tested first.
- **Fermat consumer threads** pop windows from the gaplist and Fermat-test
  all survivors to find and report qualifying gaps.

The gaplist has a bounded capacity of 4 096 entries.  When full, the sieve
producer blocks until consumers free space.  The stats line shows the
current gaplist depth (e.g. `gaplist=142`).

**Default mode: monolithic.**  All threads independently sieve and
Fermat-test their own CRT windows.  This is optimal at high shifts
(≥ 256) where sieving is <0.1% of the work — dedicating a thread to
sieving wastes CPU.

To enable producer-consumer mode, pass `--fermat-threads N` explicitly
(e.g. `--fermat-threads 14` with 16 threads = 2 sieve + 14 fermat).
This may help at low shifts (< 128) where the sieve takes longer.

**When to use producer-consumer vs monolithic:**

| Scenario | Recommendation |
|----------|---------------|
| High shift (≥ 256), any thread count | Monolithic (default) — sieve is <1ms, every thread should do Fermat work |
| Low shift (< 128), many threads | Producer-consumer (`--fermat-threads N`) — sieve takes longer, benefits from dedicated threads |
| Using `--cuda` with CRT | Prefer monolithic.  Producer-consumer GPU is experimental and requires `--crt-gpu-consumer` |

**Tuning `--sieve-primes` in producer-consumer mode** (GapMiner dev recommendation):

The ideal gaplist saw-tooth: creeps up to 2000–3000 then drops to ~100,
repeating.  Adjust `--sieve-primes` by ±1000 increments, wait 1 minute,
observe `gaplist` in STATS.

- `gaplist` stays low (< 100): sieve is too slow → reduce `--sieve-primes`
  or decrease `--fermat-threads`
- `gaplist` pegs near 4096: sieve is too fast → increase `--sieve-primes`
  or increase `--fermat-threads`

GapMiner starting point for shift 64: `-t 4 -d 3 -i 13000`
(4 threads, 3 fermat threads, 13000 sieve-primes).

Two CRT file formats are supported:

| Format | Extension | Mode | Description |
|--------|-----------|------|-------------|
| Legacy binary | `.bin` | `CRT_MODE_TEMPLATE` | Bitmap tiling, ≤10 primes (old format) |
| Text (gen_crt) | `.txt` | `CRT_MODE_SOLVER` | Prime:offset pairs, CRT-aligned mining |

### Gap scanning strategies

Controlled by `--sample-stride K` (default 8; set to 1 to disable).
Used in the normal (non-CRT) mining path.

#### CPU: Backward-scan (default)

Inspired by the original GapMiner's skip-ahead algorithm from
[Gapcoin-PoWCore](https://github.com/gapcoin-project/Gapcoin-PoWCore).
Instead of testing every sieve survivor, the miner jumps ahead by
`needed_gap = target × log(base)` and scans **backward** for the nearest
prime:

1. **Find first prime** — forward-scan through `pr[]` (sieve survivors)
   until a Fermat-prime is found.  This becomes `start`.
2. **Jump ahead** — binary-search `pr[]` for the first survivor beyond
   `start + needed_gap`.
3. **Scan backward** — walk backward through survivors from that point
   toward `start`, Fermat-testing each one.
   - **Prime found →** gap from `start` to here is < `needed_gap`.
     Update `start` to this prime and jump ahead again (step 2).
   - **No prime found →** the entire `[start, start + needed_gap]`
     interval has been tested.  This IS a qualifying gap.
4. **Forward search** — when a gap is found, scan forward from
   `start + needed_gap` to find the actual next prime and determine
   the true gap size.  If `merit ≥ target`, submit via RPC.
5. **Repeat** until the end of the sieve window.

**Why it's fast:** in dense prime clusters (which is most of the window),
the backward scan finds a prime after only ~8 Fermat tests on average
(1 / prime_density of sieve survivors).  It then jumps ahead by thousands
of positions, skipping all the survivors in between.  Only in actual
qualifying-gap regions does every survivor get tested.

**Correctness guarantee:** every sieve survivor inside a potential gap
region IS tested — no false gaps are possible.  Unlike the old two-phase
smart-scan, there is no sampling step that can miss primes.

**Threading:** the backward scan is serial (each step depends on the
previous result).  The helper thread sieves the next window in parallel;
cooperative Fermat is disabled for this path.  At shift ≤ 64, sieve time
and backward-scan time are closely balanced (~1.1s each), so the pipeline
overlap is already near-optimal.

**Est estimation:** the backward scan tests only ~5% of sieve survivors,
but the Cramér–Granville formula requires the count of ALL consecutive
prime pairs in the window.  The miner extrapolates: `est_pairs =
total_survivors × (primes_found / tests_run) − 1`.  This produces accurate
est values (~22 min at shift 43) instead of the inflated 7+ hours that
result from counting only backward-scan jumps as pairs.

**Sampling pass:** the first 200 sieve survivors of each window are
fully Fermat-tested (regardless of backward-scan logic) to track verified
consecutive-prime gaps for the `best=` display.  Cost: ~3% overhead.

#### GPU: Two-phase smart-scan

When CUDA is active (`--cuda`), the GPU path still uses the two-phase
approach: Phase 1 samples every Kth survivor via GPU batch Fermat,
identifies candidate gap regions, edge-probes to eliminate false positives,
then Phase 2 verifies all survivors inside surviving regions.  A gap-verify
safety net (`bn_candidate_is_prime` + 25-round MR) catches any remaining
false gaps before submission.

#### Full test (`--sample-stride 1`)

Disables both backward-scan and smart-scan.  Every sieve survivor is
Fermat-tested via cooperative Fermat (worker + helper).  Slowest but
simplest path; mainly useful for debugging.

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

### Backward-scan impact (CPU, shift=43, target≈20.89, 2 threads)

| Mode | Description | Fermat tests | Relative |
|------|------------|-------------|----------|
| Full (`--sample-stride 1`) | Test every survivor | 100% | 1.0× |
| Backward-scan (default) | Jump ahead + scan back | **~12%** | **~8×** |

The backward-scan algorithm finds a prime within ~8 backward Fermat tests
on average, then jumps ahead by the full target gap — skipping thousands
of survivors in dense prime clusters.  Only qualifying-gap regions get
fully tested.  No false gaps are possible (every survivor in the gap
window is tested).

### CUDA GPU Fermat testing

Benchmarked on an NVIDIA GeForce RTX 3060 at shift 512
(`--shift 512 --fast-fermat --cuda --threads 2 --sieve-primes 150000`):

#### CRT gap-solver (`--crt-file crt/crt_s512_m22.txt`)

| Mode | Threads | Fermat tests/s | Est | Relative |
|------|---------|---------------|-----|----------|
| CPU only | 3 | 47 K/s | 5.0d | 1.0× |
| GPU (no accumulator) | 3 | 47 K/s | 5.0d | 1.0× |
| GPU + batch accumulator | 2 | 125 K/s | 1.8d | **2.6×** |

Without the accumulator, each GPU kernel launch received only ~38 candidates
per CRT window — far too few to saturate 3584 CUDA cores.  The batch
accumulator collects ~3000+ candidates across windows before flushing,
achieving full SM utilization.

#### Non-CRT (normal sieve + smart-scan)

| Mode | Shift | Threads | sieve/s | pps | Est | Notes |
|------|-------|---------|---------|-----|-----|-------|
| GPU (non-CRT), before async fix | 512 | 2 | — | 350 K/s | 5.1h | `cudaStreamSynchronize` hotspot |
| GPU (non-CRT), async collector | 512 | 2 | — | 350 K/s | 5.1h | **2.8×** vs CRT GPU |
| GPU (non-CRT), async collector | 160 | 4 | ~353 M/s | ~311 K/s | ~10m | RTX 3060, `--sieve-primes 1800000 --sample-stride 5` |

At shift 512, the non-CRT path with GPU is **dramatically faster** than CRT:
each 33M sieve window produces thousands of candidates, fully saturating the
GPU without needing an accumulator.  The CRT path is limited by its tiny
per-window candidate count (~38), even with batching across windows.

At shift 160 with `--sieve-primes 1800000 --sample-stride 5`, the async
collector keeps the CPU sieve and GPU Phase-1 batches overlapped, achieving
~311k pps with a ~10m estimated time-to-block at merit target ~20.5.

The `gpu_batch=N` stat in the output shows the average candidates per GPU
flush (CRT mode only).  Larger values indicate better GPU utilization.

The GPU kernel uses configurable-width Montgomery multiplication (default
16×64-bit limbs / 1024-bit, CIOS form) to compute `2^(n-1) mod n` for
candidates in parallel.  In CRT mode, a thread-local accumulator buffers
candidates across windows and flushes them to the GPU in batches of 4096+
(configurable via `--gpu-batch`).  In non-CRT mode, each sieve window
already produces thousands of candidates, so they are sent directly to the
GPU without accumulation.  Only probable primes are returned to the CPU for
gap scanning.  Multiple GPUs are supported via `--cuda 0,1`.

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

6. **Backward-scan gap mining** (CPU) -- Inspired by the original GapMiner's
   skip-ahead algorithm.  Extracted into a standalone `backward_scan_segment()`
   function that returns a result struct (primes found, tests run, best
   merit, qualifying gap pairs).  Jumps ahead by `needed_gap` and scans
   backward; finds primes in ~8 tests on average, then skips thousands
   of survivors in dense clusters.  ~8× fewer Fermat tests than full-test,
   with zero false gaps.  A 200-survivor sampling pass at the start of
   each window provides gradual best-merit tracking.  The est formula
   extrapolates full-window prime pairs from the Fermat pass rate for
   accurate time-to-block estimates.
   GPU path retains two-phase smart-scan with a gap-verify safety net.

7. **CRT gap-solver mining** -- Chinese Remainder Theorem alignment
   constrains which nAdd values to test, reducing the search space to
   only primorial-aligned candidates.  Instead of sieving millions of
   values per window, only ~15 CRT candidates are tested per hash (at
   shift 64 / 15 primes).  Each candidate triggers a small targeted
   gap-check sieve (~23K positions) with ~1M primes, then all survivors
   are Fermat-tested.  Optional producer-consumer mode (gaplist)
   separates sieving from Fermat testing across threads.

8. **-O3 + LTO** -- Aggressive compiler optimization with link-time
   optimization enables cross-module inlining and auto-vectorization.

9. **Incremental atomic stats** -- `stats_tested` counter updated every
   4 096 candidates (not per-candidate, not per-window).  With large sieve
   windows (33M) this keeps the display moving smoothly instead of freezing
   for 20+ seconds between window boundaries.

10. **CUDA GPU Fermat** -- Batch Fermat primality testing on NVIDIA GPUs
    using a configurable-width Montgomery multiplication kernel (CIOS form,
    default 1024-bit / 16 limbs).  Works on **all mining paths**: CRT
    gap-solver uses a thread-local **batch accumulator** to collect
    candidates from multiple windows (~38 survivors each) into a single
    large GPU buffer (default 4096, `--gpu-batch N`), transforming tiny
    per-window batches into GPU-filling workloads — 2.6× speedup on an
    RTX 3060 at shift 512.  Non-CRT paths (full-test and smart-scan)
    send entire sieve windows directly to the GPU.  A dedicated
    `gpu_fermat_collector()` thread polls completed slots via
    `cudaEventQuery` and signals per-slot `pthread_cond_t`; workers block
    only when all slots are full, so no candidates are ever dropped.
    CPU GMP fallbacks inside `gpu_batch_filter()` were removed, cutting
    GMP CPU overhead from 73.59% → 3.29%.  Cooperative Fermat is disabled
    when GPU is active so the helper thread only sieves.
    Multiple GPUs supported via `--cuda 0,1` with round-robin dispatch.

11. **Presieve template** -- A 249 KB precomputed bitmap marks all
    multiples of {3, 5, 7, 11, 13, 17} (product = 510 510, bit-period
    255 255).  The template stores 8 bit-periods so that byte-level
    `memcpy` tiling wraps with zero bit-drift.  Replaces 6 per-prime
    sieve passes with a single `memcpy` + shift, cutting sieve setup
    time for each window.

12. **8-at-a-time sieve marking** -- The Phase 1 bit-setting inner loop
    (adapted from Kim Walisch's `primesieve` / danaj's `Math::Prime::Util`
    CROSS_INDEX technique) precomputes 8 `(byte-offset, bitmask)` pairs
    per sieve prime using `q = p/8` and `r = p%8`.  The main loop fires
    8 `OR` operations and advances the base pointer by `p` bytes once,
    with no per-mark division.  A scalar tail cleans up `< 8` remaining
    marks.  On GPU-bottleneck workloads (CUDA, shift 64) this yields
    **+12.6% sieve throughput** and **+25.4% pps** (RTX 3060
    benchmark).

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
| `--sieve-primes P`    | 900000        | Number of small primes used for sieving.  The actual prime value limit is auto-computed from the count via PNT upper bound (900K → primes up to ~15.4M). Used in both normal and CRT modes. |
| `--target T`          | *(node bits)* | Minimum merit `gap/log(p)` to build a block |
| `--scan-merit M`      | auto (`--target`) | Non-CRT CPU smart-scan threshold.  Controls stride/jump distance for scanning while submission threshold remains `--target` (or network merit).  Ignored in CRT mode and generally non-beneficial on CUDA/OpenCL paths. |
| `--threads N`         | 1             | Worker threads; each thread runs the full sieve + primality (Fermat/Miller-Rabin) + gap-scan pipeline over its own disjoint slice of the adder range (`tid, tid+N, tid+2N, …`) |
| `--rpc-url URL`       | --            | JSON-RPC endpoint of `gapcoind` |
| `--rpc-user USER`     | --            | RPC username |
| `--rpc-pass PASS`     | --            | RPC password |
| `--rpc-method METH`   | `getwork`     | Submission method |
| `--rpc-rate MS`       | 0             | Minimum ms between submissions |
| `--rpc-poll-ms MS`    | 1000          | Tip poll interval for `getbestblockhash`; lower reduces stale window |
| `--rpc-retries N`     | 3             | Retry attempts on failure |
| `--rpc-sign-key KEY`  | --            | HMAC key to sign payloads |
| `--log-file FILE`     | --            | Append all log messages to FILE |
| `--fast-fermat`       | off           | Fast single-base Fermat primality test |
| `--fast-euler`        | off           | Fast Euler-Plumb base-2 primality path (CPU).  Mutually exclusive with `--fast-fermat`. |
| `--mr-rounds N`       | 2             | Miller-Rabin rounds for `mpz_probab_prime_p` (default path, not `--fast-fermat`).  Old default was 10; 2 rounds gives false-positive rate < 2^-128 for sieve-filtered candidates. |
| `--sample-stride K`   | 8             | Controls gap scanning strategy.  K > 1 enables backward-scan (CPU) or two-phase smart-scan (GPU).  Set to 1 for full-test (all survivors tested). |
| `--partial-sieve-auto` / `--partial-sieve` | off | Adaptive non-CRT sieve-prime limiting.  Adjusts sieve depth periodically based on runtime behavior. |
| `--adaptive-presieve` | off           | Adaptive non-CRT presieve window skipping for dense windows after presieve. |
| `--wheel-sieve N`     | 0 (disabled)  | Select wheel-presieve backend for non-CRT runs.  Supported values: `30`, `210`, `2310`, `30030`, `510510`, `9699690`. |
| `-e` / `--extra-verbose` | off       | Write detailed `--partial-sieve-auto` adjustments to the log file only. |
| `--stats-verbose`     | off           | Include detailed CRT phase telemetry (`cramer`, `phase1`, accumulator histograms, score calibration) in periodic STATS output.  Default output stays concise. |
| `--crt-file FILE`     | --            | Load a CRT sieve file (binary `.bin` or text `.txt`).  Text files enable CRT-aligned mining; binary files enable template tiling. |
| `--fermat-threads N` / `-d N` | 0 (monolithic) | Number of Fermat consumer threads for CRT producer-consumer mode.  Default `0` = monolithic (all threads sieve+fermat independently).  Set to `N` to enable producer-consumer with `threads - N` sieve and `N` fermat threads.  Consumers are CPU by default unless `--crt-gpu-consumer` is also set with `--cuda`. |
| `--crt-gpu-consumer` | off | Experimental CRT producer-consumer mode: route consumer windows through the GPU accumulator path when `--cuda` is active. |
| `--crt-gap-scan MODE` | `fixed` | CRT solver gap-window policy for text `--crt-file` runs.  `fixed=max(2*gap_target,10000)`, `original=ceil(target*ln(start))` (clamped to `[8,gap_target]`), `original-floor=max(original,FLOOR)`.  Aliases: `orig`, `dynamic`, `orig-floor`, `dynamic-floor`, `hybrid`. |
| `--crt-gap-scan-floor N` | 10000 | Floor used by `--crt-gap-scan original-floor`.  Can also be set inline via `--crt-gap-scan original-floor=N`.  Ignored by other CRT gap-scan modes. |
| `--crt-gap-scan-adaptive` | off | Adapt CRT runtime gap-scan window from heap-pressure telemetry (`drop%`, fill, wait) during solver execution. |
| `--crt-precision` / `--no-crt-precision` | off | Accuracy-first CRT solver mode: uses stricter probable-prime checks in CRT paths. |
| `--crt-precision-rounds N` | 8 | Number of probable-prime rounds used by `--crt-precision` strict CRT checks (minimum 2). |
| `--crt-auto-split`    | off           | Enable pass-level adaptive sieve/fermat thread split in CRT solver producer-consumer mode. |
| `--heap N`            | 4096          | Maximum number of pending CRT windows in the producer-consumer gaplist heap.  Only relevant when `--fermat-threads N` is active.  Larger values allow the sieve producers to run further ahead of the Fermat consumers; useful if producers are significantly faster than consumers. |
| `--crt-accum-soft-cap N` | 24576 | CRT GPU accumulator soft preflush cap (candidates).  Used by accumulator backpressure policy. |
| `--crt-accum-hard-cap N` | 65536 | CRT GPU accumulator hard preflush cap (candidates).  Used by accumulator backpressure policy. |
| `--crt-accum-backpressure` / `--no-crt-accum-backpressure` | on | Enable/disable CRT GPU accumulator preflush/backpressure controls. |
| `--crt-gpu-batch-adaptive` / `--no-crt-gpu-batch-adaptive` | off | Enable/disable adaptive CRT GPU accumulator threshold tuning from flush/collect telemetry. |
| `--crt-gpu-batch-min N` | 512 | Lower bound used by adaptive CRT GPU batch threshold tuning. |
| `--crt-gpu-batch-max N` | 32768 | Upper bound used by adaptive CRT GPU batch threshold tuning. |
| `--mr-verify`         | off           | Verify gap boundary primes with a Miller-Rabin base-3 check before submission.  Catches Fermat base-2 pseudoprimes with negligible overhead. |
| `--no-primality`      | off           | Skip primality testing entirely |
| `--build-only`        | off           | Fetch template and build one block, then exit |
| `--no-opreturn`       | off           | Omit OP_RETURN from coinbase |
| `--force-solution`    | off           | Treat every candidate as valid (debug) |
| `--keep-going`        | on            | Continue after a found block (default) |
| `--stop-after-block`  | off           | Exit after submitting a valid block |
| `--selftest`          | off           | Run internal prime checks and exit |
| `--p P --q Q`         | --            | Force primes for `--build-only` runs |
| `--cuda [DEV,...]`    | off           | Enable CUDA GPU Fermat testing (requires `WITH_CUDA=1` build).  Optional comma-separated `DEV` list selects GPU devices (e.g. `--cuda 0,1`).  Up to 8 GPUs, round-robin dispatch. |
| `--opencl [DEV,...]`  | off           | Enable OpenCL GPU Fermat path (requires `WITH_OPENCL=1` build).  Optional device list selects GPU devices (e.g. `--opencl 0,1`).  Do not combine with `--cuda` in one run. |
| `--opencl-platform N` | 0             | OpenCL platform index used with `--opencl`. |
| `--gpu-batch N`       | 4096          | Accumulate N candidates across CRT windows before flushing to GPU (CRT mode only; non-CRT paths send full sieve windows directly).  Larger values improve GPU utilization at the cost of slightly delayed gap processing.  When unset in CRT+GPU mode, shift-band defaults may apply (`2048/4096/8192/16384`). |
| `--stratum HOST:PORT` | --            | Connect to a Gapcoin stratum pool instead of using RPC/GBT (requires `WITH_RPC=1` build). |
| `-u` / `--user`       | --            | Alias for `--rpc-user` |
| `--pass`              | --            | Alias for `--rpc-pass` |
| `-o HOST` / `-p PORT` | --            | Shorthand for `--rpc-url http://HOST:PORT/` |

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
STATS: elapsed=30.0s  sieved=5502926848 (183400328/s)  tested=8665707 (288809/s)  primes=1244781 (14.4%)  gaps=0 (0.000/s)  built=0  submitted=0  accepted=0  prob=8.74e-10/pair  est=22.4m (target=20.86)  best=9.77 (gap=2022)
```

| Field | Meaning |
|-------|---------|
| `sieved` | Odd candidates eliminated by the segmented sieve |
| `tested` | Primality tests (Fermat / Miller-Rabin) actually run |
| `primes` | Candidates that passed primality testing (with Fermat pass rate %) |
| `gaps` | Gaps found whose merit ≥ `--target` |
| `built` | Full blocks assembled from a GBT template after a qualifying gap |
| `submitted` | Blocks whose header hash also met the network `bits` difficulty and were sent to the node |
| `accepted` | Node confirmed the block |
| `prob` | Per-pair probability of a qualifying gap (`e^(-target)`, Cramér–Granville heuristic) |
| `est` | Estimated time to find a qualifying gap at current rate.  For backward-scan, pairs/s is extrapolated from the Fermat pass rate (`primes / tested × total_survivors`), not counted directly — since the backward scan only tests ~5% of survivors, the extrapolation estimates how many consecutive prime pairs the full window contains. |
| `best` | Best verified gap merit seen so far (from the sampling pass and qualifying-gap forward searches) |
| `gpu_batch` | (CUDA only) Average candidates per GPU flush.  Higher = better GPU utilization.  Absent when not using `--cuda`. |
| `pps` | Primes found per second (actual measured rate = `primes / elapsed`).  Directly comparable to GapMiner's `tests/s` field.  Note: GapMiner's `pps` field is a theoretical CRT-scaled estimate, not the actual measured rate. |
| `gaplist` | (CRT producer-consumer only) Number of sieved windows waiting in the priority heap.  Ideal: saw-tooth oscillating between ~100 and ~3000.  Persistently 0 = fermat threads too fast / sieve-primes too low.  Persistently near 4096 = sieve too fast, add fermat threads or reduce sieve-primes. |

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

`gaps=0` after ~10 minutes at ~300 K tests/s and ~180 M sieved/s is completely
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

## Tuning guide (shift 25–64)

Recommended `--sieve-primes` and `--sieve-size` values for the normal
(non-CRT) sieve path.  These balance sieve throughput against Fermat
testing cost, which grows with candidate bit-size.

| Shift | Bits | adder\_max | Windows @32M | Fermat cost | `--sieve-primes` | `--sieve-size` |
|------:|-----:|-----------:|-------------:|:-----------:|------------------:|---------------:|
| 25 | 281 | 33M | 1 | ~50 µs | **900K** (default) | **33M** (default) |
| 30 | 286 | 1B | 32 | ~60 µs | **900K** | **33M** |
| 35 | 291 | 34B | 1K | ~70 µs | **900K** | **33M** |
| 40 | 296 | 1T | 33K | ~85 µs | **1M** | **33M** |
| 45 | 301 | 35T | 1M | ~100 µs | **1M** | **67M** |
| 50 | 306 | 1P | 33M | ~120 µs | **1.2M** | **67M** |
| 55 | 311 | 36P | 1B | ~140 µs | **1.5M** | **67M** |
| 60 | 316 | 1E | 33B | ~170 µs | **1.5M** | **134M** |
| 64 | 320 | 18E | 549B | ~200 µs | **2M** | **134M** |

**Bits** = 256 + shift (candidate prime size).
**Fermat cost** = approximate wall-time per `mpz_probab_prime_p` call
(2 MR rounds, single core, modern x86-64).

### Rationale

- **Sieve size 33M** (2 MB bitmap): fits L2 cache.  At shift ≤ 40 the
  adder space is small enough that windows are covered quickly.
- **Sieve size 67M** (4 MB): at shift 45+ there are millions of windows.
  Doubling the window halves per-window setup overhead; bitmap still fits
  L3 cache.
- **Sieve size 134M** (8 MB): at shift 60+ there are billions of windows
  per nonce — maximise work per window since you'll never exhaust the
  adder space before a new block arrives.
- **Sieve primes 900K→2M**: each extra prime eliminates ~1 additional
  composite per window.  At 900K the marginal prime is ~15.4M (marks ~1
  position per 32M window).  Going to 2M (primes up to ~34M) is cheap
  and saves expensive Fermat tests.

### Example: shift 50 with sieve tuning

```sh
bin/gap_miner \
  --rpc-url  http://127.0.0.1:31397/ \
  --rpc-user USER \
  --rpc-pass PASS \
  --shift 50 \
  --threads 6 \
  --sieve-primes 1200000 \
  --sieve-size 67000000 \
  --fast-fermat
```

> At shift 50+ the bottleneck is Fermat throughput, not sieve coverage.
> Use GPU (`WITH_CUDA=1`) to offload primality testing when available.

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
