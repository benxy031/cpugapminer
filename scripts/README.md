# scripts/

## find_records.py

Fetches the prime gap record list and identifies which records are beatable by
cpugapminer at a given shift, along with the recommended `--ctr-merit` value to
pass to `gen_crt`.

### Requirements

Python 3 (stdlib only — no extra packages needed).

### How it works

For each requested shift, the script:

1. Downloads `merits.txt` from <https://primegaps.cloudygo.com/merits.txt>
   (mirror of [prime-gap-list](https://github.com/primegap-list-project/prime-gap-list)).
2. For every record gap, computes the merit Gapcoin *could* achieve at that shift:

   ```
   achievable_merit = gap / ((256 + shift) × ln 2)
   ```

   Gapcoin primes are roughly $2^{256+\text{shift}}$, so ln(p) ≈ (256 + shift) × ln 2.

3. A record is **beatable** if `achievable_merit > current_record_merit` and falls
   inside the practical CRT window (`--min-merit` to `--max-merit`).

4. Ranks beatable records by `improvement = achievable − current` and suggests
   a `--ctr-merit` value that covers the top-50 opportunities.

### Usage

```
python3 scripts/find_records.py [OPTIONS]
```

#### Options

| Option | Default | Description |
|---|---|---|
| `--shift N` | — | Shift to analyze. Repeatable. Defaults to `384 512 640 768 896 1024` if omitted. |
| `--all-shifts` | — | Analyze all supported shifts (64–1024). |
| `--top N` | 20 | Number of top opportunities to print per shift. |
| `--show-all` | — | Print every beatable record, not just the top N. |
| `--summary-only` | — | Print a single compact table; skip per-record listings. |
| `--min-merit M` | 20.0 | Lower bound on achievable merit. |
| `--max-merit M` | 40.0 | Upper bound on achievable merit (caps huge gaps outside any practical CRT window). |
| `--url URL` | primegaps.cloudygo.com | Override the merits.txt download URL. |

### Examples

**Quick overview — which shifts have the most opportunities:**

```bash
python3 scripts/find_records.py --summary-only
```

Sample output:

```
 shift  beatable    <m26    <m27    <m28    <m29   rec_ctr_merit
   384      2184       3     113     520    1133              37
   512      2722       8     178     747    1490              37
   640      3314     128     481    1206    1986              38
   768      3703     309     977    1930    2685              38
   896      4310     575    1537    2688    3492              38
  1024      5216    1165    2242    3441    4325              38
```

Columns:
- **beatable** — total records where Gapcoin achieves higher merit than the current holder
- **\<m26 … \<m29** — subset where the current record merit is below that threshold (easiest to beat)
- **rec_ctr_merit** — recommended `--ctr-merit` value for `gen_crt`

**Detailed report for one shift:**

```bash
python3 scripts/find_records.py --shift 896 --top 10
```

**Multiple shifts:**

```bash
python3 scripts/find_records.py --shift 640 --shift 768 --shift 896
```

**All supported shifts, compact:**

```bash
python3 scripts/find_records.py --all-shifts --summary-only
```

**Focus on the easiest targets (low current-record merit ≤ 28):**

```bash
python3 scripts/find_records.py --shift 1024 --max-merit 28
```

### Interpreting the output

```
rank    gap=31712  current=22.6176 (Jacobsen)  achievable=39.71  improvement=+17.10
```

- **gap** — the prime gap size (even integer)
- **current** — the existing record merit and its discoverer
- **achievable** — merit Gapcoin would earn if it finds the same gap at this shift
- **improvement** — how many merit points above the existing record

### Using rec_ctr_merit with gen_crt

Pass the recommended value as `--ctr-merit` when generating a CRT file:

```bash
./bin/gen_crt --shift 896 --ctr-merit 38 --out crt/crt_s896_m38.txt
```

> **Note:** At shifts ≥ 384 it is safe to drop one extra merit point because the
> wider gap range still covers the vast majority of beatable records:
> `--ctr-merit 37` instead of 38. See `docs/CRT_GENERATION.md` tip #5.

### Supported shifts

`64 68 96 110 128 133 160 192 256 384 512 640 720 768 896 1024`

Only shifts that have a corresponding CRT file in `crt/` are useful in practice.

---

## Record hunting with the miner

### CRT mode

In CRT mode (`--crt-file`) the qualifying gap range is baked into the CRT file
by `--ctr-merit` at generation time. The miner submits every qualifying gap
directly to the Gapcoin node; the node checks PoW against the current network
difficulty. **Do not set `--target` in CRT mode** — it would cause the backward
scan to skip gaps below that merit, wasting coverage the CRT file was built to
produce.

```bash
# Generate a CRT file for record hunting at shift 896 (rec_ctr_merit = 38)
./bin/gen_crt --shift 896 --ctr-merit 38 --out crt/crt_s896_m38.txt

# Mine — no --target needed; CUDA optional
./bin/gap_miner \
  --crt-file crt/crt_s896_m38.txt \
  --shift 896 \
  --threads 8 \
  --cuda 0 \
  --rpc-url http://127.0.0.1:31397 --user myworker --pass x
```

CUDA/GPU works in CRT mode. The GPU handles all Fermat primality tests in
double-buffered batches of 4 096 candidates (`--gpu-batch N` to tune); the CPU
runs the sieve and CRT alignment in parallel.

### Non-CRT mode — `--scan-merit`

In the normal windowed-sieve path the backward-scan jump stride is set by
`--target` (or network difficulty). Setting a high `--target` for record hunting
stops the miner from submitting pool shares.

**`--scan-merit M`** decouples the two:

| Parameter | Controls |
|---|---|
| `--target M` (or network difficulty) | Submit threshold — gaps with merit ≥ M are submitted |
| `--scan-merit M` | Scan stride — the backward scan jumps `M × ln(p)` ahead, skipping dense clusters |

Both CPU (backward scan) and GPU (smart-scan) paths detect and submit any gap that
meets the network difficulty, even when it is shorter than the `--scan-merit` stride.
The stride only controls efficiency (how far ahead to jump); submission is governed
by `--target` or the live network difficulty.

> **Note on `est=`:** the stats estimator calculates expected time at the network
> merit. Record-merit gaps (merit ≥ `--scan-merit`) are much rarer:
> roughly e^(scan_merit − network_merit) × more time.
> At shift 68 with `--scan-merit 30` and network merit 20.5, real record gap
> frequency is ~e^9.5 ≈ 13 000× rarer than `est=` implies.

```bash
# Hunt merit-30 record gaps AND submit all network-qualifying gaps
./bin/gap_miner \
  --shift 68 \
  --threads 5 \
  --cuda 0 \
  --scan-merit 30 \
  --rpc-url http://127.0.0.1:31397 --user myworker --pass x
```

> **Note:** `--scan-merit` is non-CRT only. In CRT mode use `--ctr-merit` when
> generating the CRT file instead.

### Summary

| Goal | Mode | Key flags |
|---|---|---|
| Normal network mining | non-CRT | omit `--scan-merit`; follows network difficulty automatically |
| Record hunting + normal submissions | non-CRT | `--scan-merit 30` — jumps far for records, still submits all network-qualifying gaps |
| Record hunting at large shifts (best option) | CRT | `--crt-merit 38` in `gen_crt`; no `--target` at runtime |
| Submit all gaps (network + records) | CRT | CRT submits every found gap; node accepts what meets current difficulty |
