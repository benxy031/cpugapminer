---
description: "Generate a maxgap_scan run plan and exact commands for cpugapminer, including thread-count based slicing, safety checks, output redirection, and resume strategy."
argument-hint: "goal=<continue|range|merit|smoke|parallel> start=<N> [end=<N>] mingap=<G> [threads=<N>] [skip=<S>] [threshold=<T>]"
agent: "agent"
---

Create a practical `maxgap_scan` execution plan from the user's arguments and output exact shell commands.

Use [docs/MAXGAP_SCAN.md](../../docs/MAXGAP_SCAN.md) as the source of truth.

## Parameters

Parse the argument string as key/value pairs.

Required by intent:
- `goal` — one of `continue`, `range`, `merit`, `smoke`, `parallel` (default `continue`)
- `start` — integer start value
- `mingap` — integer minimum reported gap

Optional:
- `end` — integer exclusive end value
- `threads` — number of worker processes/slices (default `1`)
- `skip` — probe step size
- `threshold` — prev-prime trigger
- `checkpoint` — checkpoint file base name
- `progress` — seconds between progress lines

Defaults if omitted:
- `threads=1`
- `skip=1400`
- `threshold=max(5, floor(skip/10))`
- `progress=60`
- `checkpoint=maxgap.ckpt`

## Step 1 - Validate and normalize

1. Validate integer inputs and report all parse errors before proceeding.
2. Enforce:
   - `start >= 2`
   - if `end` is provided, `end > start`
   - `threads >= 1`
   - `mingap > 0`, `skip > 0`, `threshold >= 0`
3. Reliability rule:
   - If `--dual-pass` will be used, recommend `skip < mingap`.
   - If single pass is implied, recommend `skip < mingap/2`.
4. If user-provided `skip` violates the rule, keep it but print a warning.
5. Threading rules:
   - If `threads > 1`, a bounded range is required (`end` must be provided).
   - If `goal=continue` and `threads > 1`, warn and fall back to `threads=1`.

## Step 2 - Build command

Always emit the build command first:

```bash
make maxgap_scan
```

Then generate one or more runnable commands using `bin/maxgap_scan`.

Goal-specific command generation:
- `goal=continue`: open-ended run from `start`, with `--dual-pass`, checkpoint, and separate stdout/stderr logs.
- `goal=range`: bounded run with `--start` and `--end`, with `--dual-pass`. If `threads > 1`, split `[start, end)` into `threads` contiguous slices and emit one explicit command per slice (no background `&`).
- `goal=merit`: compute a suggested `mingap` from merit if `merit=<M>` is present:
  - `suggested_mingap = floor(M * ln(start))`
  - If both `merit` and `mingap` are provided, show both and prefer explicit `mingap`.
- `goal=smoke`: short bounded run; if `end` missing, set `end = start + 50000`; set `progress=0` unless user overrides. If `threads > 1`, split into slices like `goal=range`.
- `goal=parallel`: split `[start, end)` into `threads` contiguous slices and generate one explicit command per slice (no background `&`), with per-slice checkpoint/output files.

For all non-smoke goals, include:
- `--skip <skip>`
- `--threshold <threshold>`
- `--mingap <mingap>`
- `--dual-pass`

Unless user asks for `--quiet`, write:
- found gaps to `gaps*.txt` (stdout)
- progress/checkpoint logs to `progress*.log` (stderr)

## Step 3 - Verification checklist

After command generation, provide a short checklist:
1. Confirm `make maxgap_scan` succeeded and `bin/maxgap_scan` exists.
2. For smoke runs near small integers, compare first line against documented expectation when applicable.
3. For long runs, confirm checkpoint file updates every 5 minutes.
4. For candidate records, require independent verification before submission.

## Step 4 - Output format

Return exactly these sections in order:

1. `Parsed Parameters` table
2. `Warnings` (or `None`)
3. `Commands` (fenced `bash` block)
4. `Why These Settings` (3-6 bullets)
5. `Verification Checklist` (numbered list)

Keep the response concise and execution-ready.