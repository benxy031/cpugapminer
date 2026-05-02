---
description: "Create a reproducible maxgap_scan benchmark matrix with estimated runtime and fair comparison settings, including thread-count estimates."
argument-hint: "start=<N> end=<N> mingap=<G> [profiles=fast,balanced,strict] [threads=<N>] [dual=true]"
agent: "agent"
---

Design a fair, repeatable benchmark plan for `bin/maxgap_scan` and output exact commands.

Use [docs/MAXGAP_SCAN.md](../../docs/MAXGAP_SCAN.md) for parameter guidance and throughput assumptions.

## Parameters

Required:
- `start`, `end`, `mingap`

Optional:
- `profiles` comma-separated from `fast`, `balanced`, `strict` (default: all three)
- `threads` for parallel slice estimates (default: detected logical core count if known, else `1`)
- `cores` alias for `threads` (if both are present, prefer `threads`)
- `dual` default `true`
- `progress` default `60`

## Step 1 - Validate scope

1. Enforce `start >= 2`, `end > start`, `mingap > 0`.
2. Compute span: `span = end - start`.
3. If span is very large, suggest a smaller pilot span first.
4. Resolve worker count:
   - if `threads` provided, use it
   - else if `cores` provided, map `cores -> threads`
   - enforce `threads >= 1`

## Step 2 - Build benchmark matrix

Generate profile settings:
- `fast`: `skip=1400`, `threshold=140`
- `balanced`: `skip=min(1000, max(200, floor(mingap*0.75)))`, `threshold=floor(skip/10)`
- `strict`: `skip=max(50, floor(mingap/2)-1)`, `threshold=max(5, floor(skip/10))`

If `dual=true`, include `--dual-pass` for all profiles.

Ensure each profile uses identical range and output naming conventions.

## Step 3 - Runtime estimates

Using doc baseline near 4e18 (`~33 million positions/s` single-core, `SKIP=1400`), provide rough estimates:

1. Estimated single-core time per profile:
   - `time_sec = span / estimated_positions_per_sec`
2. Estimated multi-core time:
   - `time_sec_parallel = time_sec / max(1, threads)`

State assumptions clearly and label all estimates as approximate.

## Step 4 - Commands

Always emit:

```bash
make maxgap_scan
```

Then emit one command per profile in a fenced `bash` block, writing:
- findings to `bench_<profile>.gaps.txt`
- progress/logs to `bench_<profile>.log`

## Output format

Return exactly these sections:

1. `Benchmark Matrix` table
2. `Estimated Runtime` table
3. `Commands` (fenced `bash`)
4. `Fair-Run Checklist` (numbered)

Checklist must include:
1. same `(start, end, mingap)` across profiles
2. identical CPU pinning / system load policy
3. separate output files per profile
4. at least one repeated run for variance
