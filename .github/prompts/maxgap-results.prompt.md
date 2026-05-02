---
description: "Merge and analyze maxgap_scan result files, then produce a deduplicated ranking and summary report."
argument-hint: "inputs=<glob|csv> [sort=<gap|merit|at>] [top=<N>] [out=<file>]"
agent: "agent"
---

Aggregate `maxgap_scan` output files and return a clean, actionable report.

Use [docs/MAXGAP_SCAN.md](../../docs/MAXGAP_SCAN.md) for output field definitions.

## Parameters

Parse key/value arguments.

Required:
- `inputs` - glob or comma-separated file list (for example `gaps_*.txt`)

Optional:
- `sort` - `gap` (default), `merit`, or `at`
- `top` - number of rows to show (default `25`)
- `out` - optional output path for merged normalized rows

## Step 1 - Load and validate lines

1. Read all matching input files.
2. Accept only lines matching this shape:
   - `gap=<int>  at=<int>  next=<int>  merit=<float>`
3. Reject malformed lines and report counts by file.
4. Validate numerical consistency where possible:
   - `gap == next - at`
   - `gap > 0`, `at >= 2`, `next > at`, `merit > 0`

## Step 2 - Normalize and deduplicate

1. Normalize each valid row to fields: `gap`, `at`, `next`, `merit`, `source_file`.
2. Deduplicate by `(at, next)` keeping one row.
3. If duplicates conflict on `gap` or `merit`, keep the numerically consistent row and report the conflict.

## Step 3 - Rank and summarize

1. Produce sorted rankings:
   - primary ranking by requested `sort`
   - secondary stable tiebreakers: `gap desc`, `merit desc`, `at asc`
2. Compute summary stats:
   - total files read
   - raw lines
   - valid rows
   - malformed rows
   - deduplicated rows
   - max gap row
   - max merit row

## Step 4 - Optional export

If `out` is provided, write normalized deduplicated rows as plain text lines in canonical format:

`gap=<gap> at=<at> next=<next> merit=<merit>`

## Output format

Return exactly these sections:

1. `Input Summary` table
2. `Data Quality` bullet list
3. `Top Results` table (up to `top` rows)
4. `Highlights` (max gap and max merit)
5. `Export` (path written or `None`)

Keep it concise, and include explicit warnings if malformed rows are nonzero.
