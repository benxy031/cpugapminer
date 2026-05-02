---
description: "Verify maxgap candidates against known records and generate a submission-ready verification summary."
argument-hint: "candidate='gap=<G> at=<L> next=<N> merit=<M>' [source=<file>] [strict=<true|false>]"
agent: "agent"
tools: [search, web]
---

Verify whether a found gap candidate appears to be record-worthy and produce a structured verification report.

Use these references:
- [docs/MAXGAP_SCAN.md](../../docs/MAXGAP_SCAN.md)
- Nicely gap tables: https://www.trnicely.net/gaps/gaplist.html
- Prime Gap List project: https://primegap-list-project.github.io/

## Parameters

Required:
- `candidate` in canonical form: `gap=<int> at=<int> next=<int> merit=<float>`

Optional:
- `source` path to a local results file containing the candidate
- `strict` default `true`

## Step 1 - Parse and local consistency checks

1. Parse candidate fields.
2. Validate:
   - `gap == next - at`
   - all numeric fields are positive and `next > at`
3. Recompute merit as `gap / ln(at)` and show absolute delta from provided merit.
4. If `strict=true`, flag if merit delta exceeds `0.01`.

## Step 2 - Source evidence

1. If `source` is provided, locate the exact candidate line and quote it.
2. If not found, state that explicitly.

## Step 3 - Record context check

1. Consult Nicely and Prime Gap List references.
2. Determine whether candidate likely:
   - below known records,
   - near known records,
   - or potentially exceeds listed values.
3. If external pages are unavailable, report that limitation and continue with local checks only.

## Step 4 - Independent verification checklist

Provide concrete commands (do not execute unless user asks) for independent verification of boundary primes using at least one external method, such as:
- `Math::Prime::Util` (Perl)
- GMP-based verifier

Include checks for:
1. `at` is prime
2. `next` is prime
3. no prime exists in `(at, next)`

## Output format

Return exactly these sections:

1. `Candidate` table
2. `Consistency Checks` (pass/fail list)
3. `Record Context` (brief)
4. `Independent Verification Commands` (fenced `bash`)
5. `Submission Readiness` with status: `not ready`, `needs verification`, or `ready to submit`

Be explicit about uncertainty; do not claim a confirmed record without independent prime-boundary validation.
