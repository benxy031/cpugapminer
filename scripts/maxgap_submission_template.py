#!/usr/bin/env python3
"""Generate a submission-ready markdown template from one maxgap candidate line.

Example:
  python3 scripts/maxgap_submission_template.py \
    --candidate "gap=1512 at=4000000000000123457 next=4000000000000124969 merit=15.3421"
"""

from __future__ import annotations

import argparse
import math
import re
from datetime import datetime, timezone
from pathlib import Path


CANDIDATE_RE = re.compile(
    r"gap=(?P<gap>\d+)\s+at=(?P<at>\d+)\s+next=(?P<next>\d+)\s+merit=(?P<merit>[0-9]+(?:\.[0-9]+)?)"
)


def parse_candidate(line: str) -> dict[str, float | int]:
    m = CANDIDATE_RE.search(line.strip())
    if not m:
        raise ValueError(
            "candidate must match: gap=<int> at=<int> next=<int> merit=<float>"
        )

    gap = int(m.group("gap"))
    at = int(m.group("at"))
    nxt = int(m.group("next"))
    merit = float(m.group("merit"))

    if gap <= 0 or at < 2 or nxt <= at:
        raise ValueError("invalid candidate values: require gap>0, at>=2, next>at")
    if nxt - at != gap:
        raise ValueError(f"inconsistent candidate: next-at={nxt-at}, gap={gap}")

    calc_merit = gap / math.log(at)
    merit_delta = abs(calc_merit - merit)

    return {
        "gap": gap,
        "at": at,
        "next": nxt,
        "merit": merit,
        "calc_merit": calc_merit,
        "merit_delta": merit_delta,
    }


def default_output_path(base_dir: Path, gap: int, at: int) -> Path:
    return base_dir / f"submission_gap{gap}_at{at}.md"


def render_template(
    candidate: dict[str, float | int],
    source: str,
    scan_command: str,
    host: str,
    cpu: str,
) -> str:
    gap = int(candidate["gap"])
    at = int(candidate["at"])
    nxt = int(candidate["next"])
    merit = float(candidate["merit"])
    calc_merit = float(candidate["calc_merit"])
    merit_delta = float(candidate["merit_delta"])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""# Prime Gap Candidate Submission Report

Generated: {generated}

## Candidate

| Field | Value |
|---|---:|
| gap | {gap} |
| at (L) | {at} |
| next (N) | {nxt} |
| merit (reported) | {merit:.6f} |
| merit (recomputed = gap/ln(at)) | {calc_merit:.6f} |
| merit delta | {merit_delta:.6f} |

Canonical line:

```text
gap={gap} at={at} next={nxt} merit={merit}
```

## Discovery Context

- Project: cpugapminer maxgap_scan
- Source line/file: {source}
- Host machine: {host}
- CPU: {cpu}
- Scan command used:

```bash
{scan_command}
```

## Independent Verification (Required)

Run at least one independent verifier and attach outputs.

### Option A: Math::Prime::Util (Perl)

```bash
perl -MMath::Prime::Util=is_prime -E 'say is_prime({at}) ? "L prime" : "L not prime"; say is_prime({nxt}) ? "N prime" : "N not prime"'
perl -MMath::Prime::Util=next_prime -E 'say next_prime({at})'
```

Expected:
- `L prime`
- `N prime`
- `next_prime(L)` equals `{nxt}`

### Option B: GMP / custom verifier

```bash
# Replace with your verifier command and keep raw output
echo "verify {at} and {nxt} with independent GMP-based tool"
```

Attach raw logs here:

```text
<paste independent verification logs>
```

## Record Context Check

Check candidate against:
- https://www.trnicely.net/gaps/gaplist.html
- https://primegap-list-project.github.io/

Notes:

```text
<paste comparison notes and links to relevant table entries>
```

## Submission Payload

- Lower prime L: {at}
- Gap G: {gap}
- Upper prime N: {nxt}
- Merit G/ln(L): {calc_merit:.6f}
- Discovery method: maxgap_scan (skip-and-probe, dual-pass)
- Hardware: {cpu} on {host}

## Final Checklist

- [ ] Candidate line preserved exactly
- [ ] Boundary primality independently verified
- [ ] No interior prime between L and N independently verified
- [ ] Record context checked against current public tables
- [ ] Raw logs attached (scan + verification)
- [ ] Submission sent to Prime Gap List workflow
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate submission-ready markdown report from one maxgap candidate line"
    )
    parser.add_argument(
        "--candidate",
        required=True,
        help="Candidate line: gap=<int> at=<int> next=<int> merit=<float>",
    )
    parser.add_argument(
        "--source",
        default="<results file>:<line>",
        help="Source location for the candidate (default placeholder)",
    )
    parser.add_argument(
        "--scan-command",
        default="bin/maxgap_scan --start ... --end ... --mingap ... --dual-pass",
        help="Command used to discover candidate",
    )
    parser.add_argument("--host", default="<hostname>", help="Host/machine label")
    parser.add_argument("--cpu", default="<cpu model>", help="CPU model/name")
    parser.add_argument(
        "--out",
        help="Output markdown path (default: scripts/submission_gap<G>_at<L>.md)",
    )
    args = parser.parse_args()

    candidate = parse_candidate(args.candidate)
    base_dir = Path(__file__).resolve().parent
    out_path = Path(args.out) if args.out else default_output_path(base_dir, int(candidate["gap"]), int(candidate["at"]))

    body = render_template(
        candidate=candidate,
        source=args.source,
        scan_command=args.scan_command,
        host=args.host,
        cpu=args.cpu,
    )

    out_path.write_text(body, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
