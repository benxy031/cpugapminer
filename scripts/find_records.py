#!/usr/bin/env python3
"""
find_records.py — Fetch the prime gap record list and show which gaps are
beatable by cpugapminer at each shift.

Source: https://primegaps.cloudygo.com/merits.txt
        (mirror of https://github.com/primegap-list-project/prime-gap-list)

Usage:
    python3 scripts/find_records.py [--shift 384] [--shift 640] ...
    python3 scripts/find_records.py --all
    python3 scripts/find_records.py --top 20 --shift 896

Output:
    For each requested shift, prints:
      - Summary: beatable records count by current-merit threshold
      - Top N gaps ranked by improvement (achievable - current) merit
      - Recommended --ctr-merit for gen_crt
"""

import argparse
import math
import sys
import urllib.request

MERITS_URL = "https://primegaps.cloudygo.com/merits.txt"

# Gapcoin shifts covered by our CRT files
DEFAULT_SHIFTS = [384, 512, 640, 768, 896, 1024]

# All supported shifts
ALL_SHIFTS = [64, 68, 96, 110, 128, 133, 160, 192, 256,
              384, 512, 640, 720, 768, 896, 1024]

LN2 = math.log(2)


def fetch_merits(url=MERITS_URL):
    """Download merits.txt and return list of (gap, merit, discoverer)."""
    print(f"Fetching {url} ...", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "cpugapminer-record-finder/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        lines = resp.read().decode("utf-8").splitlines()
    records = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            try:
                records.append((int(parts[0]), float(parts[1]), parts[2] if len(parts) > 2 else "?"))
            except ValueError:
                pass
    print(f"Loaded {len(records):,} records.", file=sys.stderr)
    return records


def lnp(shift):
    """ln(p) for Gapcoin prime at given shift: p ≈ 2^(256+shift)."""
    return (256 + shift) * LN2


def achievable_merit(gap, shift):
    return gap / lnp(shift)


def analyze_shift(records, shift, min_merit=20.0, max_merit=40.0):
    """
    For a given shift, find all gaps where the current record merit is lower
    than what Gapcoin can achieve (i.e., the record is beatable).

    Only considers gaps where the achievable merit falls in [min_merit, max_merit]
    — the practical CRT window. Gaps outside this range are either too small
    (Gapcoin won't find them) or too large (CRT can't cover them).

    Returns sorted list of (improvement, gap, current_merit, achievable_merit, discoverer).
    """
    lp = lnp(shift)
    beatable = []
    for gap, merit, disc in records:
        ach = gap / lp
        if min_merit <= ach <= max_merit:
            improvement = ach - merit
            if improvement > 0:
                beatable.append((improvement, gap, merit, ach, disc))
    beatable.sort(reverse=True)
    return beatable


def threshold_counts(beatable):
    """Return counts of beatable records where current merit is below each threshold."""
    counts = {}
    for threshold in [24, 25, 26, 27, 28, 29, 30]:
        counts[threshold] = sum(1 for imp, g, m, a, d in beatable if m < threshold)
    return counts


def recommended_ctr_merit(beatable, top_n=50):
    """
    Suggest --ctr-merit by looking at the top-N beatable records.
    The gap size of the Nth best opportunity determines the floor merit we need to cover.
    We round down to the nearest integer and subtract 1 (the standard discount).
    """
    if not beatable:
        return None
    # Take the Nth record (or last if fewer exist)
    idx = min(top_n - 1, len(beatable) - 1)
    _, gap, _, ach, _ = beatable[idx]
    # The minimum achievable merit for this gap at this shift
    # We want our CRT window to cover up to this gap, so ctr-merit = floor(ach) - 1
    return max(20, math.floor(ach) - 1)


def print_shift_report(records, shift, top_n, show_all, min_merit=20.0, max_merit=40.0):
    lp = lnp(shift)
    beatable = analyze_shift(records, shift, min_merit, max_merit)

    print(f"\n{'='*70}")
    print(f"  SHIFT {shift}  |  ln(p) = {lp:.1f}  |  prime ≈ 2^{256+shift}")
    print(f"{'='*70}")

    if not beatable:
        print("  No beatable records found.")
        return

    counts = threshold_counts(beatable)
    print(f"\n  Beatable records (achievable merit > current):")
    print(f"    Total beatable:            {len(beatable):5d}")
    for t, c in counts.items():
        print(f"    Current merit < {t}:        {c:5d}")

    rec_merit = recommended_ctr_merit(beatable, top_n=50)
    print(f"\n  Recommended --ctr-merit for record hunting: {rec_merit}")
    print(f"  (covers top-50 opportunities; use {rec_merit-1} at shifts >=384 for -2 discount)")

    # Best single opportunity
    best_imp, best_gap, best_cur, best_ach, best_disc = beatable[0]
    print(f"\n  Best single opportunity:")
    print(f"    gap={best_gap}  current={best_cur:.4f} ({best_disc})  achievable={best_ach:.4f}  improvement=+{best_imp:.4f}")

    # Top-N table
    limit = len(beatable) if show_all else min(top_n, len(beatable))
    print(f"\n  Top {limit} beatable records:")
    print(f"  {'rank':>4}  {'gap':>7}  {'current':>9}  {'achievable':>10}  {'improve':>8}  discoverer")
    print(f"  {'----':>4}  {'-------':>7}  {'---------':>9}  {'----------':>10}  {'--------':>8}  ----------")
    for rank, (imp, gap, cur, ach, disc) in enumerate(beatable[:limit], 1):
        print(f"  {rank:>4}  {gap:>7}  {cur:>9.4f}  {ach:>10.4f}  {imp:>+8.4f}  {disc}")


def main():
    parser = argparse.ArgumentParser(
        description="Find beatable prime gap records for cpugapminer CRT mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--shift", type=int, action="append", dest="shifts",
        metavar="N", help="Shift to analyze (can be repeated). Default: 384 512 640 768 896 1024"
    )
    parser.add_argument(
        "--all-shifts", action="store_true",
        help="Analyze all supported shifts."
    )
    parser.add_argument(
        "--top", type=int, default=20, metavar="N",
        help="Number of top opportunities to show per shift (default: 20)."
    )
    parser.add_argument(
        "--show-all", action="store_true",
        help="Show all beatable records, not just top N."
    )
    parser.add_argument(
        "--max-merit", type=float, default=40.0, metavar="M",
        help="Upper bound on achievable merit to consider (default: 40). "
             "Gaps above this are outside the practical CRT window."
    )
    parser.add_argument(
        "--min-merit", type=float, default=20.0, metavar="M",
        help="Lower bound on achievable merit to consider (default: 20)."
    )
    parser.add_argument(
        "--url", default=MERITS_URL,
        help=f"Merits URL (default: {MERITS_URL})"
    )
    parser.add_argument(
        "--summary-only", action="store_true",
        help="Print only the summary table, no per-record listing."
    )
    args = parser.parse_args()

    shifts = args.shifts or (ALL_SHIFTS if args.all_shifts else DEFAULT_SHIFTS)
    # Validate shifts
    for s in shifts:
        if s < 16 or s > 2048:
            print(f"Error: shift {s} out of range 16-2048", file=sys.stderr)
            sys.exit(1)

    records = fetch_merits(args.url)

    if args.summary_only:
        print(f"\n{'shift':>6}  {'beatable':>8}  {'<m26':>6}  {'<m27':>6}  {'<m28':>6}  {'<m29':>6}  {'rec_ctr_merit':>14}")
        print(f"{'------':>6}  {'--------':>8}  {'----':>6}  {'----':>6}  {'----':>6}  {'----':>6}  {'-------------':>14}")
        for shift in sorted(shifts):
            beatable = analyze_shift(records, shift, args.min_merit, args.max_merit)
            counts = threshold_counts(beatable)
            rec = recommended_ctr_merit(beatable, top_n=50)
            print(f"{shift:>6}  {len(beatable):>8}  {counts[26]:>6}  {counts[27]:>6}  {counts[28]:>6}  {counts[29]:>6}  {rec:>14}")
    else:
        for shift in sorted(shifts):
            print_shift_report(records, shift, top_n=args.top, show_all=args.show_all,
                               min_merit=args.min_merit, max_merit=args.max_merit)

    print()


if __name__ == "__main__":
    main()
