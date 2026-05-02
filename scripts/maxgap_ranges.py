#!/usr/bin/env python3
"""Generate maxgap_scan worker ranges for future runs.

Examples:
  python3 scripts/maxgap_ranges.py --start 18000000000000000000 --slice 8400000000000 --threads 8
  python3 scripts/maxgap_ranges.py --start 18000000000000000000 --end 18000067200000000000 --threads 8
  python3 scripts/maxgap_ranges.py --start 4e18 --end 4.001e18 --threads 8 --format csv
"""

from __future__ import annotations

import argparse
from decimal import Decimal


def parse_int_like(value: str) -> int:
    """Allow plain ints and simple scientific notation (e.g. 4e18)."""
    try:
        d = Decimal(value)
    except Exception as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value}") from exc

    if d != d.to_integral_value():
        raise argparse.ArgumentTypeError(f"value must be an integer: {value}")
    return int(d)


def build_ranges(start: int, threads: int, end: int | None, slice_size: int | None):
    ranges = []
    if end is not None:
        if end <= start:
            raise ValueError("end must be greater than start")
        span = end - start
        base = span // threads
        rem = span % threads
        cur = start
        for i in range(threads):
            step = base + (1 if i < rem else 0)
            nxt = cur + step
            ranges.append((i, cur, nxt))
            cur = nxt
    else:
        assert slice_size is not None
        for i in range(threads):
            s = start + i * slice_size
            e = s + slice_size
            ranges.append((i, s, e))
    return ranges


def print_markdown_table(ranges):
    print("| Worker | Start | End (exclusive) |")
    print("|---|---:|---:|")
    for i, s, e in ranges:
        print(f"| {i} | {s} | {e} |")


def print_csv(ranges):
    print("worker,start,end_exclusive")
    for i, s, e in ranges:
        print(f"{i},{s},{e}")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate maxgap worker ranges")
    p.add_argument("--start", required=True, type=parse_int_like, help="Range start")
    p.add_argument("--threads", required=True, type=int, help="Worker count")
    p.add_argument("--end", type=parse_int_like, help="Range end (exclusive)")
    p.add_argument("--slice", dest="slice_size", type=parse_int_like, help="Fixed per-worker slice size")
    p.add_argument("--format", choices=("markdown", "csv"), default="markdown")
    args = p.parse_args()

    if args.threads < 1:
        raise SystemExit("--threads must be >= 1")
    if (args.end is None) == (args.slice_size is None):
        raise SystemExit("Provide exactly one of --end or --slice")
    if args.slice_size is not None and args.slice_size <= 0:
        raise SystemExit("--slice must be > 0")

    ranges = build_ranges(args.start, args.threads, args.end, args.slice_size)
    if args.format == "markdown":
        print_markdown_table(ranges)
    else:
        print_csv(ranges)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
