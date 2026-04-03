#!/usr/bin/env python3
"""
submit_records.py — Parse cpugapminer GAP FOUND logs and submit prime gap
records to primegaps.cloudygo.com.

The site accepts records in the form:
    <gap> <merit> <start_prime>
where <start_prime> can be a raw decimal integer — exactly what cpugapminer
prints as "nAdd" in its >>> GAP FOUND output.

Usage examples
--------------
Dry-run (parse log but do NOT submit):
    python3 scripts/submit_records.py --log miner.log \\
        --discoverer S.Troisi --dry-run

Submit today's finds:
    python3 scripts/submit_records.py --log miner.log \\
        --discoverer S.Troisi --date 2024-01-15

Read from stdin (pipe miner output directly):
    ./bin/gap_miner ... 2>&1 | python3 scripts/submit_records.py \\
        --discoverer S.Troisi --date 2024-01-15

Filter: only consider gaps with merit ≥ 25:
    python3 scripts/submit_records.py --log miner.log \\
        --discoverer S.Troisi --min-merit 25

The script automatically skips gaps that don't improve the current record
(fetched live from primegaps.cloudygo.com/merits.txt).

Requirements: Python 3 standard library only.
"""

import argparse
import datetime
import http.cookiejar
import math
import re
import sys
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser


# ── Constants ──────────────────────────────────────────────────────────────
SITE_URL   = "https://primegaps.cloudygo.com/"
MERITS_URL = "https://primegaps.cloudygo.com/merits.txt"
UA         = "cpugapminer-submit/1.0"

# Minimum gap size the site will accept (smaller gaps are fully catalogued)
MIN_GAP_SIZE = 1202


# ── Log parser ──────────────────────────────────────────────────────────────
# Matches an entire >>> GAP FOUND block (multi-line, non-greedy).
# Captures: gap, merit, nShift, nAdd  (nAdd may have " (0x...)" suffix — \d+
# stops at the first non-digit, so the hex annotation is ignored automatically).
_GAP_BLOCK_RE = re.compile(
    r">>> GAP FOUND\b.*?"
    r"gap\s*=\s*(\d+).*?"
    r"merit\s*=\s*([\d.]+).*?"
    r"nShift\s*=\s*(\d+).*?"
    r"nAdd\s*=\s*(\d+)",
    re.DOTALL,
)

# [verify_pow] hash= line printed by the miner after every RPC gap block.
# The hash is displayed big-endian (bytes reversed from internal LE storage),
# but int(hash_hex, 16) == the GMP integer that was imported LE — they match.
_VERIFY_HASH_RE = re.compile(r"\[verify_pow\]\s+hash=([0-9a-fA-F]{64})")

# In RPC/Gapcoin mode nAdd is at most 8 bytes (2^64-1).
# In CRT/scan mode nAdd IS the full prime (hundreds of digits, >> 2^64).
_RPC_NADD_MAX = (1 << 64)


def parse_log(text):
    """
    Scan *text* for >>> GAP FOUND blocks and return a list of
    (gap:int, merit:float, prime_str:str) tuples, deduplicated.

    Two log formats are handled automatically:

    CRT / scan mode  —  nAdd is the full starting prime (large decimal):
        nAdd    = 35133984279...  (80+ digits)

    RPC / Gapcoin mining mode  —  nAdd is a small addend; the full prime
    is reconstructed from the [verify_pow] hash= line that follows:
        nAdd    = 1844674415710808815 (0x1999999b8ab1aaef)
        ...later...
        [verify_pow] hash=fbe6a3c073c52fd4...  bits=256 hash_ok=1 is_prime=1
        prime = int(hash_hex, 16) << nShift + nAdd
    """
    results = []
    seen = set()
    for m in _GAP_BLOCK_RE.finditer(text):
        gap    = int(m.group(1))
        merit  = float(m.group(2))
        nshift = int(m.group(3))
        nadd   = int(m.group(4))

        if nadd >= _RPC_NADD_MAX:
            # CRT/scan mode: nAdd is the full prime already.
            prime_str = str(nadd)
        else:
            # RPC/Gapcoin mode: look for [verify_pow] hash= after this block.
            hash_m = _VERIFY_HASH_RE.search(text, m.end())
            if not hash_m:
                print(f"  Warning: RPC gap (gap={gap}) has no [verify_pow] hash= "
                      f"line — cannot reconstruct prime; skipping.",
                      file=sys.stderr)
                continue
            hash_int  = int(hash_m.group(1), 16)
            prime_str = str((hash_int << nshift) + nadd)

        key = (gap, prime_str)
        if key not in seen:
            seen.add(key)
            results.append((gap, merit, prime_str))
    return results


# ── Record comparison ───────────────────────────────────────────────────────

def fetch_merits():
    """
    Download merits.txt from the site.
    Returns dict {gap_size: merit} or {} on error.
    """
    print(f"Fetching current records from {MERITS_URL} …", file=sys.stderr)
    try:
        req = urllib.request.Request(MERITS_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            lines = resp.read().decode("utf-8").splitlines()
        records = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    records[int(parts[0])] = float(parts[1])
                except ValueError:
                    pass
        print(f"  Loaded {len(records):,} existing records.", file=sys.stderr)
        return records
    except Exception as exc:
        print(f"  Warning: could not fetch merits.txt: {exc}", file=sys.stderr)
        return {}


# ── CSRF extraction ─────────────────────────────────────────────────────────

class _CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            d = dict(attrs)
            if d.get("name") == "csrf_token":
                self.csrf_token = d.get("value", "")


def _extract_csrf(html):
    p = _CSRFParser()
    p.feed(html)
    return p.csrf_token


# ── HTTP helpers (session via cookie jar) ───────────────────────────────────

def _opener(jar):
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar)
    )


def _get(jar, url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with _opener(jar).open(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def _post(jar, url, fields):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": url,
            "Origin":  url.rstrip("/"),
        },
    )
    with _opener(jar).open(req, timeout=90) as resp:
        return resp.read().decode("utf-8")


# ── Response parser ─────────────────────────────────────────────────────────

def _extract_statuses(html):
    """
    Pull human-readable status lines out of the HTML response.
    The server renders them as raw text interspersed with <br> tags.
    """
    # Look for the status block between id="status" and the next h2/hr
    status_block = re.search(
        r'id\s*=\s*["\']status["\'][^>]*>(.*?)</[^>]+>',
        html, re.DOTALL | re.IGNORECASE,
    )
    if status_block:
        raw = status_block.group(1)
    else:
        # Fall back to anything that looks like a server status message
        raw = html

    # Strip HTML tags, collapse whitespace
    text = re.sub(r"<[^>]+>", "\n", raw)
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    # Keep only lines that contain recognisable server keywords
    keywords = ("queue", "record", "merit", "processed", "added",
                 "improve", "verified", "error", "can't", "gap",
                 "prime", "even", "odd", "parse", "large")
    relevant = [l for l in lines
                if any(kw in l.lower() for kw in keywords)]
    return relevant or lines[:10]


# ── Submission ──────────────────────────────────────────────────────────────

def submit_batch(batch, discoverer, date_str, dry_run):
    """
    Submit one batch of (gap, merit, nadd_str) tuples.
    Returns True on (apparent) success.
    """
    lines = [f"{gap} {merit:.6f} {nadd}" for gap, merit, nadd in batch]
    logdata = "\n".join(lines)

    print(f"\n{'─'*60}")
    print(f"Batch of {len(batch)} record(s):")
    for gap, merit, nadd in batch:
        digits = len(nadd)
        print(f"  gap={gap:8d}  merit={merit:.4f}  "
              f"start=…{nadd[-6:]} ({digits}-digit prime)")

    if dry_run:
        print("[dry-run] logdata would be:")
        for line in lines:
            preview = line if len(line) <= 120 else line[:117] + "…"
            print("    " + preview)
        print("[dry-run] Skipping submission.")
        return True

    jar = http.cookiejar.CookieJar()

    # GET page to obtain session cookie + CSRF token
    print("  → Fetching CSRF token …", end=" ", flush=True)
    try:
        html = _get(jar, SITE_URL)
    except Exception as exc:
        print(f"FAILED ({exc})")
        return False
    csrf = _extract_csrf(html)
    if not csrf:
        print("FAILED (no csrf_token found in page)")
        return False
    print(f"OK ({csrf[:8]}…)")

    # POST
    print("  → Submitting …", end=" ", flush=True)
    try:
        resp = _post(jar, SITE_URL, {
            "discoverer": discoverer,
            "date":       date_str,
            "logdata":    logdata,
            "csrf_token": csrf,
            "submit":     "Add",
        })
    except Exception as exc:
        print(f"FAILED ({exc})")
        return False
    print("OK")

    for line in _extract_statuses(resp):
        print("  Status:", line)

    return True


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Submit cpugapminer gap records to primegaps.cloudygo.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Requirements:")[0].strip(),
    )
    ap.add_argument("--discoverer", required=True,
                    help="Short name (3-8 chars), e.g. S.Troisi")
    ap.add_argument("--date", default=None,
                    help="YYYY-MM-DD discovery date (default: today)")
    ap.add_argument("--log", default=None,
                    help="Log file to parse (default: read from stdin)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse and preview records, do NOT submit")
    ap.add_argument("--batch-size", type=int, default=10,
                    help="Records per HTTP POST batch (default: 10)")
    ap.add_argument("--delay", type=float, default=3.0,
                    help="Seconds between batches (default: 3)")
    ap.add_argument("--min-merit", type=float, default=0.0,
                    help="Ignore gaps with merit below this (default: 0)")
    ap.add_argument("--skip-check", action="store_true",
                    help="Submit all found gaps without comparing to existing records")
    args = ap.parse_args()

    # ── Validate inputs ───────────────────────────────────────────────────
    if not 3 <= len(args.discoverer) <= 8:
        ap.error(f"--discoverer '{args.discoverer}' must be 3-8 characters")

    date_str = args.date or datetime.date.today().isoformat()
    try:
        datetime.date.fromisoformat(date_str)
    except ValueError:
        ap.error(f"--date '{date_str}': use YYYY-MM-DD format")

    # ── Read log ──────────────────────────────────────────────────────────
    if args.log:
        try:
            with open(args.log, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            ap.error(f"Cannot open log file: {exc}")
    else:
        print("Reading from stdin … (Ctrl+C to stop)", file=sys.stderr)
        text = sys.stdin.read()

    # ── Parse ─────────────────────────────────────────────────────────────
    found = parse_log(text)
    print(f"\nFound {len(found)} unique GAP FOUND block(s) in log.",
          file=sys.stderr)

    if not found:
        print("Nothing to submit.")
        return

    # ── Filter by merit ───────────────────────────────────────────────────
    if args.min_merit > 0:
        found = [(g, m, n) for g, m, n in found if m >= args.min_merit]
        print(f"  After merit filter (≥{args.min_merit}): {len(found)}",
              file=sys.stderr)

    # ── Filter by min gap size ────────────────────────────────────────────
    before = len(found)
    found = [(g, m, n) for g, m, n in found if g >= MIN_GAP_SIZE]
    if len(found) < before:
        print(f"  Dropped {before - len(found)} gap(s) below "
              f"minimum size {MIN_GAP_SIZE}", file=sys.stderr)

    # ── Compare against current records ───────────────────────────────────
    if args.skip_check:
        to_submit = found
        print(f"  --skip-check: submitting all {len(to_submit)} gap(s).",
              file=sys.stderr)
    else:
        records = fetch_merits()
        to_submit = []
        skipped   = 0
        for gap, merit, nadd in found:
            existing = records.get(gap, 0.0)
            if merit > existing:
                to_submit.append((gap, merit, nadd))
            else:
                skipped += 1
                print(f"  skip gap={gap}: merit {merit:.4f} ≤ existing "
                      f"{existing:.4f}", file=sys.stderr)
        if skipped:
            print(f"  Skipped {skipped} non-improvement(s).", file=sys.stderr)

    if not to_submit:
        print("\nNo new/improved records to submit. Done.")
        return

    print(f"\n{len(to_submit)} record(s) to submit "
          f"(discoverer={args.discoverer}  date={date_str})")
    if args.dry_run:
        print("  [dry-run mode — no HTTP requests will be made]\n")

    # ── Submit in batches ─────────────────────────────────────────────────
    total   = len(to_submit)
    batches = math.ceil(total / args.batch_size)
    for i in range(0, total, args.batch_size):
        batch = to_submit[i : i + args.batch_size]
        batch_num = i // args.batch_size + 1
        print(f"\n[Batch {batch_num}/{batches}]")
        ok = submit_batch(batch, args.discoverer, date_str, args.dry_run)
        if not ok:
            print("  Batch failed; continuing with next batch …")
        remaining = total - (i + len(batch))
        if remaining > 0 and not args.dry_run:
            print(f"  Waiting {args.delay}s before next batch …")
            time.sleep(args.delay)

    print("\nAll done.")


if __name__ == "__main__":
    main()
