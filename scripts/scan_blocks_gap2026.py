#!/usr/bin/env python3
# Copyright (C) 2026  cpugapminer contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""
scan_blocks_gap2026.py — Čita blokove iz gapchain.sqlite3 i ispisuje
height, shift, merit, gaplen, difficulty, time, adder i startprime.

Po potrebi uspoređuje blokove s current merits.txt i može izvoziti ili
slati rekordne kandidate kroz scripts/submit_records.py.

Uso:
    python3 scripts/scan_blocks_gap2026.py                    # zadnjih 50 blokova
    python3 scripts/scan_blocks_gap2026.py --db gapchain.sqlite3  # eksplicitna SQLite baza
    python3 scripts/scan_blocks_gap2026.py -n 200             # zadnjih 200 blokova
    python3 scripts/scan_blocks_gap2026.py -s 2471000         # od bloka 2471000 do vrha
    python3 scripts/scan_blocks_gap2026.py -s 2471000 -e 2471100  # raspon blokova
    python3 scripts/scan_blocks_gap2026.py --min-merit 25.0   # samo merit >= 25
    python3 scripts/scan_blocks_gap2026.py --csv > blocks.csv  # CSV export
    python3 scripts/scan_blocks_gap2026.py -n 5000 --records   # označi rekorde sa neta
    python3 scripts/scan_blocks_gap2026.py -n 10000 --records-only --export-records records_to_submit.txt
    python3 scripts/scan_blocks_gap2026.py -n 10000 --records-only --submit-records --discoverer S.Troisi
    python3 scripts/scan_blocks_gap2026.py -n 10000 --records-only --submit-dry-run --discoverer S.Troisi
"""

import argparse
import json
import math
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# --------------------------------------------------------------------------
# Prime gap record list
# --------------------------------------------------------------------------

MERITS_URL = "https://primegaps.cloudygo.com/merits.txt"

def fetch_records(url=MERITS_URL):
    """
    Preuzmi merits.txt i vrati dict {gap: (merit, discoverer)}.
    Samo najveći merit za svaki gap (lista je ionako sortirana).
    """
    print(f"# Preuzimam rekorde: {url}", file=sys.stderr)
    req = urllib.request.Request(
        url, headers={"User-Agent": "cpugapminer-scan-blocks/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            lines = resp.read().decode("utf-8").splitlines()
    except Exception as ex:
        print(f"# WARN: ne mogu preuzeti rekorde: {ex}", file=sys.stderr)
        return {}
    records = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            try:
                gap  = int(parts[0])
                merit = float(parts[1])
                disc  = parts[2] if len(parts) > 2 else "?"
                # lista je sortirana descending po merit; uzmi prvi (najveći)
                if gap not in records:
                    records[gap] = (merit, disc)
            except ValueError:
                pass
    print(f"# Učitano {len(records):,} rekorda sa neta.", file=sys.stderr)
    return records


# --------------------------------------------------------------------------
# SQLite helpers
# --------------------------------------------------------------------------

DEFAULT_DB = Path(__file__).resolve().parents[1] / "gapchain.sqlite3"
SUBMIT_SCRIPT = Path(__file__).resolve().parent / "submit_records.py"

def connect_db(path=DEFAULT_DB):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn

def get_last_height(conn):
    row = conn.execute("SELECT MAX(height) AS max_height FROM gapchain").fetchone()
    if row is None or row["max_height"] is None:
        return None
    return int(row["max_height"])

def load_block_row(conn, height):
    row = conn.execute(
        """
        SELECT height, difficulty, shift, adder, startprime, gapsize, merit,
               primedigits, date, time
        FROM gapchain
        WHERE height = ?
        """,
        (height,),
    ).fetchone()
    if row is None:
        return None
    return row

def row_to_block(row):
    date_value = row["date"] or ""
    time_value = row["time"] or ""
    if date_value and time_value:
        time_text = f"{date_value} {time_value}"
    else:
        time_text = date_value or time_value
    return {
        "height": row["height"],
        "shift": row["shift"] or 0,
        "merit": float(row["merit"] or 0.0),
        "gaplen": int(row["gapsize"] or 0),
        "nonce": row["primedigits"] if row["primedigits"] is not None else "",
        "difficulty": float(row["difficulty"] or 0.0),
        "time": time_text,
        "adder": row["adder"] if row["adder"] is not None else "",
        "gapstart": row["startprime"] if row["startprime"] is not None else "",
        "hash": "",
    }

def fetch_block(conn, height):
    row = load_block_row(conn, height)
    if row is None:
        raise KeyError(f"height {height} not found in gapchain.sqlite3")
    return row_to_block(row)

def iter_blocks(conn, start, end):
    rows = conn.execute(
        """
        SELECT height, difficulty, shift, adder, startprime, gapsize, merit,
               primedigits, date, time
        FROM gapchain
        WHERE height BETWEEN ? AND ?
        ORDER BY height
        """,
        (start, end),
    )
    for row in rows:
        yield row_to_block(row)


# --------------------------------------------------------------------------
# Block parsing helpers
# --------------------------------------------------------------------------

LN2 = math.log(2)

def block_ln_p(shift):
    """ln(p) za Gapcoin prime: p ≈ 2^(256+shift)."""
    return (256 + shift) * LN2

def compute_merit(gap, shift):
    return gap / block_ln_p(shift)

def short_gapstart(s, chars=24):
    """Prikaži početak + kraj broja."""
    if len(s) <= chars * 2 + 3:
        return s
    return f"{s[:chars]}...{s[-chars:]}"

def format_time(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def format_time_value(value):
    if isinstance(value, (int, float)):
        return format_time(value)
    return str(value)


# --------------------------------------------------------------------------
# Fetch one block by height
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

HEADER = (
    f"{'Height':>9}  {'Shift':>5}  {'Merit':>8}  {'RecordM':>8}  {'Delta':>7}  "
    f"{'Gap':>7}  {'Diff':>8}  {'Time (UTC)':^19}  Adder (skraćeno)"
)
HEADER_NOREC = (
    f"{'Height':>9}  {'Shift':>5}  {'Merit':>8}  {'Gap':>7}  "
    f"{'Diff':>8}  {'Time (UTC)':^19}  Adder (skraćeno)"
)
SEP     = "-" * 120
SEP_SHORT = "-" * 105

def trunc_adder(adder, shift):
    """Skrati adder za ispis — za veliki shift prikaži samo prvih+zadnjih 10 cifara."""
    s = str(adder)
    if shift <= 64 or len(s) <= 26:
        return s
    return f"{s[:12]}…{s[-12:]}"

def print_block(blk, csv=False, verbose=False, rec_db=None):
    """
    rec_db: dict {gap: (merit, discoverer)} ili None.
    Ako je zadano, usporedi merit bloka s rekordima i označi rekorde.
    """
    h      = blk.get("height", "?")
    shift  = blk.get("shift", 0)
    merit  = blk.get("merit", 0.0)
    gaplen = blk.get("gaplen", 0)
    diff   = blk.get("difficulty", 0.0)
    ts     = blk.get("time", 0)
    adder  = blk.get("adder", "?")
    gs     = blk.get("gapstart", "")

    # Record lookup
    rec_merit, rec_disc, is_record = None, None, False
    delta = None
    if rec_db is not None and gaplen > 0:
        if gaplen in rec_db:
            rec_merit, rec_disc = rec_db[gaplen]
            delta = merit - rec_merit
            is_record = delta > 0
        else:
            # Gap nije u bazi → naš blok je vjerovatno rekord (ili gap premali za bazu)
            rec_merit, rec_disc, delta = None, "(nema u bazi)", None

    if csv:
        if rec_db is not None:
            rec_m_s = f"{rec_merit:.6f}" if rec_merit is not None else ""
            delta_s  = f"{delta:.4f}" if delta is not None else ""
            print(f"{h},{shift},{merit:.6f},{gaplen},{diff:.6f},{ts},"
                  f"{int(is_record)},{rec_m_s},{delta_s},{adder},{gs}")
        else:
            print(f"{h},{shift},{merit:.6f},{gaplen},{diff:.6f},{ts},{adder},{gs}")
        return

    tstr   = format_time_value(ts)
    adder_s = trunc_adder(adder, shift)

    if rec_db is not None:
        # Široki ispis s kolonama za rekord
        rec_s   = f"{rec_merit:8.4f}" if rec_merit is not None else "        "
        delta_s = f"{delta:+7.4f}" if delta is not None else "       "
        flag    = " *** REKORD ***" if is_record else ""
        print(f"{h:>9}  {shift:>5}  {merit:>8.4f}  {rec_s}  {delta_s}  "
              f"{gaplen:>7}  {diff:>8.4f}  {tstr}  {adder_s}{flag}")
        if is_record:
            print(f"          prijašnji rekord:  merit={rec_merit:.4f}  discoverer={rec_disc}")
    else:
        print(f"{h:>9}  {shift:>5}  {merit:>8.4f}  {gaplen:>7}  "
              f"{diff:>8.4f}  {tstr}  {adder_s}")

    if verbose and gs:
        print(f"          startprime: {short_gapstart(gs, 32)}")
        print(f"          adder:     {adder}")


# --------------------------------------------------------------------------
# Export helpers
# --------------------------------------------------------------------------

def _write_export(path, rows):
    """
    Zapiši rekorde u FILE za upload na primegaps.cloudygo.com.

    Format koji site prihvaća (jedan rekord po liniji):
        <gap> <merit> <start_prime>

    gdje je <start_prime> puni decimalni broj početnog prosta broja jaza.
    Svaka linija je neovisna — možeš fajl uploadati direktno ili ga
    koristiti s existing submit_records.py --prime-file.

    rows: list of (gap, merit, prime_start_str, height)
    """
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    with open(path, "w") as f:
        f.write(f"# Gapcoin prime gap records — exported by scan_blocks.py\n")
        f.write(f"# Generated: {now} UTC\n")
        f.write(f"# Format: gap merit prime_start\n")
        f.write(f"# Records: {len(rows)}\n")
        f.write("#\n")
        for gap, merit, prime_str, height in rows:
            f.write(f"# height={height}\n")
            f.write(f"{gap} {merit:.6f} {prime_str}\n")


def _write_export_append(path, gap, merit, prime_str, height):
    """Dodaj jedan rekord u postojeći export fajl (live --follow mode)."""
    with open(path, "a") as f:
        f.write(f"# height={height}\n")
        f.write(f"{gap} {merit:.6f} {prime_str}\n")


def _build_submit_log(rows):
    lines = []
    for gap, merit, prime_str, height in rows:
        lines.append(f"# height={height}")
        lines.append(">>> GAP FOUND")
        lines.append(f"gap = {gap}")
        lines.append(f"merit = {merit:.6f}")
        lines.append("nShift = 0")
        lines.append(f"nAdd = {prime_str}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Čita Gapcoin blokove iz gapchain.sqlite3")
    parser.add_argument("--db", type=str, default=str(DEFAULT_DB),
                        help=f"SQLite baza (default: {DEFAULT_DB})")
    parser.add_argument("-n", "--count", type=int, default=50,
                        help="Broj zadnjih blokova (default: 50)")
    parser.add_argument("-s", "--start", type=int, default=None,
                        help="Početni blok (height)")
    parser.add_argument("-e", "--end", type=int, default=None,
                        help="Krajnji blok (height, default: vrh lanca)")
    parser.add_argument("--min-merit", type=float, default=0.0,
                        help="Prikaži samo blokove s merit >= X")
    parser.add_argument("--min-shift", type=int, default=0,
                        help="Prikaži samo blokove sa shift >= X")
    parser.add_argument("--adder", type=str, default=None,
                        help="Filtriraj po adder adresi (puna ili prefiks)")
    parser.add_argument("--csv", action="store_true",
                        help="CSV output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ispiši i startprime")
    parser.add_argument("--records", "-r", action="store_true",
                        help="Preuzmi rekorde s primegaps.cloudygo.com i označi rekordne blokove")
    parser.add_argument("--records-url", type=str, default=MERITS_URL,
                        help=f"URL merits.txt (default: {MERITS_URL})")
    parser.add_argument("--records-only", action="store_true",
                        help="Prikaži samo blokove koji su rekord (implicira --records)")
    parser.add_argument("--export-records", type=str, default=None, metavar="FILE",
                        help="Spremi rekordne blokove u FILE za upload na primegaps.cloudygo.com")
    parser.add_argument("--submit-records", action="store_true",
                        help="Pošalji rekordne blokove kroz scripts/submit_records.py")
    parser.add_argument("--submit-dry-run", action="store_true",
                        help="Prikaži što bi se poslalo, ali nemoj pokretati submit_records.py")
    parser.add_argument("--discoverer", type=str, default=None,
                        help="Discoverer oznaka za --submit-records")
    parser.add_argument("--submit-date", type=str, default=None,
                        help="YYYY-MM-DD datum za --submit-records (default: danas)")
    args = parser.parse_args()

    if args.records_only or args.export_records or args.submit_records or args.submit_dry_run:
        args.records = True

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(f"error: missing SQLite database {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = connect_db(db_path)
    tip = get_last_height(conn)
    if tip is None:
        print(f"error: no rows found in {db_path}", file=sys.stderr)
        sys.exit(1)

    rec_db = fetch_records(args.records_url) if args.records else None

    if args.start is not None:
        start = args.start
        end = args.end if args.end is not None else tip
    elif args.end is not None:
        start = max(0, args.end - args.count + 1)
        end = args.end
    else:
        end = tip
        start = max(0, end - args.count + 1)

    if not args.csv:
        print(f"# Gapchain SQLite: {db_path}")
        print(f"# Vrh lanca: {tip}")
        if rec_db is not None:
            print(f"# Rekorda u bazi: {len(rec_db):,}")
        print(f"# Raspon: {start} – {end}  ({end - start + 1} blokova)\n")
        print(HEADER if rec_db is not None else HEADER_NOREC)
        print(SEP if rec_db is not None else SEP_SHORT)

    if args.csv:
        if rec_db is not None:
            print("height,shift,merit,gaplen,difficulty,time_utc,is_record,record_merit,delta,adder,startprime")
        else:
            print("height,shift,merit,gaplen,difficulty,time_utc,adder,startprime")

    printed = 0
    export_rows = []
    for blk in iter_blocks(conn, start, end):
        merit = blk.get("merit", 0.0)
        shift = blk.get("shift", 0)
        adder = blk.get("adder", "")
        gaplen = blk.get("gaplen", 0)
        if merit < args.min_merit:
            continue
        if shift < args.min_shift:
            continue
        if args.adder and not str(adder).startswith(args.adder):
            continue

        rec_merit_val = rec_db.get(gaplen, (None, None))[0] if rec_db is not None else None
        is_rec = rec_merit_val is not None and merit > rec_merit_val
        if (args.records_only or args.export_records or args.submit_records) and rec_db is not None:
            if not is_rec:
                continue

        print_block(blk, csv=args.csv, verbose=args.verbose, rec_db=rec_db)
        printed += 1

        if (args.export_records or args.submit_records) and is_rec:
            gs = blk.get("gapstart", "")
            if gs:
                export_rows.append((gaplen, merit, gs, blk.get("height", 0)))

    if not args.csv:
        print(SEP if rec_db is not None else SEP_SHORT)
        print(f"# Prikazano: {printed} blokova")

    if args.export_records:
        _write_export(args.export_records, export_rows)
        print(f"# Export: {len(export_rows)} rekord(a) zapisano u {args.export_records}", file=sys.stderr)

    if args.submit_records or args.submit_dry_run:
        if not args.discoverer:
            print("error: --discoverer is required with --submit-records", file=sys.stderr)
            sys.exit(1)
        if not export_rows:
            print("# Nema novih/improved rekordnih kandidata za slanje.", file=sys.stderr)
        else:
            submit_log = _build_submit_log(export_rows)
            submit_cmd = [sys.executable, str(SUBMIT_SCRIPT), "--discoverer", args.discoverer]
            if args.submit_date:
                submit_cmd += ["--date", args.submit_date]
            if args.submit_dry_run:
                submit_cmd.append("--dry-run")
                print(f"# Dry-run: {len(export_rows)} rekord(a) bi išlo kroz submit_records.py", file=sys.stderr)
                print(f"# Dry-run command: {' '.join(submit_cmd)}", file=sys.stderr)
                print("# Dry-run payload:", file=sys.stderr)
                for line in submit_log.splitlines():
                    print(f"#   {line}", file=sys.stderr)
            else:
                print(f"# Slanje {len(export_rows)} rekord(a) kroz submit_records.py", file=sys.stderr)
                proc = subprocess.run(submit_cmd, input=submit_log, text=True)
                if proc.returncode != 0:
                    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
