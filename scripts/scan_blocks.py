#!/usr/bin/env python3
"""
scan_blocks.py — Čita blokove iz Gapcoin walleta/čvora putem RPC-a
i ispisuje: height, shift, merit, gaplen, nonce, difficulty, adder, gapstart

Credentials se čitaju iz ~/.gapcoin/gapcoin.conf

Uso:
    python3 scripts/scan_blocks.py                    # zadnjih 50 blokova
    python3 scripts/scan_blocks.py -n 200             # zadnjih 200 blokova
    python3 scripts/scan_blocks.py -s 2471000         # od bloka 2471000 do vrha
    python3 scripts/scan_blocks.py -s 2471000 -e 2471100  # raspon blokova
    python3 scripts/scan_blocks.py --min-merit 25.0   # samo merit >= 25
    python3 scripts/scan_blocks.py --csv > blocks.csv # CSV export
    python3 scripts/scan_blocks.py --follow           # prati nove blokove uživo
    python3 scripts/scan_blocks.py -n 5000 --records  # označi rekorde sa neta
    # Zadnjih 500 blokova s usporedbom rekorda
    python3 scripts/scan_blocks.py -n 500 --records

    # Samo rekordni blokovi, zadnjih 10000
    python3 scripts/scan_blocks.py -n 10000 --records-only --export-records records_to_submit.txt

    # Praćenje novih blokova uživo i označi rekorde čim dođu
    python3 scripts/scan_blocks.py --follow --records --export-records records_to_submit.txt

    # CSV export s record kolonama
    python3 scripts/scan_blocks.py -n 1000 --records --csv > blocks_with_records.csv
"""

import argparse
import json
import math
import os
import sys
import time
import urllib.request
import urllib.error

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
# RPC helpers
# --------------------------------------------------------------------------

DEFAULT_CONF = os.path.expanduser("~/.gapcoin/gapcoin.conf")

def load_conf(path=DEFAULT_CONF):
    conf = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return conf

def make_rpc(url, user, password):
    """Returns a callable rpc(method, params=[]) -> result."""
    import base64
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}",
    }
    req_id = [0]

    def rpc(method, params=None):
        if params is None:
            params = []
        req_id[0] += 1
        body = json.dumps({
            "jsonrpc": "1.0",
            "id": str(req_id[0]),
            "method": method,
            "params": params,
        }).encode()
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            data = json.loads(e.read())
        if data.get("error"):
            raise RuntimeError(f"RPC error: {data['error']}")
        return data["result"]

    return rpc


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


# --------------------------------------------------------------------------
# Fetch one block by height
# --------------------------------------------------------------------------

def fetch_block(rpc, height):
    bh = rpc("getblockhash", [height])
    return rpc("getblock", [bh, True])


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

HEADER = (
    f"{'Height':>9}  {'Shift':>5}  {'Merit':>8}  {'RecordM':>8}  {'Delta':>7}  "
    f"{'Gap':>7}  {'Nonce':>8}  {'Diff':>8}  {'Time (UTC)':^19}  Adder (skraćeno)"
)
HEADER_NOREC = (
    f"{'Height':>9}  {'Shift':>5}  {'Merit':>8}  {'Gap':>7}  "
    f"{'Nonce':>8}  {'Diff':>8}  {'Time (UTC)':^19}  Adder (skraćeno)"
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
    nonce  = blk.get("nonce", 0)
    diff   = blk.get("difficulty", 0.0)
    ts     = blk.get("time", 0)
    adder  = blk.get("adder", "?")
    gs     = blk.get("gapstart", "")
    bhash  = blk.get("hash", "")

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
        rec_m_s = f"{rec_merit:.6f}" if rec_merit is not None else ""
        delta_s  = f"{delta:.4f}" if delta is not None else ""
        print(f"{h},{shift},{merit:.6f},{gaplen},{nonce},{diff:.6f},{ts},"
              f"{int(is_record)},{rec_m_s},{delta_s},{adder},{bhash},{gs}")
        return

    tstr   = format_time(ts)
    adder_s = trunc_adder(adder, shift)

    if rec_db is not None:
        # Široki ispis s kolonama za rekord
        rec_s   = f"{rec_merit:8.4f}" if rec_merit is not None else "        "
        delta_s = f"{delta:+7.4f}" if delta is not None else "       "
        flag    = " *** REKORD ***" if is_record else ""
        print(f"{h:>9}  {shift:>5}  {merit:>8.4f}  {rec_s}  {delta_s}  "
              f"{gaplen:>7}  {nonce:>8}  {diff:>8.4f}  {tstr}  {adder_s}{flag}")
        if is_record:
            print(f"          prijašnji rekord:  merit={rec_merit:.4f}  discoverer={rec_disc}")
    else:
        print(f"{h:>9}  {shift:>5}  {merit:>8.4f}  {gaplen:>7}  "
              f"{nonce:>8}  {diff:>8.4f}  {tstr}  {adder_s}")

    if verbose and gs:
        print(f"          gapstart:  {short_gapstart(gs, 32)}")
        print(f"          adder:     {adder}")
        print(f"          hash:      {bhash}")


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


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Čita Gapcoin blokove putem RPC-a")
    parser.add_argument("-n", "--count", type=int, default=50,
                        help="Broj zadnjih blokova (default: 50)")
    parser.add_argument("-s", "--start", type=int, default=None,
                        help="Početni blok (height)")
    parser.add_argument("-e", "--end", type=int, default=None,
                        help="Krajnji blok (height, default: vrh lanca)")
    parser.add_argument("--min-merit", type=float, default=0.0,
                        help="Prikaži samo blokove s merit >= X")
    parser.add_argument("--min-shift", type=int, default=0,
                        help="Prikaži samo blokove s shift >= X")
    parser.add_argument("--adder", type=str, default=None,
                        help="Filtriraj po adder adresi (puna ili prefiks)")
    parser.add_argument("--csv", action="store_true",
                        help="CSV output (height,shift,merit,gaplen,nonce,diff,time,adder,hash,gapstart)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ispiši i gapstart i hash bloka")
    parser.add_argument("--follow", "-f", action="store_true",
                        help="Prati nove blokove uživo (Ctrl+C za izlaz)")
    parser.add_argument("--records", "-r", action="store_true",
                        help="Preuzmi rekorde s primegaps.cloudygo.com i označi rekordne blokove")
    parser.add_argument("--records-url", type=str, default=MERITS_URL,
                        help=f"URL merits.txt (default: {MERITS_URL})")
    parser.add_argument("--records-only", action="store_true",
                        help="Prikaži samo blokove koji su rekord (implicira --records)")
    parser.add_argument("--export-records", type=str, default=None, metavar="FILE",
                        help="Spremi rekordne blokove u FILE za upload na primegaps.cloudygo.com"
                             " (format: gap merit prime_start, po jedan rekord u redu; implicira --records)")
    parser.add_argument("--rpc-url", type=str, default=None,
                        help="RPC URL (default: iz gapcoin.conf)")
    parser.add_argument("--rpc-user", type=str, default=None)
    parser.add_argument("--rpc-pass", type=str, default=None)
    args = parser.parse_args()

    # Load conf
    conf = load_conf()
    if args.records_only:
        args.records = True
    if args.export_records:
        args.records = True

    rpc_host = conf.get("rpcconnect", "127.0.0.1")
    rpc_port = conf.get("rpcport", "31397")
    rpc_user = args.rpc_user or conf.get("rpcuser", "")
    rpc_pass = args.rpc_pass or conf.get("rpcpassword", "")
    rpc_url  = args.rpc_url or f"http://{rpc_host}:{rpc_port}/"

    rpc = make_rpc(rpc_url, rpc_user, rpc_pass)

    # Fetch record list if requested
    rec_db = None
    if args.records:
        rec_db = fetch_records(args.records_url)

    # Sanity check
    try:
        tip = rpc("getblockcount")
    except Exception as ex:
        print(f"RPC nedostupan: {ex}", file=sys.stderr)
        sys.exit(1)

    if not args.csv:
        print(f"# Gapcoin blockchain — vrh lanca: {tip}")
        print(f"# RPC: {rpc_url}")
        if rec_db is not None:
            print(f"# Rekorda u bazi: {len(rec_db):,}")

    # Determine block range
    if args.start is not None:
        start = args.start
        end   = args.end if args.end is not None else tip
    elif args.end is not None:
        start = max(0, args.end - args.count + 1)
        end   = args.end
    else:
        end   = tip
        start = max(0, end - args.count + 1)

    if not args.csv:
        print(f"# Raspon: {start} – {end}  ({end-start+1} blokova)\n")
        print(HEADER if rec_db is not None else HEADER_NOREC)
        print(SEP if rec_db is not None else SEP_SHORT)

    if args.csv:
        if rec_db is not None:
            print("height,shift,merit,gaplen,nonce,difficulty,time_unix,is_record,record_merit,delta,adder,hash,gapstart")
        else:
            print("height,shift,merit,gaplen,nonce,difficulty,time_unix,adder,hash,gapstart")

    printed = 0
    export_rows = []   # list of (gap, merit, prime_start, height) for --export-records
    for height in range(start, end + 1):
        try:
            blk = fetch_block(rpc, height)
        except Exception as ex:
            if not args.csv:
                print(f"  [ERR height={height}]: {ex}", file=sys.stderr)
            continue

        # Apply filters
        merit  = blk.get("merit", 0.0)
        shift  = blk.get("shift", 0)
        adder  = blk.get("adder", "")
        gaplen = blk.get("gaplen", 0)
        if merit < args.min_merit:
            continue
        if shift < args.min_shift:
            continue
        if args.adder and not adder.startswith(args.adder):
            continue

        # --records-only / --export-records: skip non-records
        rec_merit_val = rec_db.get(gaplen, (None, None))[0] if rec_db is not None else None
        is_rec = rec_merit_val is not None and merit > rec_merit_val
        if (args.records_only or args.export_records) and rec_db is not None:
            if not is_rec:
                continue

        print_block(blk, csv=args.csv, verbose=args.verbose, rec_db=rec_db)
        printed += 1

        # Collect for --export-records
        if args.export_records and is_rec:
            gs = blk.get("gapstart", "")
            if gs:
                export_rows.append((gaplen, merit, gs, height))

    if not args.csv:
        print(SEP if rec_db is not None else SEP_SHORT)
        print(f"# Prikazano: {printed} blokova")

    # Write export file if requested
    if args.export_records:
        _write_export(args.export_records, export_rows)
        print(f"# Export: {len(export_rows)} rekord(a) zapisano u {args.export_records}", file=sys.stderr)

    # --follow mode: watch for new blocks
    if args.follow:
        if not args.csv:
            print("\n# Pratim nove blokove (Ctrl+C za izlaz)...")
        last_tip = tip
        try:
            while True:
                time.sleep(10)
                try:
                    new_tip = rpc("getblockcount")
                except Exception:
                    continue
                if new_tip > last_tip:
                    for h in range(last_tip + 1, new_tip + 1):
                        try:
                            blk = fetch_block(rpc, h)
                        except Exception:
                            continue
                        merit  = blk.get("merit", 0.0)
                        shift  = blk.get("shift", 0)
                        adder  = blk.get("adder", "")
                        if merit < args.min_merit:
                            continue
                        if shift < args.min_shift:
                            continue
                        if args.adder and not adder.startswith(args.adder):
                            continue
                        gaplen = blk.get("gaplen", 0)
                        rec_merit_val_f = rec_db.get(gaplen, (None, None))[0] if rec_db is not None else None
                        is_rec_f = rec_merit_val_f is not None and merit > rec_merit_val_f
                        if (args.records_only or args.export_records) and rec_db is not None:
                            if not is_rec_f:
                                continue
                        print_block(blk, csv=args.csv, verbose=args.verbose, rec_db=rec_db)
                        # Append to export file live
                        if args.export_records and is_rec_f:
                            gs = blk.get("gapstart", "")
                            if gs:
                                _write_export_append(args.export_records, gaplen, merit, gs, h)
                                print(f"# Export: rekord height={h} dodan u {args.export_records}", file=sys.stderr)
                        # Update in-memory rec_db if this is a new record
                        if rec_db is not None and merit > rec_db.get(gaplen, (0,))[0]:
                            rec_db[gaplen] = (merit, "(local)")
                        sys.stdout.flush()
                    last_tip = new_tip
        except KeyboardInterrupt:
            if not args.csv:
                print("\n# Izlaz.")


if __name__ == "__main__":
    main()
