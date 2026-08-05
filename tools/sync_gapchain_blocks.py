#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONF = Path.home() / ".gapcoin2606" / "gapcoin.conf"
DEFAULT_DB = Path(__file__).resolve().parents[1] / "gapchain.sqlite3"


def load_rpc_conf(path):
    values = {}
    if not path.exists():
        raise FileNotFoundError(f"RPC config not found: {path}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def make_rpc(url, user, password):
    auth = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}",
    }
    req_id = [0]

    def rpc(method, params=None):
        if params is None:
            params = []
        req_id[0] += 1
        body = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": str(req_id[0]),
                "method": method,
                "params": params,
            }
        ).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            data = json.loads(body_text)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"RPC connection failed: {exc}") from exc
        if data.get("error"):
            raise RuntimeError(str(data["error"]))
        return data["result"]

    return rpc


def connect_db(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gapchain (
            height INTEGER PRIMARY KEY,
            difficulty NUMERIC,
            primesps NUMERIC,
            shift INTEGER,
            adder INTEGER,
            startprime TEXT,
            gapsize INTEGER,
            merit NUMERIC,
            primedigits INTEGER,
            date TEXT,
            time TEXT
        )
        """
    )
    conn.commit()


def get_last_height(conn):
    row = conn.execute("SELECT MAX(height) FROM gapchain").fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])


def parse_block_timestamp(unix_ts):
    dt = datetime.fromtimestamp(int(unix_ts), tz=timezone.utc)
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")


def store_block(conn, block, primesps_value=None):
    height = block.get("height")
    if height is None:
        raise ValueError("Block missing height")

    date_value, time_value = parse_block_timestamp(block.get("time", 0))
    gapstart = block.get("gapstart")
    gaplen = block.get("gaplen")
    adder = block.get("adder")
    # primedigits is derived from the block's startprime/gapstart payload,
    # which is the same source used by the older imported rows.
    primedigits_value = len(str(gapstart)) if gapstart is not None else None
    merit = block.get("merit")
    shift = block.get("shift")
    difficulty = block.get("difficulty")

    conn.execute(
        """
        INSERT INTO gapchain(
            height, difficulty, primesps, shift, adder, startprime,
            gapsize, merit, primedigits, date, time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(height) DO UPDATE SET
            difficulty=excluded.difficulty,
            primesps=excluded.primesps,
            shift=excluded.shift,
            adder=excluded.adder,
            startprime=excluded.startprime,
            gapsize=excluded.gapsize,
            merit=excluded.merit,
            primedigits=excluded.primedigits,
            date=excluded.date,
            time=excluded.time
        """,
        (
            height,
            difficulty,
            primesps_value,
            shift,
            adder,
            str(gapstart) if gapstart is not None else None,
            gaplen,
            merit,
            primedigits_value,
            date_value,
            time_value,
        ),
    )


def fetch_block_with_retry(rpc, height, retries=5, delay=1):
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            block_hash = rpc("getblockhash", [height])
            return rpc("getblock", [block_hash, True])
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(delay)
                continue
            raise RuntimeError(f"failed to fetch height {height} after {retries} attempts: {exc}") from exc


def sync_range(conn, rpc, start, end):
    total = 0
    # The wallet RPC exposes network mining power via getnetworkminingpower;
    # we use that value for the primesps column because the block payload itself
    # does not include a dedicated primesps field.
    mining_power = rpc("getnetworkminingpower")
    for height in range(start, end + 1):
        block = fetch_block_with_retry(rpc, height)
        store_block(conn, block, mining_power)
        conn.commit()
        total += 1
        if total % 100 == 0 or height == end:
            print(f"synced height={height} (progress {total}/{end - start + 1})")
    return total


def parse_args():
    parser = argparse.ArgumentParser(description="Import Gapcoin blocks into gapchain.sqlite3")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    parser.add_argument("--conf", default=str(DEFAULT_CONF), help="Path to gapcoin.conf")
    parser.add_argument("--from-height", type=int, default=None, help="Start importing from this height")
    parser.add_argument("--to-height", type=int, default=None, help="Stop importing at this height")
    parser.add_argument("--watch", action="store_true", help="Keep watching for new blocks")
    parser.add_argument("--poll-seconds", type=int, default=10, help="Polling interval in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    conf_path = Path(args.conf).expanduser()
    conf = load_rpc_conf(conf_path)

    host = conf.get("rpcconnect", "127.0.0.1")
    port = conf.get("rpcport", "31397")
    user = conf.get("rpcuser", "")
    password = conf.get("rpcpassword", "")
    rpc_url = f"http://{host}:{port}/"

    rpc = make_rpc(rpc_url, user, password)
    conn = connect_db(args.db)
    ensure_schema(conn)

    try:
        tip = int(rpc("getblockcount"))
    except Exception as exc:
        print(f"RPC error: {exc}", file=sys.stderr)
        return 1

    if args.from_height is not None:
        start = args.from_height
    else:
        last_height = get_last_height(conn)
        start = (last_height or 0) + 1

    if args.to_height is not None:
        end = min(args.to_height, tip)
    else:
        end = tip

    if start > end:
        print("No new heights to sync")
        return 0

    print(f"Syncing heights {start}..{end} (tip={tip})")
    sync_range(conn, rpc, start, end)

    if args.watch:
        print("Watching for new blocks...")
        while True:
            time.sleep(args.poll_seconds)
            try:
                new_tip = int(rpc("getblockcount"))
            except Exception as exc:
                print(f"RPC poll error: {exc}", file=sys.stderr)
                continue
            if new_tip > end:
                print(f"New tip detected: {new_tip}")
                synced = sync_range(conn, rpc, end + 1, new_tip)
                if synced:
                    end = new_tip

    return 0


if __name__ == "__main__":
    sys.exit(main())
