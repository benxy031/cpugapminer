#!/usr/bin/env python3
"""
Phase-A CRT evaluator: compare CRT files by estimated probability of finding
at least one forward gap >= G in a finite scan window.

Model (fast approximation):
- Build CRT survivors in [1, W] where W = ceil(window_factor * G).
- Treat each survivor as independently prime with p = 1/log(N),
  log(N) ~= (256 + shift) * ln(2).
- Estimate:
    P(gap >= G and <= W) = P(no prime in [1, G-1]) * P(at least one prime in [G, W]).

This is intended for A/B ranking of CRT files, not absolute real-world odds.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

LN2 = math.log(2.0)


@dataclass
class CRTFile:
    path: str
    n_primes: int
    merit: float
    shift: int
    gap_target: int
    n_candidates: int
    pairs: List[Tuple[int, int]]


@dataclass
class MeritEval:
    merit: float
    gap: int
    window: int
    before: int
    after: int
    total: int
    prob: float


def parse_crt_file(path: str) -> CRTFile:
    n_primes = 0
    merit = 0.0
    shift = 0
    gap_target = 0
    n_candidates = 0
    pairs: List[Tuple[int, int]] = []

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2 and parts[0] == "n_primes":
                n_primes = int(parts[1])
                continue
            if len(parts) == 2 and parts[0] == "merit":
                merit = float(parts[1])
                continue
            if len(parts) == 2 and parts[0] == "shift":
                shift = int(parts[1])
                continue
            if len(parts) == 2 and parts[0] == "gap_target":
                gap_target = int(parts[1])
                continue
            if len(parts) == 2 and parts[0] == "n_candidates":
                n_candidates = int(parts[1])
                continue
            if len(parts) >= 2:
                try:
                    p = int(parts[0])
                    o = int(parts[1])
                except ValueError:
                    continue
                if p >= 2:
                    pairs.append((p, o))

    if not pairs:
        raise ValueError(f"{path}: no prime/offset pairs found")

    if n_primes <= 0:
        n_primes = len(pairs)

    return CRTFile(
        path=path,
        n_primes=n_primes,
        merit=merit,
        shift=shift,
        gap_target=gap_target,
        n_candidates=n_candidates,
        pairs=pairs,
    )


def merit_to_gap(merit: float, shift: int) -> int:
    return int(math.ceil(merit * (256.0 + float(shift)) * LN2))


def prime_probability(shift: int) -> float:
    logbase = (256.0 + float(shift)) * LN2
    return 1.0 / logbase


def survivor_split_counts(pairs: Sequence[Tuple[int, int]], gap: int, window: int) -> Tuple[int, int, int]:
    if window < gap:
        window = gap
    covered = bytearray(window + 1)

    for p, o in pairs:
        if p <= 1:
            continue
        r = o % p
        if r == 0:
            start = p
        else:
            start = r
        for d in range(start, window + 1, p):
            covered[d] = 1

    before = 0
    after = 0
    for d in range(1, window + 1):
        if covered[d]:
            continue
        if d < gap:
            before += 1
        else:
            after += 1

    return before, after, before + after


def estimate_gap_probability(before: int, after: int, p_prime: float) -> float:
    if after <= 0:
        return 0.0

    if p_prime <= 0.0 or p_prime >= 1.0:
        return 0.0

    log_q = math.log1p(-p_prime)
    p_no_before = math.exp(before * log_q)
    p_none_after = math.exp(after * log_q)
    prob = p_no_before * (1.0 - p_none_after)

    if prob < 0.0:
        return 0.0
    if prob > 1.0:
        return 1.0
    return prob


def evaluate_file(
    crt: CRTFile,
    merits: Sequence[float],
    shift_override: int,
    window_factor: float,
    window_cap: int,
) -> List[MeritEval]:
    shift = shift_override if shift_override > 0 else crt.shift
    if shift <= 0:
        raise ValueError(
            f"{crt.path}: missing shift header; pass --shift to evaluate this file"
        )

    p_prime = prime_probability(shift)
    out: List[MeritEval] = []

    for m in merits:
        gap = merit_to_gap(m, shift)
        window = int(math.ceil(window_factor * float(gap)))
        if window < gap:
            window = gap
        if window_cap > 0 and window > window_cap:
            window = window_cap
        before, after, total = survivor_split_counts(crt.pairs, gap, window)
        prob = estimate_gap_probability(before, after, p_prime)
        out.append(MeritEval(m, gap, window, before, after, total, prob))

    return out


def geometric_mean(values: Iterable[float], floor: float = 1e-300) -> float:
    vals = list(values)
    if not vals:
        return 0.0
    s = 0.0
    for v in vals:
        s += math.log(max(v, floor))
    return math.exp(s / float(len(vals)))


def short_name(path: str) -> str:
    return os.path.basename(path)


def build_merit_list(min_merit: float, max_merit: float, step: float) -> List[float]:
    merits: List[float] = []
    m = min_merit
    while m <= max_merit + 1e-12:
        merits.append(round(m, 6))
        m += step
    return merits


def winner_bands(merits: Sequence[float], winners: Sequence[str]) -> List[Tuple[float, float, str]]:
    if not merits or not winners or len(merits) != len(winners):
        return []

    bands: List[Tuple[float, float, str]] = []
    start = merits[0]
    end = merits[0]
    cur = winners[0]

    for i in range(1, len(merits)):
        if winners[i] == cur:
            end = merits[i]
            continue
        bands.append((start, end, cur))
        start = merits[i]
        end = merits[i]
        cur = winners[i]
    bands.append((start, end, cur))
    return bands


def write_csv(
    path: str,
    merits: Sequence[float],
    files_sorted: Sequence[CRTFile],
    evals: Dict[str, List[MeritEval]],
    winners: Sequence[str],
    winner_probs: Sequence[float],
) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        header = ["merit", "gap", "window", "winner", "winner_prob"]
        for crt in files_sorted:
            header.append(f"prob:{short_name(crt.path)}")
        writer.writerow(header)

        for i, m in enumerate(merits):
            row = [
                f"{m:.6f}",
                str(evals[files_sorted[0].path][i].gap),
                str(evals[files_sorted[0].path][i].window),
                winners[i],
                f"{winner_probs[i]:.12e}",
            ]
            for crt in files_sorted:
                row.append(f"{evals[crt.path][i].prob:.12e}")
            writer.writerow(row)


def file_win_bands(
    merits: Sequence[float],
    winners: Sequence[str],
    file_name: str,
) -> str:
    bands: List[str] = []
    start = None
    end = None
    for i, m in enumerate(merits):
        if winners[i] == file_name:
            if start is None:
                start = m
                end = m
            else:
                end = m
        else:
            if start is not None:
                if abs(start - end) < 1e-12:
                    bands.append(f"{start:.2f}")
                else:
                    bands.append(f"{start:.2f}-{end:.2f}")
                start = None
                end = None
    if start is not None:
        if abs(start - end) < 1e-12:
            bands.append(f"{start:.2f}")
        else:
            bands.append(f"{start:.2f}-{end:.2f}")
    return ";".join(bands)


def write_summary_csv(
    path: str,
    ranking: Sequence[Tuple[float, CRTFile]],
    merits: Sequence[float],
    winners: Sequence[str],
    evals: Dict[str, List[MeritEval]],
) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "rank",
                "file",
                "shift",
                "n_primes",
                "gap_target",
                "n_candidates",
                "geo_mean_prob",
                "wins",
                "win_bands",
            ]
        )
        for idx, (gm, crt) in enumerate(ranking, 1):
            name = short_name(crt.path)
            wins = sum(1 for w in winners if w == name)
            bands = file_win_bands(merits, winners, name)
            shift_used = crt.shift if crt.shift > 0 else ""
            writer.writerow(
                [
                    idx,
                    name,
                    shift_used,
                    crt.n_primes,
                    crt.gap_target,
                    crt.n_candidates,
                    f"{gm:.12e}",
                    wins,
                    bands,
                ]
            )


def build_phase3_payload(
    ranking: Sequence[Tuple[float, CRTFile]],
    merits: Sequence[float],
    winners: Sequence[str],
    bands: Sequence[Tuple[float, float, str]],
    args: argparse.Namespace,
) -> Dict[str, object]:
    ranked_files = []
    for idx, (gm, crt) in enumerate(ranking, 1):
        ranked_files.append(
            {
                "rank": idx,
                "file": short_name(crt.path),
                "path": crt.path,
                "shift": crt.shift,
                "n_primes": crt.n_primes,
                "gap_target": crt.gap_target,
                "n_candidates": crt.n_candidates,
                "geo_mean_prob": gm,
            }
        )

    merit_bands = []
    for lo, hi, name in bands:
        merit_bands.append(
            {
                "merit_min": lo,
                "merit_max": hi,
                "file": name,
            }
        )

    payload: Dict[str, object] = {
        "phase": "phase3-multi-target",
        "model": "independent-survivor-approx",
        "params": {
            "merit_min": args.merit_min,
            "merit_max": args.merit_max,
            "merit_step": args.merit_step,
            "window_factor": args.window_factor,
            "window_cap": args.window_cap,
            "shift_override": args.shift,
        },
        "grid_points": len(merits),
        "ranked_files": ranked_files,
        "recommended_bands": merit_bands,
        "default_file": ranked_files[0]["file"] if ranked_files else "",
    }
    return payload


def write_phase3_json(path: str, payload: Dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")


def write_phase3_selector_script(path: str,
                                 payload: Dict[str, object]) -> None:
    bands = payload.get("recommended_bands", [])
    default_file = str(payload.get("default_file", ""))

    lines: List[str] = []
    lines.append("#!/usr/bin/env bash")
    lines.append("set -euo pipefail")
    lines.append("")
    lines.append("# Auto-generated by tools/eval_crt_merit.py (Phase 3)")
    lines.append("# Usage when sourced: choose_crt_file <target_merit>")
    lines.append("# Usage as CLI: ./select_crt_<tag>.sh <target_merit>")
    lines.append("choose_crt_file() {")
    lines.append("  local merit=\"${1:-}\"")
    lines.append("  if [[ -z \"$merit\" ]]; then")
    lines.append("    echo \"usage: choose_crt_file <target_merit>\" >&2")
    lines.append("    return 2")
    lines.append("  fi")
    lines.append("")

    for i, b in enumerate(bands):
        lo = float(b["merit_min"])
        hi = float(b["merit_max"])
        f = str(b["file"])
        cmp_expr = f'awk "BEGIN{{exit !($merit >= {lo:.6f} && $merit <= {hi:.6f})}}"'
        prefix = "  if" if i == 0 else "  elif"
        lines.append(f"{prefix} {cmp_expr}; then")
        lines.append(f"    echo \"{f}\"")

    lines.append("  else")
    if default_file:
        lines.append(f"    echo \"{default_file}\"")
    else:
        lines.append("    echo \"\"")
    lines.append("  fi")
    lines.append("}")
    lines.append("")
    lines.append("# Example:")
    lines.append("# CRT_FILE=$(choose_crt_file 28.0)")
    lines.append("")
    lines.append("if [[ \"${BASH_SOURCE[0]}\" == \"$0\" ]]; then")
    lines.append("  merit_arg=\"${1:-}\"")
    lines.append("  if [[ \"$merit_arg\" == \"choose_crt_file\" ]]; then")
    lines.append("    shift")
    lines.append("    merit_arg=\"${1:-}\"")
    lines.append("  fi")
    lines.append("  choose_crt_file \"$merit_arg\"")
    lines.append("fi")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)


def phase3_auto_tag(payload: Dict[str, object]) -> str:
    ranked = payload.get("ranked_files", [])
    if isinstance(ranked, list) and ranked:
        top = ranked[0]
        if isinstance(top, dict):
            name = str(top.get("file", ""))
            m = re.search(r"s\d+", name)
            if m:
                return m.group(0)
            stem = os.path.splitext(name)[0]
            stem = re.sub(r"[^A-Za-z0-9_\-]", "_", stem)
            if stem:
                return stem
    return "auto"


def write_phase3_run_script(path: str,
                            selector_path: str,
                            payload: Dict[str, object]) -> None:
    default_file = str(payload.get("default_file", ""))

    lines: List[str] = []
    lines.append("#!/usr/bin/env bash")
    lines.append("set -euo pipefail")
    lines.append("")
    lines.append("# Auto-generated run helper from Phase 3 portfolio")
    lines.append("# Usage:")
    lines.append("#   scripts/run_auto_crt_<tag>.sh [target_merit] [--print|--launch] [-- <gap_miner args...>]")
    lines.append("# Examples:")
    lines.append("#   scripts/run_auto_crt_s512.sh 28 --launch -- --rpc-url http://127.0.0.1:31397 --rpc-user u --rpc-pass p --shift 512")
    lines.append("#   TARGET_MERIT=27 scripts/run_auto_crt_s512.sh --print")
    lines.append(f"source \"{selector_path}\"")
    lines.append("")
    lines.append("MODE=\"${AUTO_CRT_MODE:-print}\"")
    lines.append("TARGET_MERIT=\"${TARGET_MERIT:-}\"")
    lines.append("if [[ $# -gt 0 && \"${1:-}\" != --* ]]; then")
    lines.append("  TARGET_MERIT=\"$1\"")
    lines.append("  shift")
    lines.append("fi")
    lines.append("")
    lines.append("while [[ $# -gt 0 ]]; do")
    lines.append("  case \"$1\" in")
    lines.append("    --launch) MODE=launch; shift ;;")
    lines.append("    --print) MODE=print; shift ;;")
    lines.append("    --) shift; break ;;")
    lines.append("    *) echo \"Unknown option: $1\" >&2; exit 2 ;;")
    lines.append("  esac")
    lines.append("done")
    lines.append("")
    lines.append("EXTRA_ARGS=(\"$@\")")
    lines.append("")
    lines.append("if [[ -n \"$TARGET_MERIT\" ]]; then")
    lines.append("  CRT_FILE=$(choose_crt_file \"$TARGET_MERIT\")")
    lines.append("else")
    if default_file:
        lines.append(f"  CRT_FILE=\"{default_file}\"")
    else:
        lines.append("  CRT_FILE=\"\"")
    lines.append("fi")
    lines.append("")
    lines.append("if [[ -z \"${CRT_FILE}\" ]]; then")
    lines.append("  echo \"Could not resolve CRT file\" >&2")
    lines.append("  exit 2")
    lines.append("fi")
    lines.append("")
    lines.append("CMD=(bin/gap_miner --crt-file \"crt/${CRT_FILE}\")")
    lines.append("if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then")
    lines.append("  CMD+=(\"${EXTRA_ARGS[@]}\")")
    lines.append("fi")
    lines.append("")
    lines.append("echo \"Using CRT file: ${CRT_FILE}\" >&2")
    lines.append("echo \"Mode: ${MODE}\" >&2")
    lines.append("")
    lines.append("if [[ \"$MODE\" == \"launch\" ]]; then")
    lines.append("  if [[ ${#EXTRA_ARGS[@]} -eq 0 ]]; then")
    lines.append("    echo \"No gap_miner args provided. Pass them after '--'.\" >&2")
    lines.append("    echo \"Example: $0 28 --launch -- --rpc-url ... --rpc-user ... --rpc-pass ... --shift 512\" >&2")
    lines.append("    exit 2")
    lines.append("  fi")
    lines.append("  echo \"Launching: ${CMD[*]}\" >&2")
    lines.append("  exec \"${CMD[@]}\"")
    lines.append("else")
    lines.append("  echo \"Run command:\" >&2")
    lines.append("  printf '  %q ' \"${CMD[@]}\" >&2")
    lines.append("  echo >&2")
    lines.append("  echo \"Use --launch to execute directly.\" >&2")
    lines.append("fi")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate and rank CRT files by merit-conditioned gap probability estimate."
    )
    parser.add_argument("files", nargs="*", help="CRT text files to evaluate")
    parser.add_argument(
        "--glob",
        action="append",
        default=[],
        help="Glob pattern for CRT files (can repeat), e.g. 'crt/crt_s512_*.txt'",
    )
    parser.add_argument(
        "--shift",
        type=int,
        default=0,
        help="Override shift for all files (otherwise use shift from CRT header)",
    )
    parser.add_argument("--merit-min", type=float, default=20.0)
    parser.add_argument("--merit-max", type=float, default=32.0)
    parser.add_argument("--merit-step", type=float, default=1.0)
    parser.add_argument(
        "--window-factor",
        type=float,
        default=2.0,
        help="Window W = ceil(window_factor * G), where G is target gap",
    )
    parser.add_argument(
        "--window-cap",
        type=int,
        default=0,
        help="Optional hard cap for W (0 = no cap)",
    )
    parser.add_argument(
        "--top-per-merit",
        type=int,
        default=3,
        help="How many top files to print per merit row",
    )
    parser.add_argument(
        "--csv-out",
        default="",
        help="Optional CSV output path for per-merit probabilities and winners",
    )
    parser.add_argument(
        "--summary-csv-out",
        default="",
        help="Optional summary CSV path (one row per CRT file with rank and win bands)",
    )
    parser.add_argument(
        "--phase3-json-out",
        default="",
        help="Optional Phase-3 JSON output with ranked files and merit-band mapping",
    )
    parser.add_argument(
        "--phase3-selector-out",
        default="",
        help="Optional bash script output with choose_crt_file <target_merit>",
    )
    parser.add_argument(
        "--phase3-run-script-out",
        default="",
        help="Optional run-helper script output path (uses selector + default #1 file)",
    )
    parser.add_argument(
        "--phase3-run-script-auto-name",
        action="store_true",
        help="Auto-name run-helper script as scripts/run_auto_crt_<tag>.sh where tag comes from #1 file (e.g. s512)",
    )
    args = parser.parse_args()

    paths: List[str] = []
    paths.extend(args.files)
    for pat in args.glob:
        paths.extend(sorted(glob.glob(pat)))

    # Keep order stable but unique.
    seen: Dict[str, int] = {}
    unique_paths: List[str] = []
    for p in paths:
        if p not in seen:
            seen[p] = 1
            unique_paths.append(p)

    if not unique_paths:
        print("No CRT files provided. Use positional files and/or --glob.", file=sys.stderr)
        return 2

    if args.merit_step <= 0.0:
        print("--merit-step must be > 0", file=sys.stderr)
        return 2
    if args.window_factor < 1.0:
        print("--window-factor must be >= 1", file=sys.stderr)
        return 2
    if args.top_per_merit < 1:
        print("--top-per-merit must be >= 1", file=sys.stderr)
        return 2

    merits = build_merit_list(args.merit_min, args.merit_max, args.merit_step)
    if not merits:
        print("Empty merit grid.", file=sys.stderr)
        return 2

    files: List[CRTFile] = []
    for p in unique_paths:
        try:
            files.append(parse_crt_file(p))
        except Exception as exc:
            print(f"Skip {p}: {exc}", file=sys.stderr)

    if not files:
        print("No valid CRT files parsed.", file=sys.stderr)
        return 2

    evals: Dict[str, List[MeritEval]] = {}
    for f in files:
        evals[f.path] = evaluate_file(
            f,
            merits,
            args.shift,
            args.window_factor,
            args.window_cap,
        )

    ranking = []
    for f in files:
        probs = [x.prob for x in evals[f.path]]
        gm = geometric_mean(probs)
        ranking.append((gm, f))

    ranking.sort(key=lambda x: x[0], reverse=True)

    print("CRT evaluator (Phase A)\n")
    print(
        "Model: P(gap>=G, <=W) = P(no prime in [1,G-1]) * P(any prime in [G,W]); "
        "independent survivor approximation"
    )
    print(
        f"Merits: {args.merit_min:g}..{args.merit_max:g} step {args.merit_step:g}  "
        f"window_factor={args.window_factor:g}"
        + (f"  window_cap={args.window_cap}" if args.window_cap > 0 else "")
    )
    if args.shift > 0:
        print(f"Shift override: {args.shift}")
    print()

    print("Summary ranking (geometric mean probability over merit grid):")
    print(
        "rank  file                              shift  n_primes  gap_target  n_candidates  geo_mean_P"
    )
    for idx, (gm, f) in enumerate(ranking, 1):
        shift_used = args.shift if args.shift > 0 else f.shift
        print(
            f"{idx:>4}  {short_name(f.path):<32}  {shift_used:>5}  {f.n_primes:>8}  "
            f"{f.gap_target:>10}  {f.n_candidates:>12}  {gm:>10.3e}"
        )

    print("\nTop files per merit:")
    winners: List[str] = []
    winner_probs: List[float] = []
    for mi, m in enumerate(merits):
        row = []
        for f in files:
            ev = evals[f.path][mi]
            row.append((ev.prob, f, ev))
        row.sort(key=lambda x: x[0], reverse=True)
        top = row[: max(1, args.top_per_merit)]
        winners.append(short_name(row[0][1].path))
        winner_probs.append(row[0][0])
        entries = []
        for prob, f, ev in top:
            entries.append(f"{short_name(f.path)}={prob:.3e}")
        gap = top[0][2].gap if top else 0
        print(f"m={m:>5.2f}  G={gap:>6}  " + "  ".join(entries))

    bands = winner_bands(merits, winners)
    print("\nRecommended file by merit band (consecutive winners):")
    for lo, hi, name in bands:
        if abs(lo - hi) < 1e-12:
            print(f"m={lo:.2f} -> {name}")
        else:
            print(f"m={lo:.2f}..{hi:.2f} -> {name}")

    if args.csv_out:
        sorted_files = [f for _, f in ranking]
        write_csv(args.csv_out, merits, sorted_files, evals, winners, winner_probs)
        print(f"\nWrote CSV: {args.csv_out}")

    if args.summary_csv_out:
        write_summary_csv(args.summary_csv_out, ranking, merits, winners, evals)
        print(f"Wrote summary CSV: {args.summary_csv_out}")

    if args.phase3_json_out or args.phase3_selector_out:
        payload = build_phase3_payload(ranking, merits, winners, bands, args)
        if args.phase3_json_out:
            write_phase3_json(args.phase3_json_out, payload)
            print(f"Wrote Phase-3 JSON: {args.phase3_json_out}")
        if args.phase3_selector_out:
            write_phase3_selector_script(args.phase3_selector_out, payload)
            print(f"Wrote Phase-3 selector script: {args.phase3_selector_out}")

        run_script_path = args.phase3_run_script_out
        if args.phase3_run_script_auto_name:
            tag = phase3_auto_tag(payload)
            run_script_path = f"scripts/run_auto_crt_{tag}.sh"

        if run_script_path:
            selector_for_run = args.phase3_selector_out
            if not selector_for_run:
                selector_for_run = "scripts/select_crt_auto.sh"
                write_phase3_selector_script(selector_for_run, payload)
                print(f"Wrote Phase-3 selector script: {selector_for_run}")

            write_phase3_run_script(run_script_path, selector_for_run, payload)
            print(f"Wrote Phase-3 run script: {run_script_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
