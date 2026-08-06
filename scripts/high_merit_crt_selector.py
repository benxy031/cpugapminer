#!/usr/bin/env python3
"""High-merit CRT selector for Gapcoin mining campaigns.

This tool extends the existing independent-survivor model with a multi-factor
score intended for merit-30+ search planning:

- Base probability from a Cramer-style independent-prime approximation.
- Hardy-Littlewood (HL) large-gap factor for the target gap size.
- A Cramer-Granville rarity penalty for very aggressive gap/log^2 ratios.
- Simple cost penalties (n_candidates and n_primes) as CPU/GPU workload proxies.

It ranks CRT files per target merit and emits practical launch commands.
The model is heuristic and should be used for ranking/A-B selection, not as an
absolute probability oracle.
"""

from __future__ import annotations

import argparse
import glob
import math
import os
import statistics
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

LN2 = math.log(2.0)
EPS = 1e-300


@dataclass
class CRTFile:
    path: str
    merit: float
    shift: int
    gap_target: int
    n_candidates: int
    n_primes: int
    pairs: List[Tuple[int, int]]


@dataclass
class MeritScore:
    merit: float
    gap: int
    window: int
    before: int
    after: int
    surv_total: int
    base_prob: float
    hl_factor: float
    cg_ratio: float
    cost_penalty: float
    score: float


def parse_crt_file(path: str) -> CRTFile:
    merit = 0.0
    shift = 0
    gap_target = 0
    n_candidates = 0
    n_primes = 0
    pairs: List[Tuple[int, int]] = []

    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
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
            if len(parts) == 2 and parts[0] == "n_primes":
                n_primes = int(parts[1])
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
    if shift <= 0:
        raise ValueError(f"{path}: missing shift header")

    return CRTFile(
        path=path,
        merit=merit,
        shift=shift,
        gap_target=gap_target,
        n_candidates=n_candidates,
        n_primes=n_primes,
        pairs=pairs,
    )


def merit_to_gap(merit: float, shift: int) -> int:
    return int(math.ceil(merit * (256.0 + float(shift)) * LN2))


def prime_probability(shift: int) -> float:
    logbase = (256.0 + float(shift)) * LN2
    if logbase <= 1.0:
        return 0.0
    return 1.0 / logbase


def survivor_split_counts(
    pairs: Sequence[Tuple[int, int]],
    gap: int,
    window: int,
) -> Tuple[int, int, int]:
    if window < gap:
        window = gap

    covered = bytearray(window + 1)
    for prime, offset in pairs:
        if prime <= 1:
            continue
        start = offset % prime
        if start == 0:
            start = prime
        for d in range(start, window + 1, prime):
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
    if after <= 0 or p_prime <= 0.0 or p_prime >= 1.0:
        return 0.0

    log_q = math.log1p(-p_prime)
    p_no_before = math.exp(before * log_q)
    p_none_after = math.exp(after * log_q)
    prob = p_no_before * (1.0 - p_none_after)
    return max(0.0, min(1.0, prob))


def hl_gap_factor(gap: int) -> float:
    """Approximate HL factor prod_{p odd|gap}(p-1)/(p-2)."""
    if gap < 2 or (gap & 1):
        return 1.0

    rem = gap
    factor = 1.0

    p = 3
    while p * p <= rem:
        if rem % p == 0:
            factor *= (p - 1.0) / (p - 2.0)
            while rem % p == 0:
                rem //= p
        p += 2

    if rem > 2:
        factor *= (rem - 1.0) / (rem - 2.0)

    return factor


def cg_rarity_ratio(gap: int, shift: int) -> float:
    """Cramer-Granville style normalized gap ratio g/log(x)^2."""
    logbase = (256.0 + float(shift)) * LN2
    if logbase <= 0.0:
        return 0.0
    return float(gap) / (logbase * logbase)


def unique_paths(patterns: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def crt_is_eligible_for_merit(crt: CRTFile, merit: float) -> bool:
    return crt.merit + 1e-12 >= merit


def evaluate_crt_for_merit(
    crt: CRTFile,
    merit: float,
    window_factor: float,
    window_cap: int,
    w_hl: float,
    w_cg: float,
    w_candidates: float,
    w_primes: float,
) -> MeritScore:
    gap = merit_to_gap(merit, crt.shift)
    window = int(math.ceil(window_factor * float(gap)))
    if window < gap:
        window = gap
    if window_cap > 0 and window > window_cap:
        window = window_cap

    before, after, surv_total = survivor_split_counts(crt.pairs, gap, window)
    p_prime = prime_probability(crt.shift)
    base_prob = estimate_gap_probability(before, after, p_prime)

    hl = hl_gap_factor(gap)
    cg = cg_rarity_ratio(gap, crt.shift)

    cand_term = math.log1p(float(max(0, crt.n_candidates)))
    prime_term = math.log1p(float(max(0, crt.n_primes)))
    cost_penalty = w_candidates * cand_term + w_primes * prime_term

    # Log-space combination for numerical stability.
    score = math.log(max(base_prob, EPS))
    score += w_hl * math.log(max(hl, 1e-12))
    score -= w_cg * cg
    score -= cost_penalty

    return MeritScore(
        merit=merit,
        gap=gap,
        window=window,
        before=before,
        after=after,
        surv_total=surv_total,
        base_prob=base_prob,
        hl_factor=hl,
        cg_ratio=cg,
        cost_penalty=cost_penalty,
        score=score,
    )


def emit_command(path: str, shift: int, target_merit: float) -> str:
    return (
        f"bin/gap_miner --shift {shift} --threads 8 --cuda 0 --fast-fermat "
        f"--target {target_merit:.2f} --scan-merit {target_merit:.2f} "
        f"--crt-file {path}"
    )


def format_table(rows: Sequence[Tuple[str, MeritScore]], top: int) -> str:
    head = [
        "| rank | file | score | base_prob | hl | cg_ratio | candidates |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    out = []
    for idx, (name, ms) in enumerate(rows[:top], 1):
        out.append(
            "| {rank} | {name} | {score:.6f} | {prob:.3e} | {hl:.3f} | "
            "{cg:.5f} | {cand} |".format(
                rank=idx,
                name=name,
                score=ms.score,
                prob=ms.base_prob,
                hl=ms.hl_factor,
                cg=ms.cg_ratio,
                cand=ms.surv_total,
            )
        )
    return "\n".join(head + out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Rank CRT files for high-merit mining using multi-model heuristics.",
    )
    ap.add_argument("--glob", action="append", default=["crt/*.txt"],
                    help="CRT glob pattern(s), repeatable")
    ap.add_argument("--merit-min", type=float, default=30.0,
                    help="Minimum target merit")
    ap.add_argument("--merit-max", type=float, default=36.0,
                    help="Maximum target merit")
    ap.add_argument("--merit-step", type=float, default=1.0,
                    help="Merit grid step")
    ap.add_argument("--window-factor", type=float, default=2.0,
                    help="Window W = ceil(window-factor * gap)")
    ap.add_argument("--window-cap", type=int, default=0,
                    help="Optional hard cap for W (0 disables cap)")
    ap.add_argument("--weight-hl", type=float, default=0.65,
                    help="Weight for HL factor")
    ap.add_argument("--weight-cg", type=float, default=2.20,
                    help="Weight for Cramer-Granville rarity penalty")
    ap.add_argument("--weight-candidates", type=float, default=0.010,
                    help="Weight for n_candidates penalty")
    ap.add_argument("--weight-primes", type=float, default=0.020,
                    help="Weight for n_primes penalty")
    ap.add_argument("--top", type=int, default=5,
                    help="Rows shown per merit")
    ap.add_argument("--out", default="",
                    help="Optional markdown report path")
    args = ap.parse_args()

    if args.merit_step <= 0.0:
        raise SystemExit("--merit-step must be > 0")
    if args.merit_max < args.merit_min:
        raise SystemExit("--merit-max must be >= --merit-min")

    paths = unique_paths(args.glob)
    if not paths:
        raise SystemExit("No CRT files matched requested glob(s).")

    files: List[CRTFile] = []
    for path in paths:
        try:
            files.append(parse_crt_file(path))
        except Exception as exc:
            print(f"skip {path}: {exc}")

    if not files:
        raise SystemExit("No valid CRT files loaded.")

    merits: List[float] = []
    m = args.merit_min
    while m <= args.merit_max + 1e-12:
        merits.append(round(m, 6))
        m += args.merit_step

    lines: List[str] = []
    lines.append("# High-Merit CRT Selector")
    lines.append("")
    lines.append("Model: log(base_prob) + w_hl*log(HL) - w_cg*(gap/log^2) - cost")
    lines.append("")
    lines.append(
        "Weights: hl={:.3f}, cg={:.3f}, candidates={:.3f}, primes={:.3f}".format(
            args.weight_hl, args.weight_cg, args.weight_candidates, args.weight_primes
        )
    )
    lines.append("")

    winners: List[Tuple[float, str, MeritScore]] = []

    for merit in merits:
        scored: List[Tuple[str, MeritScore]] = []
        for crt in files:
            if not crt_is_eligible_for_merit(crt, merit):
                continue
            ms = evaluate_crt_for_merit(
                crt=crt,
                merit=merit,
                window_factor=args.window_factor,
                window_cap=args.window_cap,
                w_hl=args.weight_hl,
                w_cg=args.weight_cg,
                w_candidates=args.weight_candidates,
                w_primes=args.weight_primes,
            )
            scored.append((os.path.basename(crt.path), ms))

        if not scored:
            lines.append(f"## Merit {merit:.2f}")
            lines.append("")
            lines.append("No eligible CRT files (all file merits below target).")
            lines.append("")
            continue

        scored.sort(key=lambda x: x[1].score, reverse=True)
        winner_name, winner_ms = scored[0]
        winners.append((merit, winner_name, winner_ms))

        lines.append(f"## Merit {merit:.2f}")
        lines.append("")
        lines.append(format_table(scored, top=max(1, args.top)))
        lines.append("")

        winner_path = ""
        winner_shift = 0
        for crt in files:
            if os.path.basename(crt.path) == winner_name:
                winner_path = crt.path
                winner_shift = crt.shift
                break

        lines.append("Recommended launch command:")
        lines.append("")
        lines.append("```sh")
        lines.append(emit_command(winner_path, winner_shift, merit))
        lines.append("```")
        lines.append("")

    if winners:
        best_scores = [w[2].score for w in winners]
        lines.append("## Summary")
        lines.append("")
        lines.append(
            "Median winner score: {:.6f}; min: {:.6f}; max: {:.6f}".format(
                statistics.median(best_scores), min(best_scores), max(best_scores)
            )
        )
        lines.append("")
        lines.append("Winner map:")
        lines.append("")
        lines.append("| merit | winner | score | base_prob |")
        lines.append("|---:|---|---:|---:|")
        for merit, name, ms in winners:
            lines.append(
                "| {m:.2f} | {n} | {s:.6f} | {p:.3e} |".format(
                    m=merit,
                    n=name,
                    s=ms.score,
                    p=ms.base_prob,
                )
            )

    output = "\n".join(lines) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
