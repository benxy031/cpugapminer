# CRT End-to-End Workflow (Phase A -> Phase 2 -> Phase 3 -> Full Launch)

This document consolidates the full CRT workflow we implemented and used in this repository:

- Phase A: evaluate existing CRT files by merit-band probability model.
- Phase 2: generate new CRT candidates with `bin/gen_crt`.
- Phase 3: build a multi-target portfolio and auto-selection artifacts.
- Full launch mode: auto-pick CRT by target merit and directly run `bin/gap_miner`.

It also records the runtime/telemetry changes made around CRT usage and stats visibility.

## 1) What Was Added

### Runtime and stats clarity

- STATS now includes `focus` target (alongside submit/scan context).
- Wheel stats line is shown only when wheel sieve is actually enabled.
- CRT text-file loading path already sets `g_crt_gap_target` from CRT header (`gap_target`).

### Tooling additions

- `tools/eval_crt_merit.py` became the main Phase A/Phase 3 orchestrator.
- New exports:
  - `--csv-out`
  - `--summary-csv-out`
  - `--phase3-json-out`
  - `--phase3-selector-out`
  - `--phase3-run-script-out`
  - `--phase3-run-script-auto-name`
- Generated script behavior was upgraded to support true full launch mode.

## 2) Phase A - Evaluate Existing CRT Files

Purpose: rank CRT files over a merit grid using a fast, consistent approximation model, then derive winner merit bands.

### Typical command (s512 set)

```bash
tools/eval_crt_merit.py \
  --glob 'crt/crt_s512_*.txt' \
  --shift 512 \
  --merit-min 21 \
  --merit-max 30 \
  --merit-step 1 \
  --csv-out logs/bench_tuning/crt_eval_s512_phaseA.csv \
  --summary-csv-out logs/bench_tuning/crt_eval_s512_phaseA_summary.csv
```

### Main outputs

- Per-merit table (winner per merit row).
- Global ranking by geometric mean probability over configured merit grid.
- Consecutive winner bands used later for auto-selection.

### Example artifacts already produced

- `logs/bench_tuning/crt_eval_s512_phaseA.csv`
- `logs/bench_tuning/crt_eval_s512_phaseA_summary.csv`

## 3) Phase 2 - Generate New CRT Candidate(s)

Purpose: produce new CRT files (often for a specific shift/merit pair) and compare against Phase A leaders.

### Typical generation flow

```bash
make gen_crt

./bin/gen_crt --calc-ctr \
  --ctr-primes <N> --ctr-merit <M> --ctr-bits <B> \
  --ctr-strength <S> --ctr-evolution --ctr-fixed <F> --ctr-ivs <I> \
  --ctr-file crt/<new_file>.txt
```

For recommended ranges and per-shift defaults, use:

- `docs/CRT_GENERATION.md`

### Example artifact already produced

- `crt/crt_s512_m23_phase2_run1.txt`

## 4) Phase 3 - Portfolio Outputs and Selector

Purpose: convert Phase A ranking + winner bands into machine-usable outputs for operations.

### Command pattern

```bash
tools/eval_crt_merit.py \
  --glob 'crt/crt_s512_*.txt' \
  --shift 512 \
  --merit-min 21 --merit-max 30 --merit-step 1 \
  --phase3-json-out logs/bench_tuning/crt_phase3_s512.json \
  --phase3-selector-out scripts/select_crt_s512.sh \
  --phase3-run-script-auto-name
```

### Produced artifacts

- `logs/bench_tuning/crt_phase3_s512.json`
- `scripts/select_crt_s512.sh`
- `scripts/run_auto_crt_s512.sh`

### Selector contract

`choose_crt_file <target_merit>` returns the selected CRT filename from merit bands.
Here `target_merit` means the merit you want to hunt, not the CRT file's internal `gap_target` header.

Example:

```bash
source scripts/select_crt_s512.sh
choose_crt_file 28
```

The selector can also be called directly as a CLI tool:

```bash
./scripts/select_crt_s512.sh 30
./scripts/select_crt_s512.sh choose_crt_file 30
```

## 5) Full Launch Mode (Run Helper)

`run_auto_crt_<tag>.sh` now supports two modes:

- `--print` (default): show final command without executing.
- `--launch`: execute `bin/gap_miner` directly.

### Syntax

```bash
scripts/run_auto_crt_<tag>.sh [target_merit] [--print|--launch] [-- <gap_miner args...>]
```

### Behavior details

- If first positional arg is numeric merit, it is used for band selection.
- If merit is omitted, script falls back to default top-ranked CRT file.
- Extra miner args must be passed after `--`.
- In `--launch` mode, script refuses to run if no extra miner args are provided (safety guard).

### Examples

Preview command only:

```bash
scripts/run_auto_crt_s512.sh 28 --print
```

Launch directly:

```bash
scripts/run_auto_crt_s512.sh 28 --launch -- \
  --rpc-url http://127.0.0.1:31397 \
  --rpc-user <user> \
  --rpc-pass <pass> \
  --shift 512
```

Environment-driven usage:

```bash
TARGET_MERIT=27 scripts/run_auto_crt_s512.sh --print
AUTO_CRT_MODE=launch scripts/run_auto_crt_s512.sh 27 -- --rpc-url ... --rpc-user ... --rpc-pass ... --shift 512
```

## 6) Recommended Operational Loop

1. Generate/collect CRT candidates (`crt/*.txt`).
2. Run Phase A evaluator over target merit band.
3. Export CSV + summary + Phase 3 JSON + selector + run helper.
4. Use run helper in `--print` mode for quick audit.
5. Use run helper in `--launch` mode for production runs.
6. Periodically re-run Phase A as new CRT files are added.

## 7) Notes and Guardrails

- Candidate count alone is not enough. Keep merit-band winner mapping as primary operational signal.
- Keep `--shift` consistent between evaluation and runtime launch profile.
- Use `--print` first after regenerating selector/run scripts.
- Treat the evaluator as ranking guidance; final quality is confirmed in real mining telemetry.

## 8) Related Files

- `tools/eval_crt_merit.py`
- `tools/crt.md`
- `docs/CRT_GENERATION.md`
- `scripts/select_crt_*.sh`
- `scripts/run_auto_crt_*.sh`
