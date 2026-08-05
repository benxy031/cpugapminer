# Test Infrastructure (Differential / Boundary / Replay)

This document defines the staged test flow for cpugapminer correctness work.

## Stage order

1. Differential tests (`make test-differential`)
2. Boundary tests (`make test-boundary`)
3. Replay corpus tests (`make test-replay`)
4. Full bundle (`make test-all`)

## Why this order

- Differential tests catch disagreement between two independent calculation paths.
- Boundary tests catch edge-case math and window-policy mistakes.
- Replay tests validate behavior against pinned deterministic cases from real-style windows.

## Replay corpus workflow

Corpus file:

- `tests/corpus/sievegap_replay_cases.tsv`

Validation:

```sh
make tests/test_replay_sievegap
bash scripts/validate_replay_corpus.sh
```

Regenerate expected values after intentional algorithm change:

```sh
bash scripts/validate_replay_corpus.sh --regen
```

Only regenerate when behavior change is intentional and reviewed.

## CI policy

CI should run staged tests in this exact order and fail fast in stage A/B/C:

- `make -f Makefile.mingw test-differential`
- `make -f Makefile.mingw test-boundary`
- `make -f Makefile.mingw test-replay`

Performance benches remain separate from correctness gates.
