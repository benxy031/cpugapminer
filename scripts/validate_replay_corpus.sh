#!/usr/bin/env bash
set -euo pipefail

mode="check"
bin_override=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --regen)
      mode="regen"
      shift
      ;;
    --check)
      mode="check"
      shift
      ;;
    --bin)
      bin_override="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--check|--regen] [--bin <path>]" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
corpus_rel="tests/corpus/sievegap_replay_cases.tsv"
corpus="$repo_root/$corpus_rel"

# Run from repository root so relative paths are stable across local and CI
# invocations. This also avoids passing POSIX absolute paths to MinGW-native
# binaries on Windows, where fopen() may not resolve them.
cd "$repo_root"

if [[ -n "$bin_override" ]]; then
  bin="$bin_override"
elif [[ -x "$repo_root/tests/test_replay_sievegap" ]]; then
  bin="$repo_root/tests/test_replay_sievegap"
elif [[ -x "$repo_root/tests/test_replay_sievegap.exe" ]]; then
  bin="$repo_root/tests/test_replay_sievegap.exe"
else
  echo "Cannot find replay test binary. Build tests/test_replay_sievegap first." >&2
  exit 2
fi

if [[ "$mode" == "regen" ]]; then
  tmp="$(mktemp)"
  "$bin" --generate "$corpus" > "$tmp"
  mv "$tmp" "$corpus"
  echo "Regenerated replay corpus expectations: $corpus"
  exit 0
fi

# Pass the absolute path so MinGW-native binaries (which resolve relative
# paths from their own working directory, not the shell's) can open the file.
"$bin" "$corpus"
