#!/usr/bin/env bash
set -euo pipefail

CORPUS_DIR="${CORPUS_DIR:-$HOME/pangs-corpus/_out_bc}"
OUT_ROOT="${OUT_ROOT:-$(pwd)/ju_out/m1_7}"
PROFILE="${PROFILE:-release}"
PANGS_BIN="${PANGS_BIN:-$(pwd)/target/$PROFILE/pangs}"
STAGE="${STAGE:-steens}"
BUILD_MODE="${BUILD_MODE:-executable}"
RUNS="${RUNS:-5}"

DEFAULT_MODULES=(
  "exe-jq-O0.bc"
  "exe-lua-O0.bc"
  "exe-gifsicle-O0.bc"
)

if [[ $# -gt 0 ]]; then
  MODULES=("$@")
else
  MODULES=("${DEFAULT_MODULES[@]}")
fi

mkdir -p "$OUT_ROOT"

cargo build -p pangs-cli --profile "$PROFILE" >/dev/null

printf 'using corpus: %s\n' "$CORPUS_DIR"
printf 'writing outputs to: %s\n' "$OUT_ROOT"
printf 'profile=%s pangs_bin=%s\n' "$PROFILE" "$PANGS_BIN"
printf 'stage=%s build_mode=%s runs=%s\n' "$STAGE" "$BUILD_MODE" "$RUNS"

for module in "${MODULES[@]}"; do
  input="$CORPUS_DIR/$module"
  if [[ ! -f "$input" ]]; then
    printf 'missing module: %s\n' "$input" >&2
    exit 1
  fi

  stem="${module%.*}"
  outdir="$OUT_ROOT/$stem"
  run_out="$outdir/analyze_out"
  mkdir -p "$outdir"
  rm -rf "$run_out"

  printf '\n=== %s ===\n' "$module"
  /usr/bin/time -f '%e' -o "$outdir/time_once_s.txt" \
    "$PANGS_BIN" analyze "$input" -o "$run_out" \
    --stage "$STAGE" --build-mode "$BUILD_MODE" --validate \
    >"$outdir/analyze.stdout" 2>"$outdir/analyze.stderr"

  "$PANGS_BIN" report "$run_out" | tee "$outdir/report.txt"

  hyperfine \
    --warmup 1 \
    --runs "$RUNS" \
    --export-json "$outdir/hyperfine.json" \
    --prepare "rm -rf '$run_out'" \
    "$PANGS_BIN analyze '$input' -o '$run_out' --stage '$STAGE' --build-mode '$BUILD_MODE' --validate" \
    | tee "$outdir/hyperfine.txt"
done
