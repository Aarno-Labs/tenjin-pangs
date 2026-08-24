#!/bin/bash
set -u

# Diagnostic-only Phase-0 sweep for 20260824_EXTERNAL_POLICY.md.
# Usage: run_census.sh [bitcode-dir] [output-dir] [jobs]

BC_DIR=${1:-"$HOME/pangs-corpus/_out_bc"}
OUT_DIR=${2:-/tmp/pangs-external-policy-census}
JOBS=${3:-4}
PANGS=${PANGS:-"$HOME/pangs/target/release/pangs"}
REPO_ROOT=${REPO_ROOT:-"$HOME/pangs"}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-600}

mkdir -p "$OUT_DIR"

run_one() {
    local path=$1 name mode start status
    name=${path##*/}
    name=${name%.bc}
    case "$name" in
        lib-*) mode=library ;;
        *) mode=executable ;;
    esac
    start=$SECONDS
    if timeout "$TIMEOUT_SECONDS" "$PANGS" external-policy-census "$path" \
        --build-mode "$mode" \
        --repo-root "$REPO_ROOT" \
        --out "$OUT_DIR/$name.json" >"$OUT_DIR/$name.log" 2>&1; then
        status=ok
    else
        status="fail:$?"
    fi
    printf '%s %s %ss\n' "$status" "$name" "$((SECONDS - start))"
}

export -f run_one
export OUT_DIR PANGS REPO_ROOT TIMEOUT_SECONDS
find "$BC_DIR" -maxdepth 1 -type f -name '*.bc' -print0 \
    | xargs -0 -P "$JOBS" -I{} bash -c 'run_one "$1"' _ {}

