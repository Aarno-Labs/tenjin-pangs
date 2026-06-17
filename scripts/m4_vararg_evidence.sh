#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  cat >&2 <<'EOF'
usage: scripts/m4_vararg_evidence.sh EXPORT_DIR...

Summarize M4 vararg/function-pointer audit evidence from one or more
`pangs analyze` export directories. Redirect stdout to notes/m4_vararg_evidence.md
when recording a corpus run.
EOF
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 2
fi

histogram() {
  sort | uniq -c | sort -nr | awk '{ printf "- `%s`: %s\n", $2, $1 }'
}

echo "# M4 Vararg Evidence"
echo
echo "Generated from PANGS export directories."
echo

for dir in "$@"; do
  audit="$dir/audit.jsonl"
  components="$dir/components.json"
  metrics="$dir/metrics.json"
  if [[ ! -f "$audit" || ! -f "$components" || ! -f "$metrics" ]]; then
    echo "missing audit.jsonl/components.json/metrics.json in $dir" >&2
    exit 2
  fi

  label="$(basename "$dir")"
  echo "## $label"
  echo
  jq -r '
    "- functions: " + (.functions | tostring),
    "- call edges: " + (.call_edges | tostring),
    "- audit findings: " + (.audit_findings | tostring),
    "- mutable globals rewritable: " + (.in_rewritable_components | tostring) + "/" + (.mutable_globals_total | tostring)
  ' "$metrics"
  echo

  vararg_count="$(jq -r 'select(.kind | startswith("fnptr_varargs")) | .kind' "$audit" | wc -l | tr -d ' ')"
  echo "Vararg audit findings: $vararg_count"
  echo

  echo "### Audit Kinds"
  if [[ "$vararg_count" -eq 0 ]]; then
    echo "- none"
  else
    jq -r 'select(.kind | startswith("fnptr_varargs")) | .kind' "$audit" | histogram
  fi
  echo

  echo "### Affected Prefixes"
  if [[ "$vararg_count" -eq 0 ]]; then
    echo "- none"
  else
    jq -r '
      select(.kind | startswith("fnptr_varargs"))
      | .affected[]
      | split(":")[0]
    ' "$audit" | histogram
  fi
  echo

  echo "### Largest Frozen Components With Vararg Taint"
  jq -r '
    .components[]
    | select(.frozen)
    | . as $component
    | [ .taint[]?.kind | select(startswith("fnptr_varargs")) ] as $kinds
    | select($kinds | length > 0)
    | [
        (.members | length),
        (.mutable_globals | length),
        .id,
        ($kinds | unique | join(","))
      ]
    | @tsv
  ' "$components" \
    | sort -nr \
    | head -n 10 \
    | awk -F '\t' '
        BEGIN { seen = 0 }
        {
          seen = 1
          printf "- `%s`: members=%s mutable_globals=%s kinds=`%s`\n", $3, $1, $2, $4
        }
        END {
          if (!seen) {
            print "- none"
          }
        }
      '
  echo

  echo "### Top Vararg Taint Witnesses"
  jq -r '
    .components[].taint[]?
    | select(.kind | startswith("fnptr_varargs"))
    | [.kind, (.witness // "<none>")]
    | @tsv
  ' "$components" \
    | sort \
    | uniq -c \
    | sort -nr \
    | head -n 20 \
    | awk '
        BEGIN { seen = 0 }
        {
          seen = 1
          count = $1
          kind = $2
          witness = $3
          printf "- `%s` `%s`: %s\n", kind, witness, count
        }
        END {
          if (!seen) {
            print "- none"
          }
        }
      '
  echo
done
