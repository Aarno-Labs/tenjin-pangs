#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  cat >&2 <<'EOF'
usage: scripts/m5_gate_census.sh EXPORT_DIR...

Summarize the M5.0 gate signals from one or more `pangs analyze`
export directories. The census is intentionally conservative: it reports
which unsettled mutable globals look like plausible flow-summary candidates
and which are blocked by symptoms M5a cannot fix directly.
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

echo "# M5.0 Gate Census"
echo
echo "Generated from PANGS export directories."
echo
echo "Interpretation:"
echo
echo '- `known_runtime_writer` is the strongest M5a candidate bucket: a flow-sensitive'
echo "  summary pass could potentially separate init-time writes from post-publish writes."
echo '- `incomplete_initval` may include B1 poisoning, but it first needs source audit;'
echo "  M5a should not be green-lit from this count alone."
echo '- `unknown_runtime_writer` and `exported_global` are not M5a wins without earlier'
echo "  boundary/modeling improvements."
echo

echo "## Summary"
echo
echo "| row | mutable | rewritable | frozen | known runtime writer | incomplete initval | unknown runtime writer | exported | stationary | M5a gate |"
echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"

total_mutable=0
total_rewritable=0
total_runtime=0
total_incomplete=0
total_unknown=0
total_exported=0
total_stationary=0

for dir in "$@"; do
  metrics="$dir/metrics.json"
  globals="$dir/globals.jsonl"
  stationarity="$dir/stationarity.jsonl"
  components="$dir/components.json"
  if [[ ! -f "$metrics" || ! -f "$globals" || ! -f "$stationarity" || ! -f "$components" ]]; then
    echo "missing metrics.json/globals.jsonl/stationarity.jsonl/components.json in $dir" >&2
    exit 2
  fi

  label="$(basename "$dir")"
  label="${label%-andersen}"
  row="$(
    jq -n -r \
    --arg label "$label" \
    --slurpfile globals "$globals" \
    --slurpfile stationarity "$stationarity" \
    --slurpfile metrics "$metrics" '
      ($globals | map(select(.mutable) | .key) | unique) as $mutable
      | ($stationarity
          | map(select(. as $row | ($mutable | index($row.global)) != null) | .reason)
          | group_by(.)
          | map({(.[0]): length})
          | add // {}) as $reasons
      | ($metrics[0].in_rewritable_components // 0) as $rewritable
      | ($mutable | length) as $mutable_count
      | ($reasons.runtime_writer // 0) as $runtime
      | ($reasons.incomplete_initval // 0) as $incomplete
      | ($reasons.unknown_runtime_writer // 0) as $unknown
      | ($reasons.exported_global // 0) as $exported
      | ($reasons.stationary // 0) as $stationary
      | (if $runtime >= 20 then "green"
         elif $runtime > 0 then "sample"
         elif $incomplete > 0 then "audit_incomplete_initval"
         else "no_m5a_signal"
         end) as $gate
      | [$label, $mutable_count, $rewritable, ($mutable_count - $rewritable), $runtime, $incomplete, $unknown, $exported, $stationary, $gate]
      | @tsv
    '
  )"
  IFS=$'\t' read -r row_label mutable rewritable frozen runtime incomplete unknown exported stationary gate <<<"$row"
  printf '| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "$row_label" "$mutable" "$rewritable" "$frozen" "$runtime" "$incomplete" "$unknown" "$exported" "$stationary" "$gate"
  total_mutable=$((total_mutable + mutable))
  total_rewritable=$((total_rewritable + rewritable))
  total_runtime=$((total_runtime + runtime))
  total_incomplete=$((total_incomplete + incomplete))
  total_unknown=$((total_unknown + unknown))
  total_exported=$((total_exported + exported))
  total_stationary=$((total_stationary + stationary))
done

total_frozen=$((total_mutable - total_rewritable))
if [[ "$total_runtime" -ge 20 ]]; then
  m5a_gate="green"
elif [[ "$total_runtime" -gt 0 ]]; then
  m5a_gate="sample"
elif [[ "$total_incomplete" -gt 0 ]]; then
  m5a_gate="audit_incomplete_initval"
else
  m5a_gate="no_m5a_signal"
fi
printf '| **total** | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
  "$total_mutable" "$total_rewritable" "$total_frozen" "$total_runtime" "$total_incomplete" \
  "$total_unknown" "$total_exported" "$total_stationary" "$m5a_gate"

echo
echo "## Gate Decision"
echo
if [[ "$total_runtime" -eq 0 && "$total_incomplete" -gt 0 ]]; then
  echo "M5a is not green-lit from this corpus snapshot. There are no mutable globals whose"
  echo "stationarity verdict is blocked by a known \`runtime_writer\`, so the flow-sensitive"
  echo "summary machinery in \`PLAN-M5.md\` would not currently target a measured population."
  echo
  echo "The dominant earlier blocker is \`incomplete_initval\`: every mutable global in this"
  echo "census falls into that bucket. Use the Initval Diagnostics section below to distinguish"
  echo "ordinary globals with no modeled pointer initializer from explicit B1 poison cases."
elif [[ "$total_runtime" -gt 0 ]]; then
  echo "M5a has a measured known-runtime-writer population. Audit a sample of those rows before"
  echo "building summaries; only green-light M5a if the sample shows flow-insensitive smearing."
else
  echo "M5a has no measured candidate population in this corpus snapshot."
fi
echo
echo "M5b is not green-lit by this census alone; it still requires a client that consumes"
echo "thread-confinement facts."
echo
echo "If the Runtime Mod Evidence section reports unknown mod rows, those rows independently"
echo "block stationarity and should be addressed before M5a flow summaries."

echo
echo "## Runtime Mod Evidence"
echo
echo "| row | unknown mod rows | mutable globals with known mod rows | absence-only initval globals | absence-only without known mod |"
echo "|---|---:|---:|---:|---:|"
for dir in "$@"; do
  globals="$dir/globals.jsonl"
  stationarity="$dir/stationarity.jsonl"
  modrefs="$dir/modref.jsonl"
  label="$(basename "$dir")"
  label="${label%-andersen}"
  jq -n -r \
    --arg label "$label" \
    --slurpfile globals "$globals" \
    --slurpfile stationarity "$stationarity" \
    --slurpfile modrefs "$modrefs" '
      ($globals | map(select(.mutable) | .key) | unique) as $mutable
      | ($stationarity
          | map(select(.reason == "incomplete_initval")
                | select(any(.initval_diagnostics[]?; .reason == "no_modeled_pointer_initializer"))
                | .global)
          | unique) as $absence
      | ($modrefs
          | map(select(.access == "mod" and (.global.name? != null))
                | .global.name)
          | map(select(. as $global | ($mutable | index($global)) != null))
          | unique) as $known_mod_globals
      | ($modrefs
          | map(select(.access == "mod" and (.global.unknown? != null)))
          | length) as $unknown_mod_rows
      | ($absence
          | map(select(. as $global | ($known_mod_globals | index($global)) == null))
          | length) as $absence_without_known_mod
      | "| `\($label)` | \($unknown_mod_rows) | \($known_mod_globals | length) | \($absence | length) | \($absence_without_known_mod) |"
    '
done

echo
echo "## Frozen-Component Taints"
echo
for dir in "$@"; do
  components="$dir/components.json"
  label="$(basename "$dir")"
  label="${label%-andersen}"
  echo "### $label"
  echo
  jq -r '
    .components[]
    | select(.frozen and ((.mutable_globals | length) > 0))
    | .taint[]?.kind
  ' "$components" | histogram
  echo
done

echo "## Initval Diagnostics"
echo
for dir in "$@"; do
  stationarity="$dir/stationarity.jsonl"
  label="$(basename "$dir")"
  label="${label%-andersen}"
  echo "### $label"
  echo
  diagnostic_count="$(
    jq -r '
      select(.reason == "incomplete_initval")
      | .initval_diagnostics[]?.reason
    ' "$stationarity" | wc -l | tr -d ' '
  )"
  if [[ "$diagnostic_count" -eq 0 ]]; then
    echo "- none"
  else
    jq -r '
      select(.reason == "incomplete_initval")
      | .initval_diagnostics[]?.reason
    ' "$stationarity" | histogram
  fi
  echo
done

echo "## Top Runtime Writers"
echo
for dir in "$@"; do
  stationarity="$dir/stationarity.jsonl"
  label="$(basename "$dir")"
  label="${label%-andersen}"
  echo "### $label"
  echo
  runtime_count="$(
    jq -r '
      select(.reason == "runtime_writer")
      | .runtime_writers[]?
      | [.via, (.func // "<unknown>"), (.witness // "<none>")]
      | @tsv
    ' "$stationarity" | wc -l | tr -d ' '
  )"
  if [[ "$runtime_count" -eq 0 ]]; then
    echo "- none"
  else
    jq -r '
      select(.reason == "runtime_writer")
      | .runtime_writers[]?
      | [.via, (.func // "<unknown>"), (.witness // "<none>")]
      | @tsv
    ' "$stationarity" \
      | sort \
      | uniq -c \
      | sort -nr \
      | head -n 20 \
      | awk -F '\t' '
          {
            split($1, prefix, " ")
            count = prefix[1]
            via = prefix[2]
            func = $2
            witness = $3
            printf "- `%s` `%s` `%s`: %s\n", via, func, witness, count
          }
        '
  fi
  echo
done
