# HOWTO: Measure Disposition Coverage for One Bitcode File

This runbook produces and summarizes a validated disposition manifest for one LLVM
bitcode module. It is intended to be executable by either a human or a coding agent.

The headline metric is the final disposition distribution over defined mutable
globals. A useful report also records cascade blockers, certificate coverage,
materialization readiness, overrides, runtime, and peak memory.

## 1. Prerequisites

Run from the PANGS repository root. The examples assume:

```bash
PANGS_REPO=/home/brk/pangs
INPUT=/absolute/path/to/program.bc
REPO_ROOT=/absolute/path/to/the/analyzed/source/tree
OUT=/tmp/pangs-disposition-program
```

Requirements:

- `INPUT` is the linked bitcode file to measure.
- `REPO_ROOT` is the source-tree root against which debug-info paths should be
  normalized. It is required for disposition emission even when some globals lack
  source metadata.
- Static symbols have already been globally uniquified if the input combines multiple
  translation units. Bare manifest keys depend on this pipeline invariant.
- The selected build mode matches how the artifact will be used:
  - `executable` for a closed application;
  - `library` when external clients may name exported globals.
- `jq` and GNU `/usr/bin/time` are available for the commands below.

Build the optimized CLI before measuring:

```bash
cd "$PANGS_REPO"
cargo build --release -p pangs-cli -p pangs-dispose
```

If this checkout needs an explicit LLVM installation, set its normal
`LLVM_SYS_140_PREFIX` and `LD_LIBRARY_PATH` environment variables before building and
running PANGS.

## 2. Choose a baseline configuration

For measurements intended to compare analysis versions, use:

- `--stage andersen`;
- the correct `--build-mode`;
- `--no-overrides`;
- `--validate`.

Do not infer the build mode solely from a filename if build metadata is available.
Build mode affects exported-global reachability and therefore changes soundness facts,
not just policy preference.

`--mode application|library` is a separate disposition-policy option. Normally omit
it and let policy follow the analysis build mode. Use it only when deliberately
narrowing an executable analysis to library policy, and record that choice in the
report.

If the goal is to measure a deployed override configuration instead of an analysis
baseline, replace `--no-overrides` with `--overrides FILE` and report the override
outcomes separately. Never silently mix overridden and non-overridden results.

## 3. Run analysis and disposition

Use a new or empty output directory. This example captures wall time, peak RSS, normal
output, and diagnostics separately:

```bash
mkdir -p "$OUT"

PANGS_DISPOSITION_TIMINGS=1 \
/usr/bin/time \
  -f 'elapsed_seconds=%e\npeak_rss_kib=%M' \
  -o "$OUT/time.txt" \
  "$PANGS_REPO/target/release/pangs" analyze "$INPUT" \
    --stage andersen \
    --build-mode executable \
    --dispose \
    --repo-root "$REPO_ROOT" \
    --no-overrides \
    --out "$OUT" \
    --validate \
    >"$OUT/stdout.txt" \
    2>"$OUT/stderr.txt"
```

Change `--build-mode executable` to `--build-mode library` when appropriate.

`PANGS_DISPOSITION_TIMINGS=1` is optional. It adds phase checkpoints to stderr but
does not change the canonical artifacts.

A successful run produces at least:

```text
$OUT/pangs-manifest.json
$OUT/pangs-audit.json
$OUT/manifest.json
$OUT/time.txt
$OUT/stdout.txt
$OUT/stderr.txt
```

`--validate` checks the complete analysis export. Treat a nonzero exit, missing
manifest/audit pair, or validation failure as a failed measurement; do not summarize a
partial artifact.

Large modules can require tens of gigabytes. If the process exits 137 or
`time.txt` says it was terminated by signal 9, report it as resource-blocked together
with elapsed time and peak RSS. Do not reuse an older manifest without labeling the
result as derived rather than fresh.

## 4. Verify the result before summarizing it

Set the manifest path:

```bash
MANIFEST="$OUT/pangs-manifest.json"
AUDIT="$OUT/pangs-audit.json"
```

Check the recorded configuration and provenance:

```bash
jq '{schema_version, analysis:.run.analysis, dispose:.run.dispose}' "$MANIFEST"
cat "$OUT/time.txt"
```

Verify that the built-in distribution sums to the manifest population:

```bash
jq -e '
  (.globals | length) as $total
  | ([.run.dispose.measurement_report.disposition_distribution[]] | add) == $total
' "$MANIFEST"
```

Verify that keys are unique and inspect globals that could not be keyed:

```bash
jq -e '([.globals[].key] | length) == ([.globals[].key] | unique | length)' \
  "$MANIFEST"

jq '{keyed_globals:(.globals|length), unkeyed_globals}' "$MANIFEST"
```

Any nonempty `unkeyed_globals` list belongs in the final report. It is not part of the
disposition denominator because no stable manifest identity could be minted.

## 5. Headline disposition coverage

The authoritative counts are already emitted after policy and override resolution:

```bash
jq '.run.dispose.measurement_report.disposition_distribution' "$MANIFEST"
```

Print counts and percentages independently from `globals[]`:

```bash
jq -r '
  .globals as $globals
  | ($globals | length) as $total
  | "disposition\tcount\tpercent",
    ($globals
      | group_by(.disposition.chosen)
      | map({key:.[0].disposition.chosen, value:length})
      | .[]
      | "\(.key)\t\(.value)\t\((10000 * .value / $total | round) / 100)%")
' "$MANIFEST"
```

The denominator is every keyed, defined, mutable global in `globals[]`.

Report at least:

- counts for `immutable`, `once-lock`, `atomic`, `mutex`, `localize`, and
  `unhandled`, including zeroes;
- total globals;
- handled globals = total minus `unhandled`;
- handled percentage.

Compute the handled summary directly:

```bash
jq '
  (.globals | length) as $total
  | ([.globals[] | select(.disposition.chosen != "unhandled")] | length) as $handled
  | {
      total:$total,
      handled:$handled,
      unhandled:($total-$handled),
      handled_percent:(if $total == 0 then 0
                       else ((10000*$handled/$total|round)/100) end)
    }
' "$MANIFEST"
```

List every handled global for auditability:

```bash
jq -r '
  .globals[]
  | select(.disposition.chosen != "unhandled")
  | [.disposition.chosen, .key, .disposition.provenance]
  | @tsv
' "$MANIFEST" | sort
```

## 6. Explain why globals remain unhandled

Start with the built-in cascade histogram:

```bash
jq '.run.dispose.measurement_report.cascade_skip_histogram' "$MANIFEST"
```

For a compact table of guard failures:

```bash
jq -r '
  .run.dispose.measurement_report.cascade_skip_histogram
  | to_entries[] as $strategy
  | $strategy.value.guard_failed
  | to_entries[]
  | [$strategy.key, .key, .value]
  | @tsv
' "$MANIFEST" | sort -k1,1 -k3,3nr
```

And facts or certificates that were not computed:

```bash
jq -r '
  .run.dispose.measurement_report.cascade_skip_histogram
  | to_entries[] as $strategy
  | $strategy.value.fact_not_computed
  | to_entries[]
  | [$strategy.key, .key, .value]
  | @tsv
' "$MANIFEST" | sort -k1,1 -k3,3nr
```

Guard counts overlap: one global may fail several conjuncts. Do not add guard counts
and present the result as a number of globals. The per-strategy `total` is the number
of globals that skipped that cascade entry.

To inspect the complete trace for every unhandled global:

```bash
jq '
  [.globals[]
   | select(.disposition.chosen == "unhandled")
   | {key, cascade_trace:.disposition.cascade_trace}]
' "$MANIFEST"
```

To drill into one global by manifest key:

```bash
KEY='src/file.c::global_name'
jq --arg key "$KEY" '.globals[] | select(.key == $key)' "$MANIFEST"
```

Always use the manifest `key` for identity. `meta.llvm_name` is a this-run join key,
not the cross-tool identity.

## 7. Summarize declarations and certificates

Atomic declaration counts and the remaining D4 funnel are:

```bash
jq '.run.dispose.measurement_report
    | {atomic_declarations, mutex:.would_be_eligibility.mutex}' "$MANIFEST"
```

Summarize source-declared atomics and analysis-owned certificate states independently
of final cascade choice:

```bash
jq '
  def state($slot):
    if $slot == null then "not-computed" else $slot.status end;
  {
    atomic_declared: [.globals[] | select(.facts.atomic_declaration.value) | .key],
    mutex:
      ([.globals[] | state(.facts.mutex_eligibility)]
       | group_by(.) | map({key:.[0],value:length}) | from_entries),
    once_lock:
      ([.globals[] | state(.facts.phase_stationarity)]
       | group_by(.) | map({key:.[0],value:length}) | from_entries)
  }
' "$MANIFEST"
```

Count pass-owned failure codes. These counts may overlap because a failed certificate
can carry multiple codes:

```bash
for SLOT in mutex_eligibility phase_stationarity; do
  jq -r --arg slot "$SLOT" '
    [.globals[].facts[$slot]
     | select(.status == "failed")
     | .codes[]]
    | group_by(.)
    | map({code:.[0], count:length})
    | sort_by(-.count, .code)
    | .[]
    | [$slot, .code, .count]
    | @tsv
  ' "$MANIFEST"
done
```

List certified globals even when an earlier cascade strategy won:

```bash
jq -r '
  .globals[] as $global
  | ["mutex", "mutex_eligibility"],
    ["once-lock", "phase_stationarity"]
  | . as [$strategy, $slot]
  | select($global.facts[$slot].status == "certified")
  | [$strategy, $global.key, $global.disposition.chosen]
  | @tsv
' "$MANIFEST" | sort
```

List source-declared atomics in the same shape:

```bash
jq -r '.globals[]
  | select(.facts.atomic_declaration.value)
  | ["atomic", .key, .disposition.chosen] | @tsv' "$MANIFEST" | sort
```

This distinction matters: a global can have a valid mutex certificate but finish as
immutable or atomic because an earlier cascade entry wins.

## 8. Coupling, localization, and materialization readiness

Summarize hard coupling groups:

```bash
jq '
  {
    groups:(.coupling_groups|length),
    grouped_members:([.coupling_groups[].members[]]|length),
    group_dispositions:
      ([.coupling_groups[].group_disposition]
       | group_by(.) | map({key:(.[0] // "unset"),value:length}) | from_entries)
  }
' "$MANIFEST"
```

Inspect localization/context-struct pressure:

```bash
jq '.run.dispose.measurement_report.context_struct_pressure' "$MANIFEST"
```

For final mutex selections, report whether their static certificate is immediately
source-materializable. Atomic selections were already materialized by the upstream
source transform and have no PANGS recipe:

```bash
jq -r '
  .globals[]
  | select(.disposition.chosen == "mutex")
  | . as $global
  | .facts.mutex_eligibility as $slot
  | (if $slot.status == "certified"
     then $slot.certificate
     else $slot.recipe end) as $recipe
  | ["mutex",
     $global.key,
     ($recipe.source_materialization.status // "unknown"),
     ($recipe.source_materialization.code // "-")]
  | @tsv
' "$MANIFEST" | sort
```

Static eligibility and source readiness are deliberately separate. A certified but
blocked selection counts as disposition coverage, but it must be demoted if the
production materializer cannot recover the required source anchor. State both numbers
when evaluating near-term production payoff.

## 9. Overrides and audit records

For a baseline run, confirm that no override was applied:

```bash
jq '{dispose:.run.dispose | {overrides_file,overrides_sha256}, override_report}' \
  "$MANIFEST"
```

For an override-enabled run, include the built-in telemetry and all nontrivial
outcomes:

```bash
jq '.run.dispose.measurement_report.override_usage' "$MANIFEST"
jq '.override_report.entries
    | map(select(.outcome != "honored"))' "$MANIFEST"
```

Accepted-risk overrides must also have corresponding records in `pangs-audit.json`:

```bash
jq '[.[] | select(.kind == "accepted-risk")]' "$AUDIT"
```

## 10. Recommended report format

Use a short Markdown report with the following sections.

### Scope and method

Record:

- date and PANGS commit;
- absolute or stable corpus-relative input name;
- input SHA-256 from `.run.analysis.input_sha256`;
- bitcode provenance: compiler, optimization/debug level, and link/uniquification
  method when known;
- `repo_root`, analysis stage, build mode, disposition mode, registry config, and
  override file/hash;
- exact command;
- validation result;
- elapsed seconds and peak RSS;
- retained artifact directory.

### Coverage

Include a table:

| disposition | count | percent |
|---|---:|---:|
| immutable |  |  |
| once-lock |  |  |
| atomic |  |  |
| mutex |  |  |
| localize |  |  |
| unhandled |  |  |
| **total** |  | **100%** |

Then state handled count/percentage and the number of unkeyed globals.

### Explanation

Summarize:

- dominant cascade guard failures, without adding overlapping counts;
- fact-not-computed counts;
- source atomic declaration counts and D4 free-gate/certified counts;
- certificate failure-code concentrations;
- coupling-group and context-struct pressure;
- source-ready versus source-blocked final mutex selections;
- override outcomes and accepted risks.

### Audit highlights

Name the handled globals when the set is small. For a large set, attach a sorted TSV
and discuss representative globals, surprising classifications, and the largest
false-negative populations.

### Takeaway

End with the decision the measurement supports. Examples include:

- a pass materially increases handled coverage;
- most theoretical certificates lose to earlier cascade entries;
- coverage is blocked primarily by one conservative fact;
- static coverage is high but production source readiness is low;
- the input is resource-blocked and needs a narrower stage or a larger host.

## 11. Comparing two PANGS versions or configurations

Use the same bitcode bytes, repository root, stage, build mode, registry configuration,
and override selection. Retain both complete artifact directories.

```bash
OLD_OUT=/absolute/path/to/old-output
NEW_OUT=/absolute/path/to/new-output
```

Compare headline distributions:

```bash
jq '.run.dispose.measurement_report.disposition_distribution' \
  "$OLD_OUT/pangs-manifest.json"
jq '.run.dispose.measurement_report.disposition_distribution' \
  "$NEW_OUT/pangs-manifest.json"
```

List per-global disposition changes by stable key:

```bash
jq -n -r \
  --slurpfile old "$OLD_OUT/pangs-manifest.json" \
  --slurpfile new "$NEW_OUT/pangs-manifest.json" '
  $old[0].globals as $old_globals
  | $new[0].globals[] as $new_global
  | ($old_globals[] | select(.key == $new_global.key)) as $old_global
  | select($old_global.disposition.chosen != $new_global.disposition.chosen)
  | [$new_global.key,
     $old_global.disposition.chosen,
     $new_global.disposition.chosen]
  | @tsv
' | sort
```

Before interpreting the delta, verify that the key sets are identical. If they are not,
report additions/removals separately; do not treat missing keys as disposition changes.

```bash
jq -r '.globals[].key' "$OLD_OUT/pangs-manifest.json" | sort > /tmp/pangs-old-keys.txt
jq -r '.globals[].key' "$NEW_OUT/pangs-manifest.json" | sort > /tmp/pangs-new-keys.txt
diff -u /tmp/pangs-old-keys.txt /tmp/pangs-new-keys.txt
```

Finally compare runtime/RSS, skip histograms, certificate states, source readiness,
and override hashes. A coverage delta without those controls is not attributable to
the analysis change alone.
