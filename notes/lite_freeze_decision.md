# Lite Freeze Decision

Date: 2026-06-17

## Decision

Freeze the PANGS-lite analysis design as the default path. Do not add a new M6 analysis
milestone by default.

The current implementation has reached the endpoint described in `DESIGN_lite.md`: a
sound end-to-end pipeline with B1/B2 precision, Steensgaard partitioning, exhaustive
partition Andersen over the interesting surface, final FSA filtering, Ω taint, and
client post-passes. The remaining measured blockers do not justify reviving the full
`DESIGN.md` tier-E query engine, typed heap clones, or M5 flow-sensitive summaries as
default work.

## Scope

This note is a design freeze/readiness decision only. It does not audit the client-facing
export surface. That should be a separate pass if the globals-localization client needs a
contract check over `callgraph.jsonl`, `modref.jsonl`, `components.json`,
`stationarity.jsonl`, and audit outputs.

## Evidence

The relevant decision records are:

- `notes/m3_lite_decision.md`: tier E stays cut for the default pipeline. M3 showed the
  lite `--stage andersen` path completes the decision corpus, including a tmux-sized row,
  and remaining coverage loss was dominated by modeling/audit envelopes rather than a
  clear context-sensitive query need.
- `notes/m4_vararg_decision.md`: M4 vararg modeling reduced audit noise substantially in
  curl and tmux, but did not move mutable-global rewritable coverage on the corpus.
  Continuing that line would mostly improve explanations, not unlock the dominant frozen
  components.
- `metrics/m5_0_gate_census.md` and `PLAN-M5.md`: M5a is not green-lit. The census has no
  mutable globals blocked by known `runtime_writer` rows, so flow-sensitive summaries
  would not target a measured flow-smearing population. M5b is also not green-lit because
  no current lite client consumes thread-confinement facts.

The M5 Steens-external audit is the strongest recent precision signal. It found 1,640
node-preserved `omega_store` rows in the comparable O1 audit set, with 1,587 from
`omega:steens_external`. Of those Steens-external rows, 1,546 still carry finite pointee
globals and only 41 are pure external with no finite globals. That points to Steensgaard
overmerge with large finite sets, not a missing direct boundary model.

## What Stays Frozen

Tier E remains cut. The lite design explicitly treats tier E as the largest reversible
upgrade, to be added only if coverage is limited by context-insensitive icall residue
that is both load-bearing and not already Ω-frozen. The current evidence does not show
that as the dominant blocker.

Typed heap clones remain cut. `DESIGN_lite.md` names heap object conflation as a possible
upgrade gate, but the current decision evidence points first at unknown mod/ref and
Steensgaard overmerge. Do not add clone/site-object duality unless a focused measurement
shows mutable-global coverage is limited by multi-type heap allocation-site conflation.

M5a remains cut. Flow-sensitive summaries, auxiliary formals, strong updates, and
phase-aware recertification are substantial machinery. They should wait for a measured
population of flow-insensitive phase-smearing failures.

M5b remains cut. Thread escape is a valid future analysis for ownership or
`Send`/`Sync`/`Mutex` decisions, but it should be driven by a client that consumes those
facts.

## What To Keep

Keep the lite pipeline and its diagnostics:

- B1 stationarity/initval diagnostics;
- B2 exact simple-call resolution and confined subtraction;
- Andersen as the primary precise path;
- Ω-source detail on unknown mod/ref rows;
- optional `address_node` and `pointee_globals` metadata on unknown pointer-derived
  mod/ref rows;
- `scripts/m5_gate_census.sh` as a regression and diagnosis report.

These are useful audit surfaces even though they are not work queues by themselves.

## Residual Risks

The main remaining precision risk is `omega:steens_external`: broad Steensgaard classes
can keep otherwise finite store-address nodes externally tainted, which freezes
stationarity and component rewrites. This is currently a known coverage loss, not a
soundness hole.

Mega-components remain a client risk from `DESIGN.md` section 11.4. Even a sound and
mostly precise analysis can lose localization coverage if one load-bearing unknown edge
freezes a large connected component. This should be measured at the client level before
building more solver machinery.

Large JSONL exports remain a scale caveat, especially tmux-sized `modref.jsonl` output.
This is not an analysis-design blocker while clients can consume in-memory results, but
it may become an integration issue if file exports become the normal client interface.

## Reopen Conditions

Reopen tier E only if a decision corpus or real client shows that localization coverage
is blocked by context-insensitive function-pointer residue, the responsible edges are
not Ω-frozen external callbacks, and narrowing those edges would split load-bearing
components.

Reopen typed heap clones only if a focused audit shows imprecise mutable-global facts
trace to heap object conflation at multi-type allocation sites.

Reopen M5a only if measured blockers are dominated by flow-insensitive write smearing:
reuse patterns, kill-needed strong-update cases, or B1 poisoning that a local
flow-sensitive summary pass would plausibly settle.

Reopen M5b only when a downstream ownership client needs thread-confinement facts.

Otherwise, the next work should be integration/readiness work around the lite pipeline,
not a new analysis tier.
