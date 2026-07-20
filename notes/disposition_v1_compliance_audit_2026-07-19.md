# Disposition analysis-side v1 compliance audit

Date: 2026-07-19

## Verdict

The analysis-side v1 described by `DISPOSITION.md` and `DISPOSITION_PLAN.md` is
complete. No missing analysis, policy, schema, emission, or repository-boundary test
deliverable remains across D1, D2, D2b, D3, D4, and D5.

This verdict intentionally ends at the documented repository boundary. Production
C-to-C marker planting and strategy materialization, survival through the real C-to-
Rust translator, and production Rust-side marker consumption are the next milestone.
D0 can only be performed at that boundary and is not an analysis-side completion gap.

## Work-item audit

| item | implementation evidence | acceptance evidence | verdict |
|---|---|---|---|
| D1a manifest contract | `pangs-manifest`: schema v3 types, key grammar, canonical writer, unknown-field `extra` maps, marker codec and collision checking | key/marker, canonicalization, audit-id, and shipped-schema unit tests; CLI full-manifest canonical hash | complete |
| D1b fact assembly | `pangs-clients::assemble_disposition_artifacts`, lowering/API metadata plumbing, registry facts, access completeness, stationarity attachment, evidenced witnesses, optional source identities | pipeline disposition fixtures, source-less key test, registry/coupling fixture, initializer/runtime-write regression | complete |
| D1c cascade | pure policy evaluation in `pangs-dispose`, including null-vs-failed routing and violation-taint guard composition | generated Boolean/certificate grid, first-applicable, trace, null/failed, and localization tests | complete |
| D2 overrides | shared in-process/offline policy path, TOML parsing, ordered validation, accepted-risk ledger, override echo/report, exit discipline, atomic pair replacement | enablement/availability/risk, group/member conflict, safe unhandled pin, idempotence, exit 1/2/3 CLI tests | complete |
| D2b coupling | deterministic hard grouping, common-P support, per-member atomic preservation, typed shared-mutex support | group-id determinism, common-publication pipeline fixture, support/override tests, joint/member demotion harness cases | complete |
| D3 atomic | per-global coarse gates, exact load/store/RMW lowering, volatile rejection, target lock-free check, declaration and source-materialization recipes | scalar-dataflow RMW, volatile, signal/recipe fixtures; 14 surviving corpus certificates audited and remeasured | complete |
| D4 mutex | access completeness, signal and violation gates, accessor reachability, unresolved-callee fail-closed rule, per-global/shared recipes and source readiness | reentrancy and unknown-callee fixtures; hardened YAPET/JPEGoptim audit and corpus remeasurement | complete |
| D5 markers | shared name codec, expected inventory, inventory validator, header/source artifact emission, CLI `--emit-markers` | mock materializer + fixture rewriter round trip, missing/orphan rejection, joint mutex and member-only demotion tests | complete at repository boundary |

## Cross-cutting contract audit

- `pangs analyze --dispose` requires `--repo-root`, uses the same policy library as
  offline `pangs-dispose`, and leaves ordinary `analyze` unchanged when not selected.
- The manifest/audit pair is canonical and re-runnable; the disposition files remain
  outside the immutable analysis export index.
- Fact ownership remains analysis-side and preference-free; offline policy has no
  dependency on the PAG or analysis crates.
- Certificate-only cascade guards are preserved for eligibility-pass strategies;
  pass-less strategies compose raw facts.
- Downstream materialization is demotion-only, with whole-group demotion for joint
  once-lock/mutex representations and member-only demotion otherwise.
- D5 marker cardinality derives from final dispositions, and inventory validation
  rejects both missing expected symbols and translated orphan symbols.
- Coverage and skip measurements are emitted in `run.dispose.measurement_report`.

## Final verification

- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --no-fail-fast`: passed, 273 tests and all doc tests.
- Fresh corpus sweep: all 41 non-Vim, non-OpenSSL sibling modules completed with
  `--stage andersen --dispose --validate`; see
  `disposition_initializer_write_remeasurement_2026-07-19.md`.
- Working-tree implementation is split into the requested logical `jj` commits.

## Deferred production boundary

The following are explicitly not analysis-side v1 work:

1. apply immutable/atomic/mutex/once-lock recipes to production C source;
2. plant marker calls and append the real materialization inventory/demotions;
3. compile/link the generated marker TU and run the real C-to-Rust translator;
4. validate marker survival and perform production Rust rewrites/deletions;
5. execute the materializer-requested dynamic mutex lock-cycle audit.

These form the production materializer integration milestone.
