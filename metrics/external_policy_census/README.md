# External-policy Phase-0 census

`pangs external-policy-census` is diagnostic-only instrumentation for
[`20260824_EXTERNAL_POLICY.md`](../../20260824_EXTERNAL_POLICY.md). It runs the existing strict
analysis, records finite external ModRef provenance, attributes `ModuleWide` rows, constructs the
proposed callback/control closure, and evaluates the D4 counterfactual without changing analysis or
disposition facts.

The 2026-08-24 measurements and stop-gate decision are in
[`20260824_EXTERNAL_POLICY_CENSUS.md`](../../20260824_EXTERNAL_POLICY_CENSUS.md).

Run the cheap core corpus sweep with:

```bash
cargo build --release -p pangs-cli
metrics/external_policy_census/run_census.sh \
    ~/pangs-corpus/_out_bc /tmp/pangs-external-policy-census 4
python3 metrics/external_policy_census/aggregate.py \
    /tmp/pangs-external-policy-census \
    --bitcode-dir ~/pangs-corpus/_out_bc
```

Use `--callback-closure` on an individual `external-policy-census` command only after the core
report identifies strict D4 failures. It automatically reruns the analysis with targeted
allocation-level points-to for the affected principals. This enriched pass is intentionally kept
out of the parallel core script because large curl modules can take 15 minutes and several GiB.
