# Atomic Co-Update Runtime Audit Plan

Status: retired 2026-07-17; atomic eligibility analysis removed 2026-09-14.

The proposed co-update audit is not part of atomic eligibility or production
materialization. PANGS preserves defined C behavior; it does not promise to preserve
or diagnose executions containing unsynchronized concurrent accesses to plain
non-atomic globals.

Converting an eligible plain scalar global to an atomic does not remove existing
synchronization. Therefore:

- a data-racing source execution was already undefined;
- a properly synchronized concurrent execution retains its synchronization; and
- a single-threaded execution has no concurrent observer of an intermediate update.

Same-function co-writes consequently provide no soundness requirement for a
per-global atomic representation rewrite. The earlier proposal to collect suspected
co-write components, discharge their edges statically, and require a clean runtime
report imposed an additional race-hardening policy rather than defined-behavior
preservation. Its complexity and false negatives are not justified by the project
contract.

The later upstream atomic source transform made even those D3 representation checks
obsolete in PANGS. Current atomic disposition reflects an existing source atomic
declaration and performs no IR/PIR/PAG semantic eligibility analysis.

Coupling remains relevant only when a strategy creates a joint runtime object or
changes joint publication, such as `OnceLock<Struct>` or `Mutex<Struct>`.
