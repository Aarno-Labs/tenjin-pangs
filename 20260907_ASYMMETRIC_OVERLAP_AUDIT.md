# Asymmetric overlap: implementation audit

2026-09-07. This is the consumer checklist for work item C in
`20260904_STRIDE_FIELDS.md`. C is now implemented opt-in, not promoted; the companion
`20260907_ASYMMETRIC_OVERLAP_EVALUATION.md` records validation and remaining gates.
The first dependency is the Steensgaard one-hop offset correction; the static
stride experiment remains opt-in until its promotion gates pass.

## Read interpretation

Keep two operations distinct: raw contents written to one cell, and a memory read
which unions directly overlapping cells of the same allocation. Do not change
`Solve::points_to` globally: its callers also inspect pointer values, store
destinations, and raw transfer evidence. Transitive overlap closure would recreate
the sibling contamination C is intended to remove.

`field_base` and `field_location` describe raw allocation identities. Copy-SCC
representatives describe content variables, not allocations. Register reads by
raw root and location, canonicalizing only the destination. Overlap includes the
root object as `Unknown`; an external region continues to read itself.

Bulk copies need an explicit whole-object projection even when a raw endpoint is
an exact field address: `memcpy(base + 0, ..., 16)` can transfer a pointer at byte
8. Merely registering an exact-0 overlap read would miss it. Until byte-sliced
copying is implemented, use the endpoint allocation's whole-object read/write
interpretation while retaining raw endpoints for certificates and diagnostics.
Test this independently of whether an Unknown field happened to exist already.

## Consumer inventory

| Consumer in `crates/pangs-solve/src/andersen.rs` | Required treatment |
|---|---|
| Established and pending loads in `run_with_limit` | Install persistent overlap reads, including full-set seeding and fields created after the load. |
| Stores in `run_with_limit` | Keep raw destination writes; do not fan out to overlapping fields. |
| `process_memcpy_summary` | Read each active source through overlap into its site-local propagation summary; keep destination writes raw and preserve empty-endpoint activation guards. |
| Direct memcpy joins in `run_with_limit` | Use the same persistent source read for every destination pair, including late fields. |
| `field_of`, `note_direct_access` | Disable symmetric copy bridges only on the C path; new fields replay registered reads. |
| `collapse_copy_sccs` | Remap and deduplicate read destinations, preserve root/field identities, and reseed any newly required copy pairs. |
| `offline_quotient` | Protect overlap-read destinations from value-number substitution unless their future generators are represented; remap any preexisting dependencies. |
| `closed_producer_analysis` loads | Depend on all overlapping source cells, not only the pointer's raw pointee. Unsupported producer/copy cases remain incomplete. |
| `closed_consumer_certificates` load and memcpy audits | Compare overlap-read source functions against raw destination functions. Stores continue to compare raw source/destination contents. |
| `closed_consumer_certificates` boundary traversal | Traverse raw storage identities and all fields of a reachable allocation, including a boundary rooted directly at a global object. Never replace the allocation identity with its SCC content representative. |
| `apply_receiver_payload_summaries` | These synthetic cells are currently outside the ordinary `field_of` inventory. Audit overlapping payload locations explicitly; an exact-key return copy is not an overlap read. Keep receiver roots separate and preserve unknown-origin tokens. |
| `emit_global_points_to` | Already unions the root's contents and all materialized fields; retain this aggregate interpretation after compaction. |
| `emit_node_resolutions`, `discover_targets`, `query_closed_producer`, indirect-call export | Inspect value points-to sets; do not reinterpret these as memory reads. Their upstream loads must already be overlap-complete. |
| `release_propagation_state` | Drop read registrations after certificates; retain the field inventory needed by aggregate global export. If a later query needs location-aware reads, retain its location metadata too. |

## Validation obligations

Exercise summary/exact sibling isolation, both creation orders, pending and established
loads, both memcpy algorithms, empty endpoints, SCC-merged read destinations, and
external-origin propagation. Include exact/lane reads in both directions, root-object
writes, unknown writes, and unrelated allocations. A field-only callback must remain
reachable after its container crosses an external boundary with closed-producer,
closed-consumer, and receiver-payload options enabled.

For C evaluation, hold the static stride setting fixed. Record the effective C flag,
read dependency count, overlap pairs installed, late replay work, and index size.
Compare full client facts and witnesses, not just disposition histograms. Every
removed real write or callback is a failure; a smaller answer alone proves nothing.

## Implemented consumer decisions

The C path retains the raw/value distinction above. `content_fields` combines ordinary
and receiver-payload inventories for boundary and global aggregate enumeration; the
inventories survive propagation-state release. Receiver payload return reads union
directly overlapping locations after collecting all synthetic payload cells, without
connecting the raw payload cells to one another. Completeness certificates are
conservatively disabled for C when receiver summaries are active, including the
receiver-specific unknown-clearing shortcut. This proof limitation remains explicit
even though positive callback target discovery and aggregate exports are tested.
