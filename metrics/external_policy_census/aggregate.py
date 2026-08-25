#!/usr/bin/env python3
"""Aggregate diagnostic external-policy census JSON files."""

import argparse
import json
from pathlib import Path


SUM_FIELDS = (
    "finite_external_rows",
    "finite_external_rows_single_source",
    "finite_external_rows_multiple_sources",
    "finite_rows_needing_source_candidate_correlation",
    "finite_rows_with_available_source_candidate_correlation",
    "module_wide_rows",
    "module_wide_mod_rows",
    "module_wide_ref_rows",
    "module_wide_inttoptr_rows",
    "module_wide_inline_asm_rows",
    "module_wide_unattributed_rows",
    "forged_pointer_seeds",
    "forged_pointer_seeds_feasibly_bounded",
    "forged_pointer_seeds_bounded_constant_candidates",
    "forged_pointer_groups",
    "forged_pointer_groups_feasibly_certifiable",
    "forged_pointer_groups_bounded_constant_candidates",
    "module_wide_rows_in_feasibly_certifiable_groups",
    "module_wide_rows_in_bounded_constant_candidate_groups",
    "distinct_module_wide_poisoned_globals",
    "opaque_inline_asm_exposures",
    "opaque_callsites",
    "complete_principal_identities",
    "complete_callback_inventories",
    "complete_control_closures",
    "callback_functions_held",
    "callback_transmod_globals",
)

D4_SUM_FIELDS = (
    "globals_evaluated",
    "strict_mutex_eligible",
    "strict_unknown_callee_reentrancy_failures",
    "accessor_reachable_unknown_pairs",
    "complete_accessor_disjoint_pairs",
    "accessor_reaching_pairs",
    "incomplete_control_pairs",
    "ideal_newly_mutex_eligible",
    "module_wide_leave_one_out_newly_access_complete",
    "module_wide_leave_one_out_newly_mutex_eligible_under_strict_reentry",
    "forged_pointer_group_newly_access_complete",
    "forged_pointer_group_newly_mutex_eligible_under_strict_reentry",
    "module_wide_remove_all_newly_access_complete",
    "module_wide_remove_all_newly_mutex_eligible_under_strict_reentry",
    "feasible_forged_groups_newly_access_complete",
    "feasible_forged_groups_newly_mutex_eligible_under_strict_reentry",
    "bounded_constant_groups_newly_access_complete",
    "bounded_constant_groups_newly_mutex_eligible_under_strict_reentry",
)


def load_reports(directory: Path):
    reports = []
    for path in sorted(directory.glob("*.json")):
        with path.open() as handle:
            report = json.load(handle)
        report["_name"] = path.stem
        reports.append(report)
    return reports


def total(reports, section, field):
    return sum(report[section]["summary"][field] for report in reports)


def blocker_kind(blocker):
    for prefix in (
        "universal-pointer-origin:",
        "pointer-origin-resolution-unavailable:",
        "global-init-pointer-origin-unresolved:",
        "universal-pointer-origin-unattributed:",
        "unclassified-source:",
    ):
        if blocker.startswith(prefix):
            return prefix[:-1]
    return blocker


def optimistic_constant_offset_seed(seed):
    """Upper-bound profile, not a certificate: one pointer origin plus additive constants."""
    allowed_blockers = {"integer-arithmetic:add", "nonzero-integer-constant"}
    return (
        len(seed["pointer_origins"]) == 1
        and bool(seed["integer_constants"])
        and set(seed["blockers"]).issubset(allowed_blockers)
        and set(seed["operations"]).issubset({"add", "ptrtoint", "select", "phi", "freeze"})
    )


def optimistic_offset_profile(report):
    seeds = {
        seed["source"]: seed
        for seed in report["effect_control"].get("forged_pointer_seeds", [])
    }
    groups = report["effect_control"].get("forged_pointer_groups", [])
    accepted_groups = [
        group
        for group in groups
        if group["seed_sources"]
        and all(
            source in seeds
            and (
                seeds[source]["feasibly_bounded"]
                or optimistic_constant_offset_seed(seeds[source])
            )
            for source in group["seed_sources"]
        )
    ]
    accepted_rows = sum(len(group["modref_row_indices"]) for group in accepted_groups)
    all_rows = report["effect_control"]["summary"]["module_wide_rows"]
    removes_all = all_rows > 0 and accepted_rows == all_rows
    return {
        "candidate_seeds": sum(optimistic_constant_offset_seed(seed) for seed in seeds.values()),
        "candidate_groups": len(accepted_groups),
        "candidate_rows": accepted_rows,
        "newly_access_complete": (
            report["d4"]["summary"]["module_wide_remove_all_newly_access_complete"]
            if removes_all
            else 0
        ),
        "newly_mutex_eligible_under_strict_reentry": (
            report["d4"]["summary"][
                "module_wide_remove_all_newly_mutex_eligible_under_strict_reentry"
            ]
            if removes_all
            else 0
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--bitcode-dir", type=Path)
    args = parser.parse_args()
    reports = load_reports(args.directory)
    expected = (
        {path.stem for path in args.bitcode_dir.glob("*.bc")}
        if args.bitcode_dir
        else {report["_name"] for report in reports}
    )
    completed = {report["_name"] for report in reports}
    offset_profiles = {
        report["_name"]: optimistic_offset_profile(report) for report in reports
    }

    aggregate = {
        "coverage": {
            "expected_modules": len(expected),
            "completed_modules": len(completed),
            "missing_modules": sorted(expected - completed),
        },
        "effect_control": {
            field: total(reports, "effect_control", field) for field in SUM_FIELDS
        },
        "d4": {field: total(reports, "d4", field) for field in D4_SUM_FIELDS},
        "distinct_strict_d4_callsites": sum(
            len(
                {
                    call["callsite"]
                    for row in report["d4"]["globals"]
                    if "unknown-callee-reentrancy" in row["strict_mutex_codes"]
                    for call in row["unknown_calls"]
                    if call["callsite"] is not None
                }
            )
            for report in reports
        ),
        "modules_with_module_wide_rows": sum(
            report["effect_control"]["summary"]["module_wide_rows"] > 0
            for report in reports
        ),
        "modules_with_strict_d4_failures": sum(
            report["d4"]["summary"]["strict_unknown_callee_reentrancy_failures"]
            > 0
            for report in reports
        ),
        "forged_seed_classifications": {
            classification: sum(
                seed["classification"] == classification
                for report in reports
                for seed in report["effect_control"].get("forged_pointer_seeds", [])
            )
            for classification in sorted(
                {
                    seed["classification"]
                    for report in reports
                    for seed in report["effect_control"].get("forged_pointer_seeds", [])
                }
            )
        },
        "forged_seed_blockers": {
            blocker: sum(
                blocker in {blocker_kind(item) for item in seed["blockers"]}
                for report in reports
                for seed in report["effect_control"].get("forged_pointer_seeds", [])
            )
            for blocker in sorted(
                {
                    blocker_kind(blocker)
                    for report in reports
                    for seed in report["effect_control"].get("forged_pointer_seeds", [])
                    for blocker in seed["blockers"]
                }
            )
        },
        "optimistic_single_origin_constant_offset": {
            field: sum(profile[field] for profile in offset_profiles.values())
            for field in (
                "candidate_seeds",
                "candidate_groups",
                "candidate_rows",
                "newly_access_complete",
                "newly_mutex_eligible_under_strict_reentry",
            )
        },
        "modules": [
            {
                "name": report["_name"],
                "finite_rows": report["effect_control"]["summary"][
                    "finite_external_rows"
                ],
                "multi_source_rows": report["effect_control"]["summary"][
                    "finite_external_rows_multiple_sources"
                ],
                "module_wide_rows": report["effect_control"]["summary"][
                    "module_wide_rows"
                ],
                "forged_groups": report["effect_control"]["summary"][
                    "forged_pointer_groups"
                ],
                "feasible_forged_groups": report["effect_control"]["summary"][
                    "forged_pointer_groups_feasibly_certifiable"
                ],
                "bounded_constant_groups": report["effect_control"]["summary"][
                    "forged_pointer_groups_bounded_constant_candidates"
                ],
                "remove_all_new_access_complete": report["d4"]["summary"][
                    "module_wide_remove_all_newly_access_complete"
                ],
                "feasible_new_access_complete": report["d4"]["summary"][
                    "feasible_forged_groups_newly_access_complete"
                ],
                "bounded_constant_new_access_complete": report["d4"]["summary"][
                    "bounded_constant_groups_newly_access_complete"
                ],
                "offset_candidate_groups": offset_profiles[report["_name"]][
                    "candidate_groups"
                ],
                "offset_new_access_complete": offset_profiles[report["_name"]][
                    "newly_access_complete"
                ],
                "strict_d4_failures": report["d4"]["summary"][
                    "strict_unknown_callee_reentrancy_failures"
                ],
                "ideal_newly_mutex_eligible": report["d4"]["summary"][
                    "ideal_newly_mutex_eligible"
                ],
            }
            for report in reports
        ],
    }
    print(json.dumps(aggregate, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
