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
