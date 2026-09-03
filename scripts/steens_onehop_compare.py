#!/usr/bin/env python3
"""Compare stage-matched Steens one-hop analysis directories.

Each input directory contains one subdirectory per module and the ordinary `pangs analyze`
JSON/JSONL exports. The output is deterministic JSON suitable for the experiment report.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any


def jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def time_value(path: Path, key: str) -> float:
    for line in path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name == key:
            return float(value)
    raise ValueError(f"{path}: missing {key}")


def edge_key(row: dict[str, Any]) -> str:
    return json.dumps(
        {key: row.get(key) for key in ("caller", "callsite", "callee", "kind")},
        sort_keys=True,
        separators=(",", ":"),
    )


def unknown_row_key(row: dict[str, Any]) -> str:
    return json.dumps(
        {key: row.get(key) for key in ("func", "access", "witness", "address_node")},
        sort_keys=True,
        separators=(",", ":"),
    )


def pointee_count(row: dict[str, Any]) -> int | None:
    match = re.search(r"(?:^|[|:])pointee_count=(\d+)(?:$|[|:])", row.get("detail", ""))
    return int(match.group(1)) if match else None


def module_summary(baseline: Path, candidate: Path) -> dict[str, Any]:
    baseline_metrics = json.loads((baseline / "metrics.json").read_text(encoding="utf-8"))
    candidate_metrics = json.loads((candidate / "metrics.json").read_text(encoding="utf-8"))
    baseline_modref = jsonl(baseline / "modref.jsonl")
    candidate_modref = jsonl(candidate / "modref.jsonl")
    baseline_unknown = {
        unknown_row_key(row): row
        for row in baseline_modref
        if "unknown" in row.get("global", {})
    }
    candidate_unknown = {
        unknown_row_key(row): row
        for row in candidate_modref
        if "unknown" in row.get("global", {})
    }
    formerly_module_wide = {
        key for key, row in baseline_unknown.items() if row.get("candidate_scope") == "module-wide"
    }
    former_scope_counts = Counter(
        candidate_unknown[key].get("candidate_scope", "missing")
        for key in formerly_module_wide
        if key in candidate_unknown
    )
    former_finite_sizes = Counter(
        size
        for key in formerly_module_wide
        if key in candidate_unknown
        and candidate_unknown[key].get("candidate_scope") != "module-wide"
        and (size := pointee_count(candidate_unknown[key])) is not None
    )

    def modref_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
        unknown = [row for row in rows if "unknown" in row.get("global", {})]
        return {
            "total": len(rows),
            "named": sum("name" in row.get("global", {}) for row in rows),
            "unknown": len(unknown),
            "unknown_module_wide": sum(
                row.get("candidate_scope") == "module-wide" for row in unknown
            ),
            "unknown_finite": sum(row.get("candidate_scope") == "finite" for row in unknown),
        }

    baseline_globals = {row["key"]: row for row in jsonl(baseline / "globals.jsonl")}
    candidate_globals = {row["key"]: row for row in jsonl(candidate / "globals.jsonl")}
    common_globals = baseline_globals.keys() & candidate_globals.keys()
    escape_narrowed = sorted(
        key
        for key in common_globals
        if baseline_globals[key].get("escape") == "external"
        and candidate_globals[key].get("escape") != "external"
    )
    never_written_gained = sorted(
        key
        for key in common_globals
        if not baseline_globals[key].get("never_written")
        and candidate_globals[key].get("never_written")
    )

    baseline_stationarity = {
        row["global"]: row for row in jsonl(baseline / "stationarity.jsonl")
    }
    candidate_stationarity = {
        row["global"]: row for row in jsonl(candidate / "stationarity.jsonl")
    }
    stationary_gained = sorted(
        key
        for key in baseline_stationarity.keys() & candidate_stationarity.keys()
        if not baseline_stationarity[key].get("stationary")
        and candidate_stationarity[key].get("stationary")
    )

    baseline_edges = {edge_key(row) for row in jsonl(baseline / "callgraph.jsonl")}
    candidate_edges = {edge_key(row) for row in jsonl(candidate / "callgraph.jsonl")}
    metric_keys = (
        "analysis_wall_us",
        "solve_us",
        "steens_worklist_pops",
        "steens_join_attempts",
        "steens_join_successes",
        "steens_pointee_classes_created",
        "steens_content_edges",
        "steens_content_pushes",
        "steens_unify_pointees_shared",
        "andersen_coarser_than_steens_nodes",
        "oversize_fallbacks",
    )
    return {
        "wall_seconds": {
            "baseline": time_value(baseline / "time.txt", "wall_s"),
            "candidate": time_value(candidate / "time.txt", "wall_s"),
        },
        "max_rss_kib": {
            "baseline": int(time_value(baseline / "time.txt", "max_rss_kib")),
            "candidate": int(time_value(candidate / "time.txt", "max_rss_kib")),
        },
        "metrics": {
            key: {"baseline": baseline_metrics.get(key, 0), "candidate": candidate_metrics.get(key, 0)}
            for key in metric_keys
        },
        "modref": {
            "baseline": modref_counts(baseline_modref),
            "candidate": modref_counts(candidate_modref),
            "unknown_identity_added": sorted(candidate_unknown.keys() - baseline_unknown.keys()),
            "unknown_identity_removed": sorted(baseline_unknown.keys() - candidate_unknown.keys()),
            "formerly_module_wide": {
                "rows": len(formerly_module_wide),
                "candidate_scopes": dict(sorted(former_scope_counts.items())),
                "finite_candidate_sizes": {
                    str(size): count for size, count in sorted(former_finite_sizes.items())
                },
            },
        },
        "transitions": {
            "escape_external_to_module": escape_narrowed,
            "never_written_false_to_true": never_written_gained,
            "stationary_false_to_true": stationary_gained,
            "call_edges_removed": sorted(baseline_edges - candidate_edges),
            "call_edges_added": sorted(candidate_edges - baseline_edges),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    modules = sorted(
        path.name
        for path in args.baseline.iterdir()
        if path.is_dir() and (args.candidate / path.name).is_dir()
    )
    result = {
        "baseline": str(args.baseline),
        "candidate": str(args.candidate),
        "modules": {
            module: module_summary(args.baseline / module, args.candidate / module)
            for module in modules
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
