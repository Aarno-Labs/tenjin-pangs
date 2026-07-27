#!/usr/bin/env python3
"""Measure Andersen admission cost and semantic benefit partition by partition.

Each interesting partition is forcibly admitted in isolation.  Its exported
callgraph targets, ModRef rows, and global eligibility facts are compared with
one Steensgaard baseline, while the solver reports actual propagation work.

Run corpus-sized profiles under the repository's required memory scope, e.g.:

  systemd-run --scope -p MemoryMax=40G \
    scripts/profile_andersen_admission.py \
      --pangs target/release/pangs \
      --corpus ~/pangs-corpus/_out_bc \
      --output /tmp/andersen-admission.jsonl
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any


PROFILE_PREFIX = "pangs andersen admission profile: "
OUTPUT_FAMILIES = ("callgraph.jsonl", "modref.jsonl", "globals.jsonl")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pangs", type=pathlib.Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--module", type=pathlib.Path)
    source.add_argument("--corpus", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--census-output",
        type=pathlib.Path,
        help="optional JSONL structural census of every interesting partition",
    )
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument(
        "--min-quadratic-proxy",
        type=int,
        default=0,
        help="isolate every partition at or above this old-proxy cost",
    )
    parser.add_argument(
        "--sample-below",
        type=int,
        default=0,
        help="also isolate this many highest-proxy partitions below the cutoff per module",
    )
    parser.add_argument(
        "--max-nodes",
        type=int,
        help="do not speculatively isolate partitions above this structural safety cap",
    )
    parser.add_argument(
        "--max-edges",
        type=int,
        help="do not speculatively isolate partitions above this structural safety cap",
    )
    return parser.parse_args()


def module_mode(module: pathlib.Path) -> str:
    return "library" if module.name.startswith("lib-") else "executable"


def run_analysis(
    pangs: pathlib.Path,
    module: pathlib.Path,
    out: pathlib.Path,
    stage: str,
    root: int | None = None,
) -> str:
    env = os.environ.copy()
    if stage == "andersen":
        env["PANGS_ANDERSEN_ADMISSION_PROFILE"] = "1"
        if root is not None:
            env["PANGS_ANDERSEN_ADMISSION_PROFILE_ROOT"] = str(root)
    command = [
        str(pangs),
        "analyze",
        str(module),
        "--out",
        str(out),
        "--stage",
        stage,
        "--build-mode",
        module_mode(module),
    ]
    if stage == "andersen":
        command.extend(["--partition-budget", "0"])
    completed = subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"{module.name} {stage} root={root} failed:\n{completed.stderr}"
        )
    return completed.stderr


def profile_records(stderr: str, kind: str) -> list[dict[str, Any]]:
    records = []
    for line in stderr.splitlines():
        if not line.startswith(PROFILE_PREFIX):
            continue
        record = json.loads(line[len(PROFILE_PREFIX) :])
        if record["kind"] == kind:
            records.append(record)
    return records


def canonical_rows(path: pathlib.Path, family: str) -> set[str]:
    rows = set()
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            # Admission changes the provenance tier even when the target answer
            # is identical. The calibration asks whether the target row changed.
            if family == "callgraph.jsonl":
                row.pop("tier", None)
            rows.add(json.dumps(row, sort_keys=True, separators=(",", ":")))
    return rows


def row_delta(baseline: pathlib.Path, candidate: pathlib.Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    changed = False
    for family in OUTPUT_FAMILIES:
        base_rows = canonical_rows(baseline / family, family)
        candidate_rows = canonical_rows(candidate / family, family)
        added = len(candidate_rows - base_rows)
        removed = len(base_rows - candidate_rows)
        label = family.removesuffix(".jsonl")
        result[f"{label}_rows_added"] = added
        result[f"{label}_rows_removed"] = removed
        changed |= added != 0 or removed != 0
    result["client_visible_difference"] = changed
    return result


def profile_module(
    pangs: pathlib.Path,
    module: pathlib.Path,
    min_quadratic_proxy: int,
    sample_below: int,
    max_nodes: int | None,
    max_edges: int | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix=f"pangs-admission-{module.stem}-") as tmp:
        root_dir = pathlib.Path(tmp)
        baseline = root_dir / "steens"
        run_analysis(pangs, module, baseline, "steens")

        census_out = root_dir / "census"
        census_stderr = run_analysis(pangs, module, census_out, "andersen")
        structures = profile_records(census_stderr, "structure")
        shutil.rmtree(census_out)
        for structure in structures:
            structure["module"] = module.name
            structure["build_mode"] = module_mode(module)

        safe = [
            structure
            for structure in structures
            if (max_nodes is None or structure["nodes"] <= max_nodes)
            and (max_edges is None or structure["edges"] <= max_edges)
        ]
        selected = [
            structure
            for structure in safe
            if structure["quadratic_proxy"] >= min_quadratic_proxy
        ]
        below = sorted(
            (
                structure
                for structure in safe
                if structure["quadratic_proxy"] < min_quadratic_proxy
            ),
            key=lambda structure: structure["quadratic_proxy"],
            reverse=True,
        )
        selected.extend(below[:sample_below])

        records = []
        for structure in selected:
            root = structure["root"]
            candidate = root_dir / f"root-{root}"
            stderr = run_analysis(pangs, module, candidate, "andersen", root)
            work_records = profile_records(stderr, "work")
            if len(work_records) != 1:
                raise RuntimeError(
                    f"{module.name} root={root}: expected one work record, "
                    f"found {len(work_records)}"
                )
            record = {
                "module": module.name,
                "build_mode": module_mode(module),
                **structure,
                **work_records[0],
                **row_delta(baseline, candidate),
            }
            records.append(record)
            shutil.rmtree(candidate)
        return structures, records


def modules(args: argparse.Namespace) -> list[pathlib.Path]:
    if args.module:
        return [args.module.resolve()]
    return sorted(args.corpus.expanduser().resolve().glob("*.bc"))


def main() -> None:
    args = parse_args()
    pangs = args.pangs.expanduser().resolve()
    selected = modules(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    census_output = None
    if args.census_output:
        args.census_output.parent.mkdir(parents=True, exist_ok=True)
        census_output = args.census_output.open("w")
    try:
        output = args.output.open("w")
        with output:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
                futures = {
                    executor.submit(
                        profile_module,
                        pangs,
                        module,
                        args.min_quadratic_proxy,
                        args.sample_below,
                        args.max_nodes,
                        args.max_edges,
                    ): module
                    for module in selected
                }
                for future in concurrent.futures.as_completed(futures):
                    module = futures[future]
                    try:
                        structures, records = future.result()
                    except Exception as error:
                        raise SystemExit(f"{module}: {error}") from error
                    if census_output:
                        for structure in structures:
                            census_output.write(json.dumps(structure, sort_keys=True) + "\n")
                        census_output.flush()
                    for record in records:
                        output.write(json.dumps(record, sort_keys=True) + "\n")
                    output.flush()
    finally:
        if census_output:
            census_output.close()


if __name__ == "__main__":
    main()
