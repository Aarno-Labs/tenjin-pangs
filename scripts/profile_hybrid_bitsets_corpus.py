#!/usr/bin/env python3
"""Paired time/RSS measurements for hybrid Andersen points-to sets.

The default input is every top-level ``*.bc`` in the PANGS corpus except
OpenSSL and Vim.  Each module is solved with the requested partition budget
in both the ordinary hash-set and default hybrid representations.  Analysis
exports are retained only long enough to compute content hashes, so a full
corpus pass does not leave a large output tree behind.

Example:

  scripts/profile_hybrid_bitsets_corpus.py \
      --results /tmp/pangs-hybrid-corpus-$(date +%Y%m%d).json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = pathlib.Path.home() / "pangs-corpus" / "_out_bc"
MAX_PARTITION_BUDGET = "18446744073709551615"
EXCLUDED_TOKENS = ("openssl", "vim")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=pathlib.Path, default=DEFAULT_CORPUS)
    parser.add_argument(
        "--pangs", type=pathlib.Path, default=ROOT / "target" / "release" / "pangs"
    )
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument(
        "--partition-budget",
        default=MAX_PARTITION_BUDGET,
        help=(
            "partition admission budget passed to pangs "
            f"(default: {MAX_PARTITION_BUDGET}; normal default: 200000)"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=1_800,
        help="per-analysis timeout (default: 1800)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        help="optional PANGS_ANDERSEN_HYBRID_BITSET_THRESHOLD override",
    )
    parser.add_argument(
        "--keep-run-logs",
        action="store_true",
        help="keep stdout/stderr files next to the result JSON",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume an interrupted run file, retaining completed configurations",
    )
    return parser.parse_args()


def build_mode(module: pathlib.Path) -> str:
    return "library" if module.name.startswith("lib-") else "executable"


def classify_modules(corpus: pathlib.Path) -> tuple[list[pathlib.Path], list[dict[str, str]]]:
    included: list[pathlib.Path] = []
    excluded: list[dict[str, str]] = []
    for module in sorted(corpus.glob("*.bc")):
        name = module.name.lower()
        token = next((token for token in EXCLUDED_TOKENS if token in name), None)
        if token:
            excluded.append({"module": module.name, "reason": f"requested exclusion: {token}"})
        else:
            included.append(module)
    return included, excluded


SEMANTIC_EXPORTS = (
    "callgraph.jsonl",
    "modref.jsonl",
    "globals.jsonl",
    "stationarity.jsonl",
    "audit.jsonl",
)


def hash_exports(out_dir: pathlib.Path) -> dict[str, str]:
    """Hash the deterministic client-visible export families.

    The manifest carries configuration details (including the points-to representation) and
    is therefore deliberately not part of semantic equivalence.
    """
    result: dict[str, str] = {}
    if not out_dir.is_dir():
        return result
    for name in SEMANTIC_EXPORTS:
        path = out_dir / name
        if path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def semantic_hashes(record: dict[str, Any]) -> dict[str, str | None]:
    """Extract only client-visible hashes from both new and legacy run files."""
    hashes = record["export_hashes"]
    return {name: hashes.get(name) for name in SEMANTIC_EXPORTS}


def run_one(
    pangs: pathlib.Path,
    module: pathlib.Path,
    label: str,
    partition_budget: str,
    timeout_seconds: int,
    threshold: int | None,
    run_dir: pathlib.Path,
    keep_logs: bool,
) -> dict[str, Any]:
    output = run_dir / "output"
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    time_path = run_dir / "time.txt"
    command = [
        "/usr/bin/time",
        "-f",
        "%e %M",
        "-o",
        str(time_path),
        str(pangs),
        "analyze",
        str(module),
        "--out",
        str(output),
        "--stage",
        "andersen",
        "--build-mode",
        build_mode(module),
        "--partition-budget",
        partition_budget,
    ]
    env = os.environ.copy()
    for key in (
        "PANGS_ANDERSEN_HYBRID_BITSETS",
        "PANGS_ANDERSEN_HYBRID_BITSET_THRESHOLD",
        "PANGS_ANDERSEN_HYBRID_SMALL_THRESHOLD",
        "PANGS_ANDERSEN_HYBRID_BITSET_MAX_BITS_PER_MEMBER",
        "PANGS_ANDERSEN_HYBRID_BITSETS_PROFILE",
    ):
        env.pop(key, None)
    if label == "baseline":
        env["PANGS_ANDERSEN_HYBRID_BITSETS"] = "0"
    else:
        if threshold is not None:
            env["PANGS_ANDERSEN_HYBRID_BITSET_THRESHOLD"] = str(threshold)

    started = time.monotonic()
    timed_out = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            command,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            returncode: int | None = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            # `/usr/bin/time` is a wrapper: signal its whole session so its PANGS
            # child cannot survive a timeout and overlap the next measurement.
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            returncode = None
    elapsed = time.monotonic() - started

    wall_seconds = None
    peak_rss_kib = None
    if time_path.is_file():
        fields = time_path.read_text(errors="replace").strip().split()
        if len(fields) == 2:
            wall_seconds = float(fields[0])
            peak_rss_kib = int(fields[1])

    record: dict[str, Any] = {
        "module": module.name,
        "build_mode": build_mode(module),
        "configuration": label,
        "command": command,
        "timeout_seconds": timeout_seconds,
        "returncode": returncode,
        "timed_out": timed_out,
        "driver_elapsed_seconds": elapsed,
        "wall_seconds": wall_seconds,
        "peak_rss_kib": peak_rss_kib,
        "export_hashes": hash_exports(output) if returncode == 0 else {},
    }
    if stderr_path.is_file() and returncode != 0:
        record["stderr_tail"] = stderr_path.read_text(errors="replace")[-4_000:]

    if not keep_logs:
        shutil.rmtree(run_dir, ignore_errors=True)
    return record


def emit_progress(record: dict[str, Any]) -> None:
    outcome = "timeout" if record["timed_out"] else f"exit={record['returncode']}"
    wall = record["wall_seconds"]
    rss = record["peak_rss_kib"]
    print(
        f"{record['module']:<42} {record['configuration']:<8} {outcome:<10} "
        f"wall={wall if wall is not None else '-'}s rss={rss if rss is not None else '-'}KiB",
        flush=True,
    )


def main() -> int:
    args = parse_args()
    corpus = args.corpus.expanduser().resolve()
    pangs = args.pangs.expanduser().resolve()
    results = args.results.expanduser().resolve()
    if not corpus.is_dir():
        raise SystemExit(f"corpus directory does not exist: {corpus}")
    if not pangs.is_file() or not os.access(pangs, os.X_OK):
        raise SystemExit(f"pangs binary is not executable: {pangs}")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    try:
        partition_budget = str(int(args.partition_budget))
    except ValueError as error:
        raise SystemExit("--partition-budget must be a nonnegative integer") from error
    if int(partition_budget) < 0:
        raise SystemExit("--partition-budget must be a nonnegative integer")
    if args.threshold is not None and args.threshold < 0:
        raise SystemExit("--threshold must be nonnegative")

    included, excluded = classify_modules(corpus)
    results.parent.mkdir(parents=True, exist_ok=True)
    logs_root = results.parent / f"{results.stem}-logs"
    if args.keep_run_logs:
        logs_root.mkdir(parents=True, exist_ok=True)

    if args.resume and results.is_file():
        document = json.loads(results.read_text())
        if document.get("included_modules") != [module.name for module in included]:
            raise SystemExit("existing result file has a different corpus selection")
        if document.get("partition_budget") != partition_budget:
            raise SystemExit("existing result file has a different partition budget")
        if document.get("timeout_seconds") != args.timeout_seconds:
            document.setdefault("timeout_policy_transitions", []).append(
                {
                    "after_completed_configurations": len(document["runs"]),
                    "from_timeout_seconds": document.get("timeout_seconds"),
                    "to_timeout_seconds": args.timeout_seconds,
                }
            )
            document["timeout_seconds"] = args.timeout_seconds
    else:
        document = {
            "schema": 1,
            "pangs": str(pangs),
            "corpus": str(corpus),
            "partition_budget": partition_budget,
            "stage": "andersen",
            "hybrid_threshold": args.threshold,
            "timeout_seconds": args.timeout_seconds,
            "included_modules": [module.name for module in included],
            "excluded_modules": excluded,
            "runs": [],
        }
    results.write_text(json.dumps(document, indent=2) + "\n")
    seen = {(record["module"], record["configuration"]) for record in document["runs"]}
    print(f"included={len(included)} excluded={len(excluded)} completed={len(seen)} results={results}", flush=True)

    with tempfile.TemporaryDirectory(prefix="pangs-hybrid-corpus-") as scratch_str:
        scratch = pathlib.Path(scratch_str)
        for index, module in enumerate(included):
            # Swap first configuration each pair so a monotonic thermal/cache drift
            # is not systematically assigned to one representation.
            order = ("baseline", "hybrid") if index % 2 == 0 else ("hybrid", "baseline")
            pair: list[dict[str, Any]] = []
            for label in order:
                if (module.name, label) in seen:
                    continue
                run_dir = (logs_root if args.keep_run_logs else scratch) / f"{index:03d}-{module.stem}-{label}"
                run_dir.mkdir(parents=True, exist_ok=True)
                record = run_one(
                    pangs,
                    module,
                    label,
                    partition_budget,
                    args.timeout_seconds,
                    args.threshold,
                    run_dir,
                    args.keep_run_logs,
                )
                pair.append(record)
                document["runs"].append(record)
                seen.add((module.name, label))
                results.write_text(json.dumps(document, indent=2) + "\n")
                emit_progress(record)
    by_module: dict[str, dict[str, dict[str, Any]]] = {}
    for record in document["runs"]:
        by_module.setdefault(record["module"], {})[record["configuration"]] = record
    pair_results = []
    for module in included:
        pair = by_module.get(module.name, {})
        baseline, hybrid = pair.get("baseline"), pair.get("hybrid")
        equivalent = None
        if baseline and hybrid and baseline["returncode"] == hybrid["returncode"] == 0:
            equivalent = semantic_hashes(baseline) == semantic_hashes(hybrid)
        pair_results.append({"module": module.name, "semantic_hashes_equal": equivalent})
    document["pair_results"] = pair_results
    results.write_text(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
