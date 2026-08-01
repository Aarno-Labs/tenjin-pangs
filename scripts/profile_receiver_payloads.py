#!/usr/bin/env python3
"""Fresh paired corpus profiler for the receiver-payload Andersen prototype.

This intentionally uses the current corpus and one caller-supplied release binary.  It
profiles baseline versus ``PANGS_ANDERSEN_RECEIVER_PAYLOADS=1`` at the ordinary admission
budget for every top-level bitcode input (including OpenSSL and Vim), then adds a forced-full
``u64::MAX`` pair for chibicc O1.  Analysis outputs are summarized and removed; compact stderr,
stdout, and timing logs are retained when requested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = pathlib.Path.home() / "pangs-corpus" / "_out_bc"
STANDARD_BUDGET = "200000"
FULL_BUDGET = "18446744073709551615"
FORCED_MODULE = "exe-chibicc-O1.bc"
EXPORTS = (
    "callgraph.jsonl",
    "modref.jsonl",
    "globals.jsonl",
    "stationarity.jsonl",
    "audit.jsonl",
)
SCOPE_RE = re.compile(r"pangs andersen profile: scope (?P<fields>.*)$")
FINAL_RE = re.compile(r"pangs andersen profile: joint solve done (?P<fields>.*)$")
EXHAUSTED_RE = re.compile(r"pangs andersen exhausted: (?P<fields>.*)$")
PAYLOAD_INFER_RE = re.compile(r"pangs receiver payloads: inferred=(?P<inferred>\d+)")
PAYLOAD_SUMMARY_RE = re.compile(r"pangs receiver payloads: contexts=(?P<fields>.*)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=pathlib.Path, default=DEFAULT_CORPUS)
    parser.add_argument("--pangs", type=pathlib.Path, default=ROOT / "target" / "release" / "pangs")
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument("--partition-budget", default=STANDARD_BUDGET)
    parser.add_argument("--forced-module", default=FORCED_MODULE)
    parser.add_argument("--forced-budget", default=FULL_BUDGET)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--keep-run-logs", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def build_mode(module: pathlib.Path) -> str:
    return "library" if module.name.startswith("lib-") else "executable"


def parse_nonnegative(value: str, name: str) -> str:
    try:
        parsed = int(value)
    except ValueError as error:
        raise SystemExit(f"{name} must be a nonnegative integer") from error
    if parsed < 0:
        raise SystemExit(f"{name} must be a nonnegative integer")
    return str(parsed)


def fields(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in text.split():
        key, separator, value = item.partition("=")
        if separator and value.isdigit():
            result[key] = int(value)
    return result


def profile_lines(stderr: pathlib.Path) -> dict[str, Any]:
    scope: dict[str, int] = {}
    final: dict[str, int] = {}
    exhausted: list[dict[str, int]] = []
    inferred: int | None = None
    summaries: list[dict[str, int]] = []
    if not stderr.is_file():
        return {"scope": scope, "final": final, "exhausted": exhausted,
                "receiver_payload_inferred": inferred, "receiver_payload_summaries": summaries}
    for line in stderr.read_text(errors="replace").splitlines():
        if match := SCOPE_RE.search(line):
            scope = fields(match.group("fields"))
        if match := FINAL_RE.search(line):
            final = fields(match.group("fields"))
        if match := EXHAUSTED_RE.search(line):
            exhausted.append(fields(match.group("fields")))
        if match := PAYLOAD_INFER_RE.search(line):
            inferred = int(match.group("inferred"))
        if match := PAYLOAD_SUMMARY_RE.search(line):
            summaries.append(fields(match.group("fields")))
    return {"scope": scope, "final": final, "exhausted": exhausted,
            "receiver_payload_inferred": inferred, "receiver_payload_summaries": summaries}


def export_stats(output: pathlib.Path) -> dict[str, dict[str, int | str]]:
    result: dict[str, dict[str, int | str]] = {}
    for name in EXPORTS:
        path = output / name
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        records = 0
        with path.open("rb") as handle:
            for line in handle:
                digest.update(line)
                records += 1
        result[name] = {"sha256": digest.hexdigest(), "records": records, "bytes": path.stat().st_size}
    return result


def indirect_edges(output: pathlib.Path) -> set[tuple[str, str, str]]:
    path = output / "callgraph.jsonl"
    result: set[tuple[str, str, str]] = set()
    if not path.is_file():
        return result
    with path.open(errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("kind") != "indirect":
                continue
            callsite = row.get("callsite", "")
            callee = row.get("callee", {}).get("func", "")
            tier = row.get("tier", "")
            result.add((callsite, callee, tier))
    return result


def payload_environment(enabled: bool) -> dict[str, str]:
    # Starting from a clean PANGS experiment environment makes both arms independent of a
    # developer shell that happened to enable another prototype.
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("PANGS_ANDERSEN_") or key.startswith("PANGS_PARTITION_"):
            environment.pop(key, None)
    environment["PANGS_ANDERSEN_PROFILE"] = "1"
    if enabled:
        environment["PANGS_ANDERSEN_RECEIVER_PAYLOADS"] = "1"
    return environment


def run_one(
    pangs: pathlib.Path,
    module: pathlib.Path,
    label: str,
    budget: str,
    timeout_seconds: int,
    run_dir: pathlib.Path,
    keep_logs: bool,
) -> dict[str, Any]:
    output = run_dir / "output"
    stdout, stderr, timing = run_dir / "stdout.log", run_dir / "stderr.log", run_dir / "time.txt"
    command = [
        "/usr/bin/time", "-f", "%e %U %S %M", "-o", str(timing), str(pangs), "analyze",
        str(module), "--out", str(output), "--stage", "andersen", "--build-mode", build_mode(module),
        "--partition-budget", budget,
    ]
    started = time.monotonic()
    timed_out = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(
            command, stdout=out, stderr=err, env=payload_environment(label == "receiver_payloads"),
            start_new_session=True,
        )
        try:
            returncode: int | None = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            returncode = None
    elapsed = time.monotonic() - started
    wall = user = system = None
    rss = None
    if timing.is_file():
        values = timing.read_text(errors="replace").split()
        if len(values) == 4:
            wall, user, system, rss = float(values[0]), float(values[1]), float(values[2]), int(values[3])
    result: dict[str, Any] = {
        "module": module.name, "build_mode": build_mode(module), "configuration": label,
        "partition_budget": budget, "command": command, "returncode": returncode, "timed_out": timed_out,
        "driver_elapsed_seconds": elapsed, "wall_seconds": wall, "user_seconds": user,
        "system_seconds": system, "peak_rss_kib": rss, "profile": profile_lines(stderr),
        "exports": export_stats(output) if returncode == 0 else {},
        "indirect_edges": sorted(indirect_edges(output)) if returncode == 0 else [],
    }
    if returncode != 0 and stderr.is_file():
        result["stderr_tail"] = stderr.read_text(errors="replace")[-4000:]
    # Export files can be very large. The JSON records their content hash/count/size and target
    # set; retain compact execution logs but do not consume corpus-scale disk for duplicate output.
    shutil.rmtree(output, ignore_errors=True)
    if keep_logs:
        result["log_dir"] = str(run_dir)
    else:
        shutil.rmtree(run_dir, ignore_errors=True)
    return result


def pair_summary(baseline: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    export_difference: dict[str, dict[str, int | bool]] = {}
    for name in EXPORTS:
        before, after = baseline["exports"].get(name), payload["exports"].get(name)
        export_difference[name] = {
            "changed": before != after,
            "baseline_records": before.get("records", 0) if before else 0,
            "payload_records": after.get("records", 0) if after else 0,
            "record_delta": (after.get("records", 0) if after else 0) - (before.get("records", 0) if before else 0),
        }
    before_edges, after_edges = set(map(tuple, baseline["indirect_edges"])), set(map(tuple, payload["indirect_edges"]))
    changed_sites = {site for site, _, _ in before_edges ^ after_edges}
    return {
        "completed": baseline["returncode"] == payload["returncode"] == 0,
        "export_difference": export_difference,
        "indirect_targets": {
            "baseline_edges": len(before_edges), "payload_edges": len(after_edges),
            "added_edges": len(after_edges - before_edges), "removed_edges": len(before_edges - after_edges),
            "changed_callsites": len(changed_sites), "changed_callsite_sample": sorted(changed_sites)[:12],
        },
        "oversize_fallbacks": {
            "baseline": baseline["profile"]["scope"].get("oversize_fallbacks", 0),
            "payload": payload["profile"]["scope"].get("oversize_fallbacks", 0),
        },
        "exhaustion_events": {
            "baseline": len(baseline["profile"]["exhausted"]),
            "payload": len(payload["profile"]["exhausted"]),
        },
    }


def emit(record: dict[str, Any], case: str) -> None:
    status = "timeout" if record["timed_out"] else f"exit={record['returncode']}"
    print(
        f"{case:<10} {record['module']:<34} {record['configuration']:<18} {status:<10} "
        f"wall={record['wall_seconds']}s user={record['user_seconds']}s rss={record['peak_rss_kib']}KiB",
        flush=True,
    )


def main() -> int:
    args = parse_args()
    corpus, pangs, results = args.corpus.expanduser().resolve(), args.pangs.expanduser().resolve(), args.results.expanduser().resolve()
    if not corpus.is_dir() or not pangs.is_file() or not os.access(pangs, os.X_OK):
        raise SystemExit("corpus directory or executable pangs binary is unavailable")
    standard_budget = parse_nonnegative(args.partition_budget, "--partition-budget")
    forced_budget = parse_nonnegative(args.forced_budget, "--forced-budget")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    modules = sorted(corpus.glob("*.bc"))
    forced = corpus / args.forced_module
    if not forced.is_file():
        raise SystemExit(f"forced module does not exist: {forced}")
    results.parent.mkdir(parents=True, exist_ok=True)
    if args.resume and results.is_file():
        document = json.loads(results.read_text())
        if document.get("modules") != [path.name for path in modules]:
            raise SystemExit("resume result uses a different corpus")
    else:
        document = {
            "schema": 1, "pangs": str(pangs), "corpus": str(corpus), "modules": [path.name for path in modules],
            "standard_partition_budget": standard_budget, "forced_module": forced.name,
            "forced_partition_budget": forced_budget, "timeout_seconds": args.timeout_seconds,
            "points_to_representation": "standard default: hash sets (hybrid opt-in disabled)",
            "baseline_environment": {"PANGS_ANDERSEN_PROFILE": "1"},
            "receiver_payload_environment": {"PANGS_ANDERSEN_PROFILE": "1", "PANGS_ANDERSEN_RECEIVER_PAYLOADS": "1"},
            "runs": [], "pairs": [],
        }
    seen = {(row["case"], row["module"], row["configuration"]) for row in document["runs"]}
    log_root = results.parent / f"{results.stem}-logs"
    if args.keep_run_logs:
        log_root.mkdir(exist_ok=True)
    cases = [("standard", path, standard_budget) for path in modules] + [("forced_chibicc", forced, forced_budget)]
    print(f"standard_modules={len(modules)} including_openssl_vim=1 completed={len(seen)} results={results}", flush=True)
    with tempfile.TemporaryDirectory(prefix="pangs-receiver-payloads-") as scratch_text:
        scratch = pathlib.Path(scratch_text)
        for index, (case, module, budget) in enumerate(cases):
            order = ("baseline", "receiver_payloads") if index % 2 == 0 else ("receiver_payloads", "baseline")
            for label in order:
                key = (case, module.name, label)
                if key in seen:
                    continue
                run_dir = (log_root if args.keep_run_logs else scratch) / f"{case}-{index:03d}-{module.stem}-{label}"
                run_dir.mkdir(parents=True, exist_ok=True)
                record = run_one(pangs, module, label, budget, args.timeout_seconds, run_dir, args.keep_run_logs)
                record["case"] = case
                document["runs"].append(record)
                seen.add(key)
                results.write_text(json.dumps(document, indent=2) + "\n")
                emit(record, case)
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in document["runs"]:
        grouped[(row["case"], row["module"])][row["configuration"]] = row
    document["pairs"] = [
        {"case": case, "module": module, **pair_summary(rows["baseline"], rows["receiver_payloads"])}
        for (case, module), rows in sorted(grouped.items())
        if "baseline" in rows and "receiver_payloads" in rows
    ]
    results.write_text(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
