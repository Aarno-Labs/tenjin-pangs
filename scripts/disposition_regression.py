#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PANGS_ROOT = SCRIPT_DIR.parent
CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", str(Path.home() / "pangs-corpus")))
PANGS_BIN = Path(os.environ.get("PANGS_BIN", str(PANGS_ROOT / "target/release/pangs")))
CHIBICC_REPO_ROOT = Path(os.environ.get("CHIBICC_REPO_ROOT", str(CORPUS_ROOT / "chibicc")))
SLAP_REPO_ROOT = Path(os.environ.get("SLAP_REPO_ROOT", str(Path.home() / "xj-res/surprisetalk__slap")))

CONFIGURATION_ENV_OVERRIDES = {
    "vanilla": {
        "PANGS_ANDERSEN_RECEIVER_PAYLOADS": None,
        "PANGS_ANDERSEN_CLOSED_PRODUCERS": None,
        "PANGS_ANDERSEN_CLOSED_CONSUMERS": None,
    },
    "experimental": {
        "PANGS_ANDERSEN_RECEIVER_PAYLOADS": "1",
        "PANGS_ANDERSEN_CLOSED_PRODUCERS": "1",
        "PANGS_ANDERSEN_CLOSED_CONSUMERS": "1",
    },
}

warnings = 0


def die(message: str, code: int = 2) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def run_case(
    run_root: Path,
    label: str,
    module: str,
    source_root: Path,
    expected: int,
    configuration: str,
    partition_budget: int = 200000,
) -> None:
    global warnings

    input_path = CORPUS_ROOT / "_out_bc" / module
    out = run_root / label

    if not input_path.is_file():
        die(f"corpus module not found: {input_path}")
    if not source_root.is_dir():
        die(f"source repository not found: {source_root}")

    if configuration not in CONFIGURATION_ENV_OVERRIDES:
        die(f"unknown disposition configuration: {configuration}")

    env = os.environ.copy()
    for key, value in CONFIGURATION_ENV_OVERRIDES[configuration].items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value

    stdout_path = run_root / f"{label}.stdout"
    stderr_path = run_root / f"{label}.stderr"
    with stdout_path.open("wb") as stdout_f, stderr_path.open("wb") as stderr_f:
        result = subprocess.run(
            [
                str(PANGS_BIN),
                "analyze",
                str(input_path),
                "--out",
                str(out),
                "--stage",
                "andersen",
                "--partition-budget",
                str(partition_budget),
                "--build-mode",
                "executable",
                "--dispose",
                "--no-overrides",
                "--validate",
                "--repo-root",
                str(source_root),
            ],
            env=env,
            stdout=stdout_f,
            stderr=stderr_f,
        )

    if result.returncode != 0:
        print(f"error: disposition analysis failed for {label}", file=sys.stderr)
        with stderr_path.open("r", errors="replace") as f:
            for line in f.readlines()[:120]:
                sys.stderr.write(line)
        sys.exit(1)

    manifest_path = out / "pangs-manifest.json"
    if not manifest_path.is_file():
        die(f"analysis produced no manifest for {label}", code=1)

    manifest = json.loads(manifest_path.read_text())
    unhandled = [
        g for g in manifest.get("globals", []) if g.get("disposition", {}).get("chosen") == "unhandled"
    ]
    actual = len(unhandled)
    print(f"{label:<21} unhandled={actual} expected<={expected}")

    if actual > expected:
        warnings += 1
        print(
            f"WARNING: {label} has {actual} unhandled globals; expected at most {expected}",
            file=sys.stderr,
        )
        for g in unhandled:
            name = g.get("meta", {}).get("llvm_name") or g.get("key")
            print(f"  - {name}", file=sys.stderr)


def main() -> None:
    if os.environ.get("SKIP_BUILD", "0") != "1":
        subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(PANGS_ROOT / "Cargo.toml"),
                "--release",
                "-p",
                "pangs-cli",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    if not PANGS_BIN.is_file() or not os.access(PANGS_BIN, os.X_OK):
        die(f"pangs executable not found: {PANGS_BIN}")

    with tempfile.TemporaryDirectory(prefix="pangs-disposition-regression-") as run_root_str:
        run_root = Path(run_root_str)

        run_case(run_root, "chibicc-vanilla", "exe-chibicc-O1.bc", CHIBICC_REPO_ROOT, 2, "vanilla")
        run_case(run_root, "chibicc-experimental", "exe-chibicc-O1.bc", CHIBICC_REPO_ROOT, 2, "experimental")
        run_case(
            run_root,
            "chibicc-big-budget",
            "exe-chibicc-O1.bc",
            CHIBICC_REPO_ROOT,
            2,
            "experimental",
            partition_budget=200000000,
        )
        run_case(run_root, "slap", "exe-surprisetalk__slap-O0.bc", SLAP_REPO_ROOT, 4, "experimental")

    if warnings == 0:
        print("disposition regression check completed without warnings")
    else:
        print(f"disposition regression check completed with {warnings} warning(s)")


if __name__ == "__main__":
    main()
