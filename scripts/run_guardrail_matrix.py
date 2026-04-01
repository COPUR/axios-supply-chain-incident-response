#!/usr/bin/env python3
import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json"}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".runtime",
    ".npm-cache",
    "dist",
    "build",
    "target",
    "vendor",
}


def discover_lockfiles(roots: List[Path], extra_excludes: List[str]) -> List[Path]:
    lockfiles: List[Path] = []

    for root in roots:
        if not root.exists():
            continue
        if root.is_file() and root.name in LOCKFILE_NAMES:
            lockfiles.append(root.resolve())
            continue

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            current = Path(dirpath)
            for filename in filenames:
                if filename not in LOCKFILE_NAMES:
                    continue
                candidate = (current / filename).resolve()
                normalized = str(candidate)
                if any(ex in normalized for ex in extra_excludes):
                    continue
                lockfiles.append(candidate)

    return sorted(set(lockfiles))


def read_lockfiles_file(path: Path, extra_excludes: List[str]) -> List[Path]:
    lockfiles = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        p = Path(line).resolve()
        if any(ex in str(p) for ex in extra_excludes):
            continue
        if p.name in LOCKFILE_NAMES and p.exists():
            lockfiles.append(p)
    return sorted(set(lockfiles))


def git_toplevel(path: Path) -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            .strip()
        )
    except subprocess.SubprocessError:
        return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run guardrail checks for every Node lockfile.")
    parser.add_argument("--roots", nargs="+", default=["."], help="Root paths to discover lockfiles from.")
    parser.add_argument("--lockfiles-file", default="", help="Optional file listing lockfiles, one per line.")
    parser.add_argument("--output-dir", default="guardrail-matrix-output", help="Directory for result artifacts.")
    parser.add_argument("--policy-file", default="policies/guardrail-policy.json", help="Guardrail policy file.")
    parser.add_argument("--guardrail-script", default="scripts/guardrail.py", help="Path to guardrail script.")
    parser.add_argument(
        "--cache-file",
        default=".guardrail-npm-metadata-cache.json",
        help="Shared metadata cache file used by all lockfile runs.",
    )
    parser.add_argument("--denylist-only", action="store_true", help="Enable denylist-only mode.")
    parser.add_argument(
        "--age-scope",
        choices=["all", "direct"],
        default="all",
        help="Scope for package age checks in full mode.",
    )
    parser.add_argument(
        "--http-timeout-seconds",
        type=int,
        default=10,
        help="HTTP timeout for npm metadata calls inside guardrail.",
    )
    parser.add_argument(
        "--runner-timeout-seconds",
        type=int,
        default=240,
        help="Timeout per lockfile guardrail subprocess.",
    )
    parser.add_argument(
        "--exclude-substring",
        action="append",
        default=[],
        help="Exclude lockfile paths containing this substring. Can be provided multiple times.",
    )
    parser.add_argument(
        "--exit-on",
        choices=["all", "block-only"],
        default="all",
        help="Exit policy: fail on all non-allow statuses or only on block.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    results_dir = output_dir / "results"
    summary_csv = output_dir / "summary.csv"
    summary_json = output_dir / "summary.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    extra_excludes = args.exclude_substring or []

    if args.lockfiles_file:
        lockfiles = read_lockfiles_file(Path(args.lockfiles_file).resolve(), extra_excludes)
    else:
        roots = [Path(r).resolve() for r in args.roots]
        lockfiles = discover_lockfiles(roots, extra_excludes)

    print(f"LOCKFILE_COUNT={len(lockfiles)}")
    if not lockfiles:
        print("No lockfiles found. Nothing to do.")
        return 0

    guardrail_script = Path(args.guardrail_script).resolve()
    policy_file = Path(args.policy_file).resolve()
    cache_file = Path(args.cache_file).resolve()

    rows: List[Dict[str, object]] = []

    for idx, lockfile in enumerate(lockfiles, start=1):
        project_dir = lockfile.parent
        repo_root = git_toplevel(project_dir)
        safe_name = str(lockfile).replace("/", "__").replace(":", "_")
        result_file = results_dir / f"{safe_name}.json"

        env = os.environ.copy()
        env["GUARDRAIL_POLICY_FILE"] = str(policy_file)
        env["GUARDRAIL_RESULT_FILE"] = str(result_file)
        env["GUARDRAIL_CACHE_FILE"] = str(cache_file)
        env["GUARDRAIL_HTTP_TIMEOUT_SECONDS"] = str(args.http_timeout_seconds)
        env["GUARDRAIL_AGE_SCOPE"] = args.age_scope
        if args.denylist_only:
            env["GUARDRAIL_DENYLIST_ONLY"] = "1"

        start = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                ["python3", str(guardrail_script)],
                cwd=str(project_dir),
                env=env,
                text=True,
                capture_output=True,
                timeout=args.runner_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            proc = subprocess.CompletedProcess(
                args=exc.cmd,
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )

        duration = round(time.time() - start, 2)

        status = "timeout" if timed_out else "error"
        mode = "unknown"
        age_scope = "unknown"
        blocked = 0
        quarantined = 0
        allowed = 0
        errors = 0

        if result_file.exists():
            try:
                payload = json.loads(result_file.read_text(encoding="utf-8"))
                status = payload.get("status", status)
                mode = payload.get("mode", mode)
                age_scope = payload.get("age_scope", age_scope)
                summary = payload.get("summary", {})
                blocked = int(summary.get("blocked_count", 0) or 0)
                quarantined = int(summary.get("quarantined_count", 0) or 0)
                allowed = int(summary.get("allowed_count", 0) or 0)
                errors = int(summary.get("errors_count", 0) or 0)
            except (OSError, json.JSONDecodeError, ValueError):
                status = "error"

        row: Dict[str, object] = {
            "repo_root": repo_root,
            "project_dir": str(project_dir),
            "lockfile": str(lockfile),
            "mode": mode,
            "age_scope": age_scope,
            "status": status,
            "exit_code": proc.returncode,
            "blocked_count": blocked,
            "quarantined_count": quarantined,
            "allowed_count": allowed,
            "errors_count": errors,
            "duration_seconds": duration,
            "stderr_tail": "\n".join(str(proc.stderr).strip().splitlines()[-3:]) if proc.stderr else "",
        }
        rows.append(row)
        print(
            f"[{idx}/{len(lockfiles)}] {status.upper()} mode={mode} "
            f"age_scope={age_scope} blocked={blocked} quarantined={quarantined} errors={errors} "
            f"path={lockfile}"
        )

    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "repo_root",
                "project_dir",
                "lockfile",
                "mode",
                "age_scope",
                "status",
                "exit_code",
                "blocked_count",
                "quarantined_count",
                "allowed_count",
                "errors_count",
                "duration_seconds",
                "stderr_tail",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    aggregate = {
        "output_dir": str(output_dir),
        "lockfile_count": len(lockfiles),
        "status_counts": {},
        "rows": rows,
    }
    for row in rows:
        key = str(row["status"])
        aggregate["status_counts"][key] = aggregate["status_counts"].get(key, 0) + 1

    summary_json.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")

    print("--- AGGREGATE ---")
    print(json.dumps(aggregate["status_counts"], indent=2))
    print(f"SUMMARY_CSV={summary_csv}")
    print(f"SUMMARY_JSON={summary_json}")

    blocks = int(aggregate["status_counts"].get("block", 0))
    quarantines = int(aggregate["status_counts"].get("quarantine", 0))
    timeouts = int(aggregate["status_counts"].get("timeout", 0))
    errors = int(aggregate["status_counts"].get("error", 0))

    if args.exit_on == "block-only":
        return 1 if blocks > 0 else 0

    if blocks > 0:
        return 1
    if quarantines > 0:
        return 3
    if timeouts > 0:
        return 4
    if errors > 0:
        return 5
    return 0


if __name__ == "__main__":
    sys.exit(main())
