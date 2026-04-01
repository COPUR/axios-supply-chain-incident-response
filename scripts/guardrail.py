#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

POLICY_FILE = os.environ.get("GUARDRAIL_POLICY_FILE", "policies/guardrail-policy.json")
RESULT_FILE = os.environ.get("GUARDRAIL_RESULT_FILE", "guardrail-result.json")
LOCK_FILES = ["package-lock.json", "npm-shrinkwrap.json"]


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def find_lockfile() -> str:
    for f in LOCK_FILES:
        if os.path.exists(f):
            return f
    print("ERROR: package-lock.json or npm-shrinkwrap.json not found", file=sys.stderr)
    sys.exit(2)


def extract_packages_from_lock(lock_data: Dict[str, Any]) -> List[Tuple[str, str]]:
    found: Set[Tuple[str, str]] = set()

    if "packages" in lock_data and isinstance(lock_data["packages"], dict):
        for path, meta in lock_data["packages"].items():
            if path == "":
                continue
            name = meta.get("name")
            version = meta.get("version")
            if not name:
                parts = path.split("node_modules/")
                name = parts[-1] if parts else path
            if name and version:
                found.add((name, version))

    def walk_deps(deps: Dict[str, Any]):
        for name, meta in deps.items():
            version = meta.get("version")
            if version:
                found.add((name, version))
            sub = meta.get("dependencies", {})
            if isinstance(sub, dict):
                walk_deps(sub)

    if "dependencies" in lock_data and isinstance(lock_data["dependencies"], dict):
        walk_deps(lock_data["dependencies"])

    return sorted(found)


def is_allowlisted(name: str, allowlist: List[str]) -> bool:
    for pattern in allowlist:
        if pattern.endswith("/*"):
            prefix = pattern[:-1]
            if name.startswith(prefix):
                return True
        elif name == pattern:
            return True
    return False


def fetch_npm_metadata(pkg_name: str) -> Dict[str, Any]:
    url = f"https://registry.npmjs.org/{pkg_name}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "guardrail-agent/1.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_publish_time(pkg_name: str, version: str) -> str:
    meta = fetch_npm_metadata(pkg_name)
    times = meta.get("time", {})
    published = times.get(version)
    if not published:
        raise ValueError(f"publish time not found for {pkg_name}@{version}")
    return published


def compute_age_hours(published_at: str) -> float:
    dt = parse_iso8601(published_at)
    delta = now_utc() - dt
    return delta.total_seconds() / 3600.0


def main() -> int:
    policy = load_json(POLICY_FILE)
    lockfile = find_lockfile()
    lock_data = load_json(lockfile)
    packages = extract_packages_from_lock(lock_data)

    denylist: Dict[str, List[str]] = policy.get("denylist", {})
    allowlist: List[str] = policy.get("allowlist", [])
    min_age = int(policy.get("min_package_age_hours", 48))
    strict_mode = bool(policy.get("strict_mode", True))

    blocked = []
    quarantined = []
    allowed = []
    errors = []

    for name, version in packages:
        if is_allowlisted(name, allowlist):
            allowed.append({"name": name, "version": version, "reason": "allowlisted"})
            continue

        if name in denylist and version in denylist[name]:
            blocked.append({"name": name, "version": version, "reason": "denylisted_version"})
            continue

        try:
            published_at = get_publish_time(name, version)
            age_hours = compute_age_hours(published_at)

            if age_hours < min_age:
                quarantined.append(
                    {
                        "name": name,
                        "version": version,
                        "published_at": published_at,
                        "age_hours": round(age_hours, 2),
                        "reason": f"package_younger_than_{min_age}_hours",
                    }
                )
            else:
                allowed.append(
                    {
                        "name": name,
                        "version": version,
                        "published_at": published_at,
                        "age_hours": round(age_hours, 2),
                        "reason": "age_ok",
                    }
                )
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError) as e:
            msg = str(e)
            errors.append({"name": name, "version": version, "error": msg})
            if strict_mode:
                quarantined.append(
                    {
                        "name": name,
                        "version": version,
                        "reason": "metadata_unavailable_strict_mode",
                        "error": msg,
                    }
                )
            else:
                allowed.append(
                    {
                        "name": name,
                        "version": version,
                        "reason": "metadata_unavailable_non_strict_mode",
                    }
                )

    status = "allow"
    exit_code = 0

    if blocked:
        status = "block"
        exit_code = 1
    elif quarantined:
        status = "quarantine"
        exit_code = 3

    result = {
        "status": status,
        "lockfile": lockfile,
        "policy_file": POLICY_FILE,
        "summary": {
            "total_packages": len(packages),
            "blocked_count": len(blocked),
            "quarantined_count": len(quarantined),
            "allowed_count": len(allowed),
            "errors_count": len(errors),
        },
        "blocked": blocked,
        "quarantined": quarantined,
        "allowed": allowed[:25],
        "errors": errors,
    }

    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result["summary"], indent=2))

    if status == "block":
        print("BUILD BLOCKED: denylisted dependency detected", file=sys.stderr)
    elif status == "quarantine":
        print("BUILD QUARANTINED: dependency newer than policy threshold", file=sys.stderr)
    else:
        print("BUILD ALLOWED")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
