#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.parse
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


def extract_direct_packages_from_lock(lock_data: Dict[str, Any]) -> List[Tuple[str, str]]:
    found: Set[Tuple[str, str]] = set()

    lock_packages = lock_data.get("packages")
    if isinstance(lock_packages, dict):
        root_meta = lock_packages.get("", {})
        if isinstance(root_meta, dict):
            for section in ("dependencies", "optionalDependencies"):
                deps = root_meta.get(section, {})
                if not isinstance(deps, dict):
                    continue
                for name in deps.keys():
                    dep_meta = lock_packages.get(f"node_modules/{name}", {})
                    if isinstance(dep_meta, dict) and dep_meta.get("version"):
                        found.add((str(name), str(dep_meta["version"])))

    # Fallback for lockfile v1 style where top-level dependencies map direct deps.
    deps = lock_data.get("dependencies", {})
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if isinstance(meta, dict) and meta.get("version"):
                found.add((str(name), str(meta["version"])))

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


def fetch_npm_metadata(
    pkg_name: str,
    cache: Dict[str, Dict[str, Any]],
    use_cache: bool,
    http_timeout_seconds: int,
) -> Dict[str, Any]:
    if use_cache and pkg_name in cache:
        return cache[pkg_name]

    encoded_name = urllib.parse.quote(pkg_name, safe="")
    url = f"https://registry.npmjs.org/{encoded_name}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "guardrail-agent/1.0"},
    )
    with urllib.request.urlopen(req, timeout=http_timeout_seconds) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        if use_cache:
            cache[pkg_name] = payload
        return payload


def get_publish_time(
    pkg_name: str,
    version: str,
    cache: Dict[str, Dict[str, Any]],
    use_cache: bool,
    http_timeout_seconds: int,
) -> str:
    meta = fetch_npm_metadata(pkg_name, cache, use_cache, http_timeout_seconds)
    times = meta.get("time", {})
    published = times.get(version)
    if not published:
        raise ValueError(f"publish time not found for {pkg_name}@{version}")
    return published


def compute_age_hours(published_at: str) -> float:
    dt = parse_iso8601(published_at)
    delta = now_utc() - dt
    return delta.total_seconds() / 3600.0


def is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_cache(cache_file: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(cache_file):
        return {}

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass

    return {}


def save_cache(cache_file: str, cache: Dict[str, Dict[str, Any]]) -> None:
    parent = os.path.dirname(cache_file)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def main() -> int:
    policy = load_json(POLICY_FILE)
    lockfile = find_lockfile()
    lock_data = load_json(lockfile)
    packages = extract_packages_from_lock(lock_data)

    denylist: Dict[str, List[str]] = policy.get("denylist", {})
    allowlist: List[str] = policy.get("allowlist", [])
    min_age = int(policy.get("min_package_age_hours", 48))
    strict_mode = bool(policy.get("strict_mode", True))
    denylist_only_mode = is_truthy(os.environ.get("GUARDRAIL_DENYLIST_ONLY", ""))
    use_cache = not is_truthy(os.environ.get("GUARDRAIL_DISABLE_CACHE", ""))
    cache_file = os.environ.get("GUARDRAIL_CACHE_FILE", ".guardrail-npm-metadata-cache.json")
    http_timeout_seconds = int(os.environ.get("GUARDRAIL_HTTP_TIMEOUT_SECONDS", "10"))
    age_scope = os.environ.get("GUARDRAIL_AGE_SCOPE", "all").strip().lower() or "all"
    if age_scope not in {"all", "direct"}:
        age_scope = "all"
    cache: Dict[str, Dict[str, Any]] = load_cache(cache_file) if use_cache else {}
    direct_packages = extract_direct_packages_from_lock(lock_data)
    age_packages: Set[Tuple[str, str]]
    if age_scope == "direct" and direct_packages:
        age_packages = set(direct_packages)
    else:
        age_packages = set(packages)

    blocked = []
    quarantined = []
    allowed = []
    errors = []
    age_checked_count = 0

    for name, version in packages:
        if is_allowlisted(name, allowlist):
            allowed.append({"name": name, "version": version, "reason": "allowlisted"})
            continue

        if name in denylist and version in denylist[name]:
            blocked.append({"name": name, "version": version, "reason": "denylisted_version"})
            continue

        if denylist_only_mode:
            allowed.append(
                {
                    "name": name,
                    "version": version,
                    "reason": "denylist_only_mode",
                }
            )
            continue

        if (name, version) not in age_packages:
            allowed.append(
                {
                    "name": name,
                    "version": version,
                    "reason": "age_scope_excluded",
                }
            )
            continue

        try:
            age_checked_count += 1
            published_at = get_publish_time(name, version, cache, use_cache, http_timeout_seconds)
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
        "mode": "denylist_only" if denylist_only_mode else "full",
        "age_scope": age_scope,
        "lockfile": lockfile,
        "policy_file": POLICY_FILE,
        "cache_file": cache_file if use_cache else "",
        "summary": {
            "total_packages": len(packages),
            "age_checked_count": age_checked_count,
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

    if use_cache:
        save_cache(cache_file, cache)

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
