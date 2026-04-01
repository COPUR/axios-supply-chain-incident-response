#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict, replace
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

MALICIOUS_AXIOS_VERSIONS = {"1.14.1", "0.30.4"}
MALICIOUS_DEPENDENCIES = {"plain-crypto-js": {"4.2.1"}}

SYSTEM_IOCS = [
    ("linux", Path("/tmp/ld.py")),
    ("darwin", Path("/Library/Caches/com.apple.act.mond")),
]

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(
        r"(?i)aws[^\n]{0,20}(secret|access)[^\n]{0,10}[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"
    ),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) PRIVATE KEY-----"),
}

CI_FILE_CANDIDATES = {
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "circle.yml",
    "buildspec.yml",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".next",
    ".turbo",
    ".venv",
    "venv",
    "coverage",
    ".idea",
    ".gradle",
}

TEXT_FILE_EXTENSIONS = {
    ".env",
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".tsx",
    ".sh",
    ".properties",
    ".tf",
    ".ini",
    ".conf",
    ".cfg",
    ".dockerfile",
}


@dataclass
class ProjectFinding:
    root: str
    axios_versions_in_lock: List[str] = field(default_factory=list)
    axios_declared_versions: List[str] = field(default_factory=list)
    malicious_axios_versions: List[str] = field(default_factory=list)
    malicious_dependency_hits: List[str] = field(default_factory=list)
    plain_crypto_node_modules_present: bool = False
    uncertainty_flags: List[str] = field(default_factory=list)
    lockfile_paths: List[str] = field(default_factory=list)

    def is_impacted(self) -> bool:
        return bool(
            self.malicious_axios_versions
            or self.malicious_dependency_hits
            or self.plain_crypto_node_modules_present
            or self.uncertainty_flags
        )


@dataclass
class ScanResult:
    affected: bool
    affected_basis: str
    confidence: str
    evidence: List[str]
    direct_compromise_evidence: List[str]
    uncertainty_evidence: List[str]
    risk_level: str
    impacted_projects: List[ProjectFinding]
    direct_impacted_projects: List[ProjectFinding]
    uncertainty_impacted_projects: List[ProjectFinding]
    ci_pipelines_with_npm_install: List[str]
    probable_secret_exposures: List[str]
    lateral_movement_paths: List[str]
    production_exposure_risk: str
    immediate_actions: List[str]
    remediation_plan: List[str]
    preventive_measures: List[str]


def safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def safe_load_json(path: Path) -> Optional[dict]:
    text = safe_read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def walk_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        current = Path(dirpath)
        for name in filenames:
            yield current / name


def discover_projects(roots: List[Path]) -> List[Path]:
    found: Set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        if root.is_file() and root.name == "package.json":
            found.add(root.parent)
            continue
        for path in walk_files(root):
            if path.name == "package.json":
                found.add(path.parent)
    return sorted(found)


def extract_from_package_json(path: Path) -> List[str]:
    data = safe_load_json(path)
    if not data:
        return []

    versions: List[str] = []
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        deps = data.get(section, {})
        if isinstance(deps, dict) and "axios" in deps:
            versions.append(str(deps["axios"]))
    return sorted(set(versions))


def normalize_pkg_name_from_lock_path(lock_path: str) -> str:
    marker = "node_modules/"
    if marker in lock_path:
        return lock_path.split(marker)[-1]
    return lock_path


def extract_packages_from_lock(lock_data: dict) -> Set[Tuple[str, str]]:
    packages: Set[Tuple[str, str]] = set()

    lock_packages = lock_data.get("packages")
    if isinstance(lock_packages, dict):
        for path, meta in lock_packages.items():
            if path == "":
                continue
            if not isinstance(meta, dict):
                continue
            name = meta.get("name") or normalize_pkg_name_from_lock_path(path)
            version = meta.get("version")
            if name and version:
                packages.add((str(name), str(version)))

    def walk_deps(deps: dict):
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                packages.add((str(name), str(version)))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk_deps(nested)

    top_deps = lock_data.get("dependencies")
    if isinstance(top_deps, dict):
        walk_deps(top_deps)

    return packages


def parse_lockfiles(project_root: Path) -> Tuple[Set[Tuple[str, str]], List[str], List[str]]:
    lockfiles = [
        project_root / "package-lock.json",
        project_root / "npm-shrinkwrap.json",
    ]
    packages: Set[Tuple[str, str]] = set()
    parsed_lockfiles: List[str] = []
    errors: List[str] = []

    for lockfile in lockfiles:
        if not lockfile.exists():
            continue
        data = safe_load_json(lockfile)
        if data is None:
            errors.append(f"could_not_parse:{lockfile}")
            continue
        parsed_lockfiles.append(str(lockfile))
        packages |= extract_packages_from_lock(data)

    return packages, parsed_lockfiles, errors


def is_exact_semver(version: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", version))


def detect_system_iocs() -> List[str]:
    evidence = []
    for os_name, path in SYSTEM_IOCS:
        if path.exists():
            evidence.append(f"ioc_file_present:{os_name}:{path}")

    program_data = os.environ.get("PROGRAMDATA", r"C:\\ProgramData")
    windows_ioc = Path(program_data) / "wt.exe"
    if windows_ioc.exists():
        evidence.append(f"ioc_file_present:windows:{windows_ioc}")

    return evidence


def find_ci_pipelines_with_npm(roots: List[Path]) -> List[str]:
    hits: List[str] = []
    pattern = re.compile(r"\bnpm\s+(ci|install)\b")

    for root in roots:
        for path in walk_files(root):
            name = path.name
            in_github_workflow = ".github/workflows" in str(path)
            ci_candidate = name in CI_FILE_CANDIDATES or (in_github_workflow and name.endswith((".yml", ".yaml")))
            if not ci_candidate:
                continue

            content = safe_read_text(path)
            if content and pattern.search(content):
                hits.append(str(path))

    return sorted(set(hits))


def looks_textual(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name.startswith(".env"):
        return True
    if path.suffix.lower() in TEXT_FILE_EXTENSIONS:
        return True
    return path.name in {"Dockerfile", "dockerfile", "Jenkinsfile"}


def hunt_probable_secrets(roots: List[Path], max_hits: int = 100) -> List[str]:
    hits: List[str] = []

    for root in roots:
        for path in walk_files(root):
            if not looks_textual(path):
                continue

            content = safe_read_text(path)
            if content is None:
                continue

            if path.name.startswith(".env"):
                hits.append(f"env_file_present:{path}")

            for label, regex in SECRET_PATTERNS.items():
                if regex.search(content):
                    hits.append(f"{label}:{path}")

            if len(hits) >= max_hits:
                return sorted(set(hits))[:max_hits]

    return sorted(set(hits))


def infer_lateral_paths(
    impacted_projects: List[ProjectFinding], ci_hits: List[str], secret_hits: List[str]
) -> List[str]:
    paths: List[str] = []

    if impacted_projects:
        paths.append(
            "Compromised dependency execution during install can execute arbitrary code in developer/CI context."
        )

    if ci_hits:
        paths.append(
            "CI pipelines invoking npm install/npm ci may expose runner identity, repository tokens, and artifact credentials."
        )

    if secret_hits:
        paths.append(
            "Probable secret exposure increases risk of cloud account takeover, source control abuse, and registry poisoning."
        )

    if impacted_projects and ci_hits:
        paths.append(
            "Potential movement path: compromised package -> CI runner -> secret exfiltration -> container registry/IaC/prod deployment chain."
        )

    return paths


def infer_production_exposure(
    direct_impacted_projects: List[ProjectFinding],
    uncertainty_impacted_projects: List[ProjectFinding],
    ci_hits: List[str],
    secret_hits: List[str],
) -> str:
    if direct_impacted_projects and ci_hits and secret_hits:
        return "Critical"
    if direct_impacted_projects and ci_hits:
        return "High"
    if direct_impacted_projects:
        return "Medium"
    if uncertainty_impacted_projects and ci_hits and secret_hits:
        return "High"
    if uncertainty_impacted_projects:
        return "Medium"
    return "Low"


def compute_risk_level(
    direct_iocs: List[str],
    direct_impacted_projects: List[ProjectFinding],
    uncertainty_impacted_projects: List[ProjectFinding],
    ci_hits: List[str],
    secret_hits: List[str],
) -> str:
    malicious_hit = bool(direct_impacted_projects)
    uncertainty_hit = bool(uncertainty_impacted_projects)
    incident_signal = bool(direct_iocs or malicious_hit or uncertainty_hit)

    if not incident_signal:
        # Keep incident risk separate from baseline secret hygiene findings.
        return "Low"

    if direct_iocs or (malicious_hit and ci_hits):
        return "Critical"
    if malicious_hit:
        return "High"
    if uncertainty_hit and ci_hits and secret_hits:
        return "High"
    if uncertainty_hit or secret_hits:
        return "Medium"
    return "Low"


def compute_confidence(
    affected: bool, direct_iocs: List[str], impacted_projects: List[ProjectFinding], scan_errors: List[str]
) -> str:
    direct_project_ioc = any(
        p.malicious_axios_versions or p.malicious_dependency_hits or p.plain_crypto_node_modules_present
        for p in impacted_projects
    )
    uncertainty_only = affected and not (direct_iocs or direct_project_ioc)

    if scan_errors:
        return "Low"
    if direct_iocs or direct_project_ioc:
        return "High"
    if uncertainty_only:
        return "Medium"
    return "High"


def build_immediate_actions(affected: bool) -> List[str]:
    if not affected:
        return [
            "Keep monitoring; no direct indicators found in scanned scope.",
            "Run the scan across all remaining repositories and build environments to confirm global status.",
            "Apply preventive controls now (exact pinning, package age gating, SBOM policy checks).",
        ]

    return [
        "Freeze all deployments and disable release promotion immediately.",
        "Isolate all hosts and CI runners that executed npm install/npm ci during exposure window.",
        "Revoke and rotate all credentials: AWS keys, SSH keys, npm tokens, CI tokens, API secrets, .env secrets.",
        "Audit CI/CD logs for npm install/npm ci executions and map impacted commits, runners, and artifacts.",
        "Invalidate and re-issue artifact registry credentials; quarantine images/build artifacts from impacted pipelines.",
        "Open security incident and preserve forensic logs before rebuild actions.",
    ]


def build_remediation_plan(affected: bool) -> List[str]:
    if not affected:
        return [
            "Establish an immutable rebuild procedure and test it quarterly.",
            "Convert CI pipelines to deterministic installs with script restrictions.",
            "Treat this scan as baseline and run scheduled recurring scans.",
        ]

    return [
        "1) Declare incident severity High/Critical and assume compromise where visibility is incomplete.",
        "2) Stop all deployment and package-promotion pipelines that consumed Node dependencies in exposure window.",
        "3) Isolate compromised/suspected systems (dev workstations, CI runners, build agents).",
        "4) Capture forensic artifacts (runner logs, host telemetry, lockfiles, pipeline metadata) before wipe.",
        "5) Revoke all long-lived and short-lived credentials and tokens across cloud, SCM, CI, package registries.",
        "6) Rebuild systems from trusted immutable images; do not perform in-place cleaning.",
        "7) Recreate secrets from clean control plane and enforce least-privilege scopes.",
        "8) Re-run full scan and validate zero indicators before restoring deployment paths.",
        "9) Review lateral movement evidence and production access logs for unauthorized activity.",
        "10) Close incident only after security sign-off with documented evidence and timeline.",
    ]


def build_preventive_measures() -> List[str]:
    return [
        "Enforce exact dependency version pinning in package.json and lockfiles (no caret ^ or tilde ~).",
        "Use npm ci --ignore-scripts by default in CI; allow scripts only in explicitly approved jobs.",
        "Implement dependency allowlist and denylist policy with central governance.",
        "Block packages younger than 48 hours unless manually approved by security.",
        "Generate SBOM on every build and enforce policy checks before deploy.",
        "Use ephemeral CI runners with no persistent disk and strong network egress restrictions.",
        "Isolate secrets per pipeline/job; use short-lived credentials from a secret manager.",
        "Add artifact quarantine and promotion gates integrated with security findings.",
    ]


def build_root_aliases(roots: List[Path]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    normalized_roots = sorted({str(root.resolve()) for root in roots})
    for idx, root in enumerate(normalized_roots, start=1):
        aliases[root] = f"<SCAN_ROOT_{idx}>"
    return aliases


def sanitize_text(value: str, root_aliases: Dict[str, str]) -> str:
    redacted = value

    for root, alias in sorted(root_aliases.items(), key=lambda item: len(item[0]), reverse=True):
        redacted = redacted.replace(root, alias)

    home = str(Path.home())
    if home:
        redacted = redacted.replace(home, "$HOME")

    redacted = re.sub(r"/Users/[^/]+", "/Users/<redacted>", redacted)
    redacted = re.sub(r"/home/[^/]+", "/home/<redacted>", redacted)
    redacted = re.sub(r"([A-Za-z]:\\\\Users\\\\)[^\\\\]+", r"\1<redacted>", redacted)
    redacted = re.sub(r"([A-Za-z]:\\\\Documents and Settings\\\\)[^\\\\]+", r"\1<redacted>", redacted)

    return redacted


def anonymize_project_finding(project: ProjectFinding, root_aliases: Dict[str, str]) -> ProjectFinding:
    return replace(
        project,
        root=sanitize_text(project.root, root_aliases),
        lockfile_paths=[sanitize_text(path, root_aliases) for path in project.lockfile_paths],
        uncertainty_flags=[sanitize_text(flag, root_aliases) for flag in project.uncertainty_flags],
        malicious_dependency_hits=[
            sanitize_text(hit, root_aliases) for hit in project.malicious_dependency_hits
        ],
    )


def anonymize_scan_result(result: ScanResult, roots: List[Path]) -> ScanResult:
    root_aliases = build_root_aliases(roots)

    return replace(
        result,
        evidence=[sanitize_text(item, root_aliases) for item in result.evidence],
        direct_compromise_evidence=[
            sanitize_text(item, root_aliases) for item in result.direct_compromise_evidence
        ],
        uncertainty_evidence=[sanitize_text(item, root_aliases) for item in result.uncertainty_evidence],
        impacted_projects=[anonymize_project_finding(project, root_aliases) for project in result.impacted_projects],
        direct_impacted_projects=[
            anonymize_project_finding(project, root_aliases) for project in result.direct_impacted_projects
        ],
        uncertainty_impacted_projects=[
            anonymize_project_finding(project, root_aliases) for project in result.uncertainty_impacted_projects
        ],
        ci_pipelines_with_npm_install=[
            sanitize_text(path, root_aliases) for path in result.ci_pipelines_with_npm_install
        ],
        probable_secret_exposures=[
            sanitize_text(item, root_aliases) for item in result.probable_secret_exposures
        ],
        lateral_movement_paths=[sanitize_text(item, root_aliases) for item in result.lateral_movement_paths],
    )


def render_markdown(result: ScanResult) -> str:
    impacted_paths = [p.root for p in result.impacted_projects]
    direct_impacted_paths = [p.root for p in result.direct_impacted_projects]
    uncertainty_impacted_paths = [p.root for p in result.uncertainty_impacted_projects]

    evidence_lines = result.evidence[:] if result.evidence else ["No direct indicators found in scanned scope."]
    evidence_lines.insert(0, f"affected_basis:{result.affected_basis}")
    if impacted_paths:
        evidence_lines.append(f"Impacted repositories: {', '.join(impacted_paths)}")
    if direct_impacted_paths:
        evidence_lines.append(f"Directly compromised repositories: {', '.join(direct_impacted_paths)}")
    if uncertainty_impacted_paths:
        evidence_lines.append(
            f"Uncertainty-driven repositories (assumed compromised): {', '.join(uncertainty_impacted_paths)}"
        )
    if result.ci_pipelines_with_npm_install:
        evidence_lines.append(
            "CI/CD pipelines with npm install/npm ci: " + ", ".join(result.ci_pipelines_with_npm_install)
        )
    if result.probable_secret_exposures:
        evidence_lines.append(
            "Probable credential/secret findings: " + ", ".join(result.probable_secret_exposures[:15])
        )

    lines: List[str] = []
    lines.append("## SECTION 1: Detection Result")
    lines.append("")
    lines.append(f"- Status: {'Affected' if result.affected else 'Not affected'}")
    lines.append(f"- Evidence: Confidence={result.confidence}; Basis={result.affected_basis}")
    for item in evidence_lines:
        lines.append(f"  - {item}")

    lines.append("")
    lines.append("## SECTION 2: Risk Level")
    lines.append("")
    lines.append(f"- {result.risk_level}")

    lines.append("")
    lines.append("## SECTION 3: Immediate Actions")
    lines.append("")
    for item in result.immediate_actions:
        lines.append(f"- {item}")

    lines.append("")
    lines.append("## SECTION 4: Remediation Plan")
    lines.append("")
    for item in result.remediation_plan:
        lines.append(f"- {item}")

    lines.append("")
    lines.append("## SECTION 5: Preventive Measures")
    lines.append("")
    for item in result.preventive_measures:
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def scan_projects(projects: List[Path]) -> Tuple[List[ProjectFinding], List[str]]:
    findings: List[ProjectFinding] = []
    scan_errors: List[str] = []

    for project in projects:
        finding = ProjectFinding(root=str(project))

        package_json = project / "package.json"
        if package_json.exists():
            finding.axios_declared_versions = extract_from_package_json(package_json)

        packages, lockfiles, errors = parse_lockfiles(project)
        finding.lockfile_paths = lockfiles
        scan_errors.extend(errors)

        axios_versions = sorted({version for name, version in packages if name == "axios"})
        finding.axios_versions_in_lock = axios_versions
        finding.malicious_axios_versions = sorted(v for v in axios_versions if v in MALICIOUS_AXIOS_VERSIONS)

        for dep_name, bad_versions in MALICIOUS_DEPENDENCIES.items():
            dep_versions = sorted({version for name, version in packages if name == dep_name})
            for version in dep_versions:
                if version in bad_versions:
                    finding.malicious_dependency_hits.append(f"{dep_name}@{version}")

        plain_crypto_path = project / "node_modules" / "plain-crypto-js"
        finding.plain_crypto_node_modules_present = plain_crypto_path.exists()

        if finding.axios_declared_versions and not finding.axios_versions_in_lock:
            finding.uncertainty_flags.append("axios_declared_but_no_resolved_lockfile_version")

        for declared in finding.axios_declared_versions:
            if declared in MALICIOUS_AXIOS_VERSIONS:
                finding.malicious_axios_versions.append(declared)
            elif not is_exact_semver(declared):
                finding.uncertainty_flags.append(f"non_exact_axios_version_spec:{declared}")

        if errors:
            finding.uncertainty_flags.append("lockfile_parse_error")

        if (
            finding.axios_versions_in_lock
            or finding.axios_declared_versions
            or finding.malicious_dependency_hits
            or finding.plain_crypto_node_modules_present
            or finding.uncertainty_flags
        ):
            findings.append(finding)

    return findings, scan_errors


def run_scan(roots: List[Path]) -> ScanResult:
    projects = discover_projects(roots)
    project_findings, scan_errors = scan_projects(projects)

    direct_system_iocs = detect_system_iocs()

    impacted_projects = [p for p in project_findings if p.is_impacted()]
    direct_impacted_projects = [
        p
        for p in impacted_projects
        if p.malicious_axios_versions or p.malicious_dependency_hits or p.plain_crypto_node_modules_present
    ]
    uncertainty_impacted_projects = [
        p
        for p in impacted_projects
        if p.uncertainty_flags
        and not (p.malicious_axios_versions or p.malicious_dependency_hits or p.plain_crypto_node_modules_present)
    ]
    ci_hits = find_ci_pipelines_with_npm(roots)
    secret_hits = hunt_probable_secrets(roots)

    evidence: List[str] = []
    evidence.extend(direct_system_iocs)

    for project in project_findings:
        if project.axios_versions_in_lock:
            evidence.append(f"axios_versions:{project.root}:{','.join(project.axios_versions_in_lock)}")
        if project.malicious_axios_versions:
            evidence.append(f"malicious_axios:{project.root}:{','.join(sorted(set(project.malicious_axios_versions)))}")
        if project.malicious_dependency_hits:
            evidence.append(
                f"malicious_dependency:{project.root}:{','.join(sorted(set(project.malicious_dependency_hits)))}"
            )
        if project.plain_crypto_node_modules_present:
            evidence.append(f"plain_crypto_js_present:{project.root}")
        for flag in project.uncertainty_flags:
            evidence.append(f"uncertainty:{project.root}:{flag}")

    if scan_errors:
        evidence.extend(f"scan_error:{err}" for err in scan_errors)

    affected = bool(
        direct_system_iocs
        or direct_impacted_projects
        or uncertainty_impacted_projects
    )

    if direct_system_iocs or direct_impacted_projects:
        affected_basis = "direct_compromise_detected"
    elif uncertainty_impacted_projects:
        affected_basis = "assumed_compromise_due_to_uncertainty"
    else:
        affected_basis = "no_compromise_indicators"

    direct_compromise_evidence = sorted(
        {
            item
            for item in evidence
            if item.startswith("ioc_file_present:")
            or item.startswith("malicious_axios:")
            or item.startswith("malicious_dependency:")
            or item.startswith("plain_crypto_js_present:")
        }
    )
    uncertainty_evidence = sorted(
        {
            item
            for item in evidence
            if item.startswith("uncertainty:") or item.startswith("scan_error:")
        }
    )

    confidence = compute_confidence(affected, direct_system_iocs, project_findings, scan_errors)
    risk_level = compute_risk_level(
        direct_system_iocs,
        direct_impacted_projects,
        uncertainty_impacted_projects,
        ci_hits,
        secret_hits,
    )
    lateral_paths = infer_lateral_paths(impacted_projects, ci_hits, secret_hits)
    production_risk = infer_production_exposure(
        direct_impacted_projects,
        uncertainty_impacted_projects,
        ci_hits,
        secret_hits,
    )

    return ScanResult(
        affected=affected,
        affected_basis=affected_basis,
        confidence=confidence,
        evidence=sorted(set(evidence)),
        direct_compromise_evidence=direct_compromise_evidence,
        uncertainty_evidence=uncertainty_evidence,
        risk_level=risk_level,
        impacted_projects=impacted_projects,
        direct_impacted_projects=direct_impacted_projects,
        uncertainty_impacted_projects=uncertainty_impacted_projects,
        ci_pipelines_with_npm_install=ci_hits,
        probable_secret_exposures=secret_hits,
        lateral_movement_paths=lateral_paths,
        production_exposure_risk=production_risk,
        immediate_actions=build_immediate_actions(affected),
        remediation_plan=build_remediation_plan(affected),
        preventive_measures=build_preventive_measures(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero-trust incident scanner for malicious axios supply chain versions."
    )
    parser.add_argument(
        "--roots",
        nargs="+",
        default=[os.getcwd()],
        help="One or more root directories to scan.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional markdown report output path. If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional structured JSON output path.",
    )
    parser.add_argument(
        "--no-anonymize-output",
        action="store_true",
        help="Disable output anonymization/redaction (not recommended).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = [Path(root).resolve() for root in args.roots]

    result = run_scan(roots)
    if not args.no_anonymize_output:
        result = anonymize_scan_result(result, roots)
    markdown = render_markdown(result)

    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    else:
        print(markdown)

    if args.json_out:
        payload = asdict(result)
        payload["impacted_projects"] = [asdict(project) for project in result.impacted_projects]
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return 2 if result.affected else 0


if __name__ == "__main__":
    sys.exit(main())
