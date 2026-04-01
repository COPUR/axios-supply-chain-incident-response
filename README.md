# Axios Supply Chain Incident Response Kit

Zero-trust response toolkit for the axios supply chain incident involving:
- `axios@1.14.1`
- `axios@0.30.4`
- malicious dependency `plain-crypto-js@4.2.1`

This repository provides:
- Full detection scan with **action-oriented report output**
- Impact analysis (repos, CI/CD, potential secret exposure)
- Strict remediation runbook (assume compromise when uncertain)
- Preventive guardrails for CI/CD and runtime operations

## Quick Start

```bash
python3 scripts/incident_scan.py --roots /path/to/repos --output report.md --json-out report.json
```

Output hygiene:
- Report output is anonymized/redacted by default (paths and usernames).
- To disable redaction for internal-only debugging, use `--no-anonymize-output`.

The scanner prints a report in this format:
- SECTION 1: Detection Result
- SECTION 2: Risk Level
- SECTION 3: Immediate Actions
- SECTION 4: Remediation Plan
- SECTION 5: Preventive Measures

The JSON output also includes:
- `affected_basis` (`direct_compromise_detected`, `assumed_compromise_due_to_uncertainty`, `no_compromise_indicators`)
- `direct_compromise_evidence`
- `uncertainty_evidence`

## Repository Layout

```text
.
├── scripts/
│   ├── incident_scan.py
│   ├── guardrail.py
│   ├── run_guardrail_matrix.py
│   └── publish_guardrail_event.py
├── agent/
│   └── security_agent.py
├── policies/
│   └── guardrail-policy.json
├── docs/
│   ├── approach.md
│   └── remediation-runbook.md
├── k8s/
│   └── security-agent-deployment.yaml
└── .github/workflows/
    ├── dependency-guardrail.yml
    ├── guardrail-matrix.yml
    └── python-tests.yml
```

## Detection Scope

The detector checks:
- Whether `axios` is installed and which versions are present
- Whether any project uses `axios@1.14.1` or `axios@0.30.4`
- Whether `node_modules/plain-crypto-js` exists
- System-level indicators:
  - Linux: `/tmp/ld.py`
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\\wt.exe`

## CI Guardrail

```bash
python3 scripts/guardrail.py
```

Behavior:
- Denylisted package/version -> **block** (non-zero exit)
- Very new package (< policy threshold) -> **quarantine**
- Otherwise -> **allow**

## Multi-Repo Lockfile Guardrail

Run per-lockfile guardrail checks in one command:

```bash
python3 scripts/run_guardrail_matrix.py \
  --roots /path/to/repos \
  --output-dir guardrail-matrix-output \
  --policy-file policies/guardrail-policy.json \
  --denylist-only
```

For full mode with cache and age checks:

```bash
python3 scripts/run_guardrail_matrix.py \
  --roots /path/to/repos \
  --output-dir guardrail-matrix-output \
  --policy-file policies/guardrail-policy.json \
  --cache-file /tmp/guardrail-npm-metadata-cache.json \
  --age-scope direct
```

Artifacts:
- `summary.csv`
- `summary.json`
- `results/*.json` (one per lockfile)

Artifact hygiene:
- Matrix output is anonymized/redacted by default.
- Result filenames are path-safe hashes (no host path leakage).
- To disable redaction for internal-only debugging, use `--no-anonymize-output`.

Performance note:
- `full` mode can be expensive on large lockfiles if age policy is evaluated for every transitive package.
- Use `--age-scope direct` for practical CI execution while keeping denylist checks on all resolved packages.

## Tests

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

## Security Principles

- Dependency installation is code execution.
- Prefer false positive over false negative.
- Assume compromise if uncertainty exists.
- Do not rely on `node_modules` inspection alone.

## Disclaimer

This kit is incident-response automation support, not a substitute for professional forensic investigation.
