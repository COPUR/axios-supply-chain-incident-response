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

The scanner prints a report in this format:
- SECTION 1: Detection Result
- SECTION 2: Risk Level
- SECTION 3: Immediate Actions
- SECTION 4: Remediation Plan
- SECTION 5: Preventive Measures

## Repository Layout

```text
.
├── scripts/
│   ├── incident_scan.py
│   ├── guardrail.py
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
    └── dependency-guardrail.yml
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

## Security Principles

- Dependency installation is code execution.
- Prefer false positive over false negative.
- Assume compromise if uncertainty exists.
- Do not rely on `node_modules` inspection alone.

## Disclaimer

This kit is incident-response automation support, not a substitute for professional forensic investigation.
