# Axios Supply Chain Incident Response Kit

Zero-trust response toolkit for the axios supply chain incident involving:
- `axios@1.14.1`
- `axios@0.30.4`
- malicious dependency `plain-crypto-js@4.2.1`

This repository provides:
- Full detection scan with action-oriented report output
- Impact analysis (repos, CI/CD, potential secret exposure)
- Strict remediation runbook (assume compromise when uncertain)
- Preventive guardrails for CI/CD and runtime operations
- Node.js-first tooling with TDD and coverage gates

## Quick Start

```bash
npm ci --ignore-scripts
npm run scan -- --roots /path/to/repos --output report.md --json-out report.json
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
├── src/lib/
│   ├── anonymize.js
│   ├── guardrail-core.js
│   ├── incident-scan-core.js
│   ├── lockfile-utils.js
│   ├── matrix-core.js
│   └── security-events.js
├── scripts/
│   ├── incident-scan.js
│   ├── guardrail.js
│   ├── run-guardrail-matrix.js
│   └── publish-guardrail-event.js
├── agent/
│   └── security-agent.js
├── policies/
│   └── guardrail-policy.json
├── docs/
│   ├── approach.md
│   └── remediation-runbook.md
├── k8s/
│   └── security-agent-deployment.yaml
├── tests/
│   └── *.test.js
└── .github/workflows/
    ├── dependency-guardrail.yml
    ├── guardrail-matrix.yml
    └── node-tests.yml
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
npm run guardrail
```

Behavior:
- Denylisted package/version -> block (non-zero exit)
- Very new package (< policy threshold) -> quarantine
- Otherwise -> allow

## Multi-Repo Lockfile Guardrail

Run per-lockfile guardrail checks in one command:

```bash
npm run guardrail:matrix -- \
  --roots /path/to/repos \
  --output-dir guardrail-matrix-output \
  --policy-file policies/guardrail-policy.json \
  --denylist-only \
  --max-workers 4
```

For full mode with cache and age checks:

```bash
npm run guardrail:matrix -- \
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
- Use `--max-workers` to parallelize lockfile checks and reduce wall-clock runtime for large mono-repo fleets.

## Security Event Pipeline

Publish guardrail events:

```bash
npm run publish:guardrail-event
```

Run incident agent:

```bash
npm run agent:start
```

## Tests (TDD)

```bash
npm test
```

Coverage gates are enforced at `95%+` globally for statements, lines, and branches.

## Observability, Self-Heal, Self-Improve

Enable structured runtime telemetry and optional self-heal:

```bash
OBSERVABILITY_EVENTS_FILE=.observability/events.ndjson \
OBSERVABILITY_FORMAT=json \
OBSERVABILITY_LEVEL=info \
OBSERVABILITY_SELF_HEAL=1 \
npm run guardrail:matrix -- --roots /path/to/repos --denylist-only --max-workers 4
```

Generate improvement recommendations from captured runtime events:

```bash
npm run observability:insights -- --events-file .observability/events.ndjson --output observability-insights.md
```

## Security Principles

- Dependency installation is code execution.
- Prefer false positive over false negative.
- Assume compromise if uncertainty exists.
- Do not rely on `node_modules` inspection alone.

## Disclaimer

This kit is incident-response automation support, not a substitute for professional forensic investigation.
