## SECTION 1: Detection Result

- Status: Affected
- Evidence: Confidence=High
  - malicious_axios:/repo-a:1.14.1
  - malicious_dependency:/repo-a:plain-crypto-js@4.2.1
  - ioc_file_present:linux:/tmp/ld.py

## SECTION 2: Risk Level

- Critical

## SECTION 3: Immediate Actions

- Freeze all deployments and disable release promotion immediately.
- Isolate all hosts and CI runners that executed npm install/npm ci during exposure window.
- Revoke and rotate all credentials: AWS keys, SSH keys, npm tokens, CI tokens, API secrets, .env secrets.

## SECTION 4: Remediation Plan

- 1) Declare incident severity High/Critical and assume compromise where visibility is incomplete.
- 2) Stop all deployment and package-promotion pipelines that consumed Node dependencies in exposure window.
- 3) Isolate compromised/suspected systems (dev workstations, CI runners, build agents).
- 4) Capture forensic artifacts (runner logs, host telemetry, lockfiles, pipeline metadata) before wipe.
- 5) Revoke all long-lived and short-lived credentials and tokens across cloud, SCM, CI, package registries.
- 6) Rebuild systems from trusted immutable images; do not perform in-place cleaning.

## SECTION 5: Preventive Measures

- Enforce exact dependency version pinning in package.json and lockfiles (no caret ^ or tilde ~).
- Use npm ci --ignore-scripts by default in CI; allow scripts only in explicitly approved jobs.
- Implement dependency allowlist and denylist policy with central governance.
