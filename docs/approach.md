# Approach

## Zero-Trust Assumptions

- Treat every dependency install as untrusted code execution.
- Treat missing evidence as incomplete visibility, not safety.
- Escalate to compromised state when confidence is reduced by uncertainty.

## Workflow

1. Detection
- Parse lockfiles and manifests across target repositories.
- Check known malicious axios versions and `plain-crypto-js` indicators.
- Validate host-level indicators for Linux/macOS/Windows IOC paths.

2. Impact Analysis
- Map impacted repositories.
- Identify CI/CD definitions invoking `npm ci`/`npm install`.
- Hunt probable credential exposures and secret files.
- Assess lateral movement and production blast radius.

3. Immediate Response
- Isolate hosts and runners.
- Halt deployment/promotion pipelines.
- Rotate all credentials and revoke all tokens.
- Preserve forensic artifacts and logs.

4. Recovery
- Full system rebuild from trusted immutable images.
- Re-establish trust chain from source to runtime.

5. Hardening
- Exact version pinning and lockfile enforcement.
- `npm ci --ignore-scripts` where feasible.
- Dependency allowlist, package age gates, SBOM + policy enforcement.
- Ephemeral CI runners, network egress controls, secret isolation.
