# Strict Remediation Runbook

Use this runbook when the scan status is **Affected** or uncertainty remains.

1. Declare incident severity as High/Critical and trigger incident response.
2. Freeze deployments and disable promotion to production immediately.
3. Isolate all CI runners, developer workstations, and build hosts that executed `npm install` or `npm ci` during exposure window.
4. Revoke and rotate all credentials:
- Cloud access keys
- CI/CD service tokens
- npm tokens
- SSH keys
- API keys in `.env` and secret stores
5. Capture forensic artifacts before wiping:
- CI logs
- Host process/network telemetry
- Lockfiles/manifests at impacted commits
6. Rebuild affected systems from known-clean immutable images (no in-place cleaning).
7. Rehydrate secrets via secure secret manager with short-lived credentials.
8. Re-run full detection scan and validate no indicators remain.
9. Audit for lateral movement:
- Registry access logs
- IAM role assumptions
- SSH usage
- Unexpected network egress
10. Restore deployment flow only after security sign-off and evidence closure.
