# npm Audit Triage (2026-04-01)

## Scope
- Repository: `COPUR/axios-supply-chain-incident-response`
- Branch: `codex/npm-audit-remediation-v2.0.1`
- Command: `npm audit --json`

## Actions Taken
1. Upgraded `vitest` from `2.1.8` to `2.1.9`.
2. Upgraded `@vitest/coverage-v8` from `2.1.8` to `2.1.9`.
3. Re-ran `npm audit --json` and `npm test` (coverage gate still passing).

## Results
- Current audit counts:
  - Critical: `0`
  - High: `0`
  - Moderate: `6`
  - Low: `0`
- Coverage/test gate:
  - Tests: `43/43` passed
  - Global coverage: statements `98.4%`, branches `95.35%`, functions `96.49%`, lines `98.4%`

## Remaining Risk (Moderate)
Remaining vulnerabilities are in dev-only test toolchain packages:
- `vitest`
- `@vitest/coverage-v8`
- `vite`
- `vite-node`
- `@vitest/mocker`
- `esbuild`

These are not part of production runtime artifacts for this repository. They can still impact local/CI developer environments if test tooling is executed in unsafe contexts.

## Compensating Controls
- Continue running CI with `npm ci --ignore-scripts`.
- Use ephemeral runners with network egress restrictions.
- Do not expose Vitest API server in shared/untrusted networks.
- Keep test execution isolated from production credentials.

## Follow-Up Plan
- Perform semver-major migration to `vitest@4.x` and `@vitest/coverage-v8@4.x` in a dedicated compatibility branch.
- Re-baseline test coverage instrumentation under Vitest v4.
- Close remaining moderate advisories after compatibility validation.
