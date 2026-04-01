# Changelog

All notable changes to this project will be documented in this file.

## v2.0.1 - 2026-04-01

### Security
- Upgraded `vitest` from `2.1.8` to `2.1.9`.
- Upgraded `@vitest/coverage-v8` from `2.1.8` to `2.1.9`.
- Removed previously reported critical advisories affecting the earlier test stack.

### Triage
- `npm audit` now reports `0 critical`, `0 high`, and `6 moderate` vulnerabilities.
- Remaining advisories are limited to the Vitest/Vite test toolchain in development dependencies and do not affect production runtime paths.
- Follow-up major migration to Vitest v4 is tracked for full moderate-vulnerability closure.

## v2.0.0 - 2026-04-01

### Added
- Full Node.js rewrite for incident scanning, guardrail enforcement, matrix execution, and security event processing.
- New modular core libraries under `src/lib` for scan logic, guardrail logic, anonymization, and event handling.
- Node-based CLI entrypoints for scan/guardrail/matrix/event publishing and security agent runtime.
- Vitest TDD suite with strict global coverage gates.
- Node CI workflow (`node-tests.yml`) and hardened install mode (`npm ci --ignore-scripts`).

### Changed
- GitHub Actions guardrail workflows migrated from Python to Node.js.
- Container runtime migrated from Python base image to Node 20.
- README and operational commands updated for Node-first execution.

### Removed
- Legacy Python scripts, Python tests, and Python dependency/runtime files.
