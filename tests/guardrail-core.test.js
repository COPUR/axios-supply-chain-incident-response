import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  computeAgeHours,
  isAllowlisted,
  isTruthy,
  parseIso8601,
  runGuardrail,
} from '../src/lib/guardrail-core.js';

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'guardrail-core-'));
}

async function writeJson(filePath, value) {
  await fsp.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

describe('guardrail core', () => {
  it('parses timestamps and computes age', () => {
    const parsed = parseIso8601('2026-04-01T00:00:00Z');
    expect(parsed.toISOString()).toBe('2026-04-01T00:00:00.000Z');

    const age = computeAgeHours('2026-04-01T00:00:00Z', () => new Date('2026-04-01T12:00:00Z'));
    expect(age).toBe(12);
  });

  it('evaluates truthy values and allowlist patterns', () => {
    expect(isTruthy('YES')).toBe(true);
    expect(isTruthy('0')).toBe(false);

    expect(isAllowlisted('@org/pkg', ['@org/*'])).toBe(true);
    expect(isAllowlisted('axios', ['lodash'])).toBe(false);
  });

  it('returns exit code 2 when no lockfile exists', async () => {
    const tmp = mkTmpDir();
    const policyFile = path.join(tmp, 'policy.json');
    const resultFile = path.join(tmp, 'result.json');

    await writeJson(policyFile, {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: {},
      allowlist: [],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: policyFile,
        GUARDRAIL_RESULT_FILE: resultFile,
      },
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(2);
    expect(output.result).toBeNull();
  });

  it('blocks denylisted version in denylist-only mode', async () => {
    const tmp = mkTmpDir();
    const lockfile = path.join(tmp, 'package-lock.json');
    const policyFile = path.join(tmp, 'policy.json');
    const resultFile = path.join(tmp, 'result.json');

    await writeJson(lockfile, {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '1.14.1', 'safe-lib': '1.0.0' } },
        'node_modules/axios': { version: '1.14.1' },
        'node_modules/safe-lib': { version: '1.0.0' },
      },
    });

    await writeJson(policyFile, {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: { axios: ['1.14.1', '0.30.4'] },
      allowlist: [],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: policyFile,
        GUARDRAIL_RESULT_FILE: resultFile,
        GUARDRAIL_DENYLIST_ONLY: '1',
      },
      fetchFn: async () => {
        throw new Error('network should not be called in denylist-only mode');
      },
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(1);
    expect(output.result.status).toBe('block');
    expect(output.result.mode).toBe('denylist_only');
    expect(output.result.summary.blocked_count).toBeGreaterThanOrEqual(1);
  });

  it('quarantines package younger than policy threshold', async () => {
    const tmp = mkTmpDir();
    const lockfile = path.join(tmp, 'package-lock.json');
    const policyFile = path.join(tmp, 'policy.json');
    const resultFile = path.join(tmp, 'result.json');

    await writeJson(lockfile, {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'safe-lib': '1.0.0' } },
        'node_modules/safe-lib': { version: '1.0.0' },
      },
    });

    await writeJson(policyFile, {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: {},
      allowlist: [],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: policyFile,
        GUARDRAIL_RESULT_FILE: resultFile,
      },
      fetchFn: async () => ({
        ok: true,
        json: async () => ({
          time: { '1.0.0': '2026-04-01T11:30:00Z' },
        }),
      }),
      nowFn: () => new Date('2026-04-01T12:00:00Z'),
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(3);
    expect(output.result.status).toBe('quarantine');
    expect(output.result.summary.quarantined_count).toBe(1);
  });

  it('allows package when metadata unavailable in non-strict mode', async () => {
    const tmp = mkTmpDir();
    const lockfile = path.join(tmp, 'package-lock.json');
    const policyFile = path.join(tmp, 'policy.json');
    const resultFile = path.join(tmp, 'result.json');

    await writeJson(lockfile, {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'safe-lib': '1.0.0' } },
        'node_modules/safe-lib': { version: '1.0.0' },
      },
    });

    await writeJson(policyFile, {
      min_package_age_hours: 48,
      strict_mode: false,
      denylist: {},
      allowlist: [],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: policyFile,
        GUARDRAIL_RESULT_FILE: resultFile,
      },
      fetchFn: async () => {
        throw new Error('registry unavailable');
      },
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(0);
    expect(output.result.status).toBe('allow');
    expect(output.result.summary.errors_count).toBe(1);
    expect(output.result.allowed[0].reason).toBe('metadata_unavailable_non_strict_mode');
  });

  it('checks age only for direct dependencies in direct mode', async () => {
    const tmp = mkTmpDir();
    const lockfile = path.join(tmp, 'package-lock.json');
    const policyFile = path.join(tmp, 'policy.json');
    const resultFile = path.join(tmp, 'result.json');

    await writeJson(lockfile, {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'safe-lib': '1.0.0' } },
        'node_modules/safe-lib': { version: '1.0.0' },
        'node_modules/transitive-lib': { version: '2.0.0' },
      },
    });

    await writeJson(policyFile, {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: {},
      allowlist: [],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: policyFile,
        GUARDRAIL_RESULT_FILE: resultFile,
        GUARDRAIL_AGE_SCOPE: 'direct',
      },
      fetchFn: async (_url) => ({
        ok: true,
        json: async () => ({
          time: {
            '1.0.0': '2025-01-01T00:00:00Z',
            '2.0.0': '2025-01-01T00:00:00Z',
          },
        }),
      }),
      nowFn: () => new Date('2026-04-01T12:00:00Z'),
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(0);
    expect(output.result.status).toBe('allow');
    expect(output.result.summary.age_checked_count).toBe(1);
    expect(output.result.allowed.some((item) => item.reason === 'age_scope_excluded')).toBe(true);
  });
});
