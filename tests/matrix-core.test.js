import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

import {
  discoverLockfiles,
  readLockfilesFile,
  runGuardrailMatrix,
} from '../src/lib/matrix-core.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'matrix-core-'));
}

async function writeJson(filePath, value) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

describe('matrix core', () => {
  it('discovers lockfiles and applies excludes', async () => {
    const root = mkTmpDir();
    const projectA = path.join(root, 'a');
    const projectB = path.join(root, 'b');

    await writeJson(path.join(projectA, 'package-lock.json'), {});
    await writeJson(path.join(projectB, 'npm-shrinkwrap.json'), {});

    const all = await discoverLockfiles([root]);
    expect(all.length).toBe(2);

    const filtered = await discoverLockfiles([root], ['/b/']);
    expect(filtered.length).toBe(1);
    expect(filtered[0]).toContain('/a/');
  });

  it('reads lockfiles from explicit list file', async () => {
    const root = mkTmpDir();
    const lockfile = path.join(root, 'package-lock.json');
    await writeJson(lockfile, {});

    const listFile = path.join(root, 'lockfiles.txt');
    await fsp.writeFile(listFile, `${lockfile}\n`, 'utf8');

    const results = await readLockfilesFile(listFile);
    expect(results).toEqual([lockfile]);
  });

  it('returns success when no lockfiles are found', async () => {
    const outputDir = mkTmpDir();

    const result = await runGuardrailMatrix({
      roots: [path.join(outputDir, 'empty')],
      outputDir,
      cwd: repoRoot,
      logger: () => {},
    });

    expect(result.exitCode).toBe(0);
    expect(result.lockfileCount).toBe(0);
  });

  it('runs guardrail for each lockfile and blocks denylisted versions', async () => {
    const workspace = mkTmpDir();
    const project = path.join(workspace, 'project');
    const outputDir = path.join(workspace, 'out');
    const policyPath = path.join(workspace, 'policy.json');
    const cachePath = path.join(workspace, 'cache.json');

    await writeJson(path.join(project, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '1.14.1' } },
        'node_modules/axios': { version: '1.14.1' },
      },
    });

    await writeJson(policyPath, {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: {
        axios: ['1.14.1', '0.30.4'],
      },
      allowlist: [],
    });
    execFileSync('git', ['init'], { cwd: workspace, stdio: 'ignore' });

    const result = await runGuardrailMatrix({
      roots: [workspace],
      outputDir,
      policyFile: policyPath,
      guardrailScript: path.join(repoRoot, 'scripts/guardrail.js'),
      cacheFile: cachePath,
      denylistOnly: true,
      exitOn: 'block-only',
      cwd: repoRoot,
      logger: () => {},
    });

    expect(result.exitCode).toBe(1);
    expect(result.lockfileCount).toBe(1);
    expect(result.statusCounts.block).toBe(1);
    expect(fs.existsSync(result.summaryCsv)).toBe(true);
    expect(fs.existsSync(result.summaryJson)).toBe(true);
    expect(result.rows[0].status).toBe('block');
    expect(String(result.rows[0].lockfile)).toContain('<REPO_');
  });
});
