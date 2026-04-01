import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  buildRootAliases,
  anonymizePath,
  sanitizeText,
} from '../src/lib/anonymize.js';
import {
  buildGuardrailConfig,
  computeAgeHours,
  fetchNpmMetadata,
  getPublishTime,
  isAllowlisted,
  loadCache,
  parseIso8601,
  runGuardrail,
} from '../src/lib/guardrail-core.js';
import {
  buildImmediateActions,
  buildPreventiveMeasures,
  buildRemediationPlan,
  computeConfidence,
  computeRiskLevel,
  detectSystemIocs,
  discoverProjects,
  extractAxiosFromPackageJson,
  findCiPipelinesWithNpm,
  huntProbableSecrets,
  inferLateralPaths,
  inferProductionExposure,
  looksTextual,
  parseLockfiles,
  projectIsImpacted,
  renderMarkdown,
  runScan,
  safeLoadJson,
  safeReadText,
  scanProjects,
  walkFiles,
} from '../src/lib/incident-scan-core.js';
import {
  discoverLockfiles,
  gitTopLevel,
  readLockfilesFile,
  runGuardrailMatrix,
} from '../src/lib/matrix-core.js';
import { buildGuardrailEventPayload, createIncident } from '../src/lib/security-events.js';
import { isExactSemver, normalizePkgNameFromLockPath } from '../src/lib/lockfile-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

function mkTmpDir(prefix = 'coverage-extra-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function writeJson(filePath, value) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

describe('additional branch coverage', () => {
  it('covers anonymize fallback and root alias generation edge cases', () => {
    const aliases = buildRootAliases([]);
    expect(aliases.size).toBe(0);
    expect(buildRootAliases(null).size).toBe(0);
    expect(anonymizePath('', '/tmp/repo', '<R>')).toBe('');

    const sanitized = sanitizeText('C:\\Users\\alice\\secret');
    expect(sanitized).toContain('<redacted>');
  });

  it('covers semver and lockfile normalization fallback branches', () => {
    expect(normalizePkgNameFromLockPath('node_modules/')).toBe('node_modules/');
    expect(isExactSemver()).toBe(false);
  });

  it('covers guardrail config normalization and metadata helpers', async () => {
    const cfg = buildGuardrailConfig({
      cwd: '/tmp',
      env: {
        GUARDRAIL_AGE_SCOPE: 'invalid',
        GUARDRAIL_DISABLE_CACHE: 'true',
      },
    });
    expect(cfg.ageScope).toBe('all');
    expect(cfg.useCache).toBe(false);

    const loadedInvalid = await loadCache('/tmp/non-existent-cache.json');
    expect(loadedInvalid).toEqual({});

    const cache = { axios: { time: { '1.14.1': '2026-04-01T00:00:00Z' } } };
    const cached = await fetchNpmMetadata('axios', {
      cache,
      useCache: true,
      httpTimeoutSeconds: 1,
      fetchFn: async () => {
        throw new Error('should not run fetch');
      },
    });
    expect(cached.time['1.14.1']).toBe('2026-04-01T00:00:00Z');

    await expect(getPublishTime('axios', '9.9.9', {
      cache: {},
      useCache: false,
      httpTimeoutSeconds: 1,
      fetchFn: async () => ({ ok: true, json: async () => ({ time: {} }) }),
    })).rejects.toThrow('publish time not found');

    await expect(fetchNpmMetadata('axios', {
      cache: {},
      useCache: false,
      httpTimeoutSeconds: 1,
      fetchFn: async () => ({ ok: false, status: 500 }),
    })).rejects.toThrow('registry error 500');

    await expect(loadCache(path.join(mkTmpDir(), 'cache.json'))).resolves.toEqual({});

    expect(() => parseIso8601('')).toThrow('invalid iso8601');
    expect(parseIso8601('2026-04-01T00:00:00+00:00').toISOString()).toBe('2026-04-01T00:00:00.000Z');
    expect(() => computeAgeHours('not-a-date', () => new Date('2026-04-01T00:00:00Z'))).toThrow('invalid publish');
    expect(isAllowlisted('axios', ['axios'])).toBe(true);
    expect(isAllowlisted('@org/pkg', ['@other/*'])).toBe(false);
  });

  it('covers guardrail allowlist branch and cache disable path', async () => {
    const tmp = mkTmpDir('guardrail-extra-');
    await writeJson(path.join(tmp, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { '@org/tool': '1.0.0' } },
        'node_modules/@org/tool': { version: '1.0.0' },
      },
    });

    await writeJson(path.join(tmp, 'policy.json'), {
      min_package_age_hours: 48,
      strict_mode: true,
      denylist: {},
      allowlist: ['@org/*'],
    });

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: path.join(tmp, 'policy.json'),
        GUARDRAIL_RESULT_FILE: path.join(tmp, 'out.json'),
        GUARDRAIL_DISABLE_CACHE: '1',
      },
      log: () => {},
      errorLog: () => {},
      fetchFn: async () => ({ ok: true, json: async () => ({ time: {} }) }),
    });

    expect(output.exitCode).toBe(0);
    expect(output.result.status).toBe('allow');
    expect(output.result.cache_file).toBe('');
    expect(output.result.allowed[0].reason).toBe('allowlisted');
  });

  it('covers guardrail strict metadata failure and default policy branches', async () => {
    const tmp = mkTmpDir('guardrail-strict-extra-');
    await writeJson(path.join(tmp, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'safe-lib': '1.0.0' } },
        'node_modules/safe-lib': { version: '1.0.0' },
      },
      dependencies: {
        sample: 'non-object',
        zed: { version: '2.0.0' },
      },
    });
    await writeJson(path.join(tmp, 'policy.json'), {});

    const output = await runGuardrail({
      cwd: tmp,
      env: {
        GUARDRAIL_POLICY_FILE: path.join(tmp, 'policy.json'),
        GUARDRAIL_RESULT_FILE: path.join(tmp, 'out.json'),
      },
      fetchFn: async () => {
        throw new Error('metadata failed');
      },
      log: () => {},
      errorLog: () => {},
    });

    expect(output.exitCode).toBe(3);
    expect(output.result.status).toBe('quarantine');
    expect(output.result.quarantined[0].reason).toBe('metadata_unavailable_strict_mode');
  });

  it('covers filesystem helpers and project discovery edge branches', async () => {
    const tmp = mkTmpDir('incident-extra-');
    const missingRead = await safeReadText(path.join(tmp, 'missing.txt'));
    expect(missingRead).toBeNull();

    const invalidJsonPath = path.join(tmp, 'invalid.json');
    await fsp.writeFile(invalidJsonPath, '{broken', 'utf8');
    expect(await safeLoadJson(invalidJsonPath)).toBeNull();

    const noAccessRoot = path.join(tmp, 'none');
    const files = await walkFiles(noAccessRoot);
    expect(files).toEqual([]);

    const singlePackage = path.join(tmp, 'package.json');
    await writeJson(singlePackage, { name: 'single', dependencies: { axios: '1.0.0' } });
    const projectsFromFile = await discoverProjects([singlePackage]);
    expect(projectsFromFile).toEqual([tmp]);

    const txtPath = path.join(tmp, 'plain.txt');
    await fsp.writeFile(txtPath, 'hi', 'utf8');
    const projectsFromText = await discoverProjects([txtPath]);
    expect(projectsFromText).toEqual([]);

    const projectsFromMissing = await discoverProjects(['/definitely/missing/project/path']);
    expect(projectsFromMissing).toEqual([]);

    const axiosVersions = await extractAxiosFromPackageJson(path.join(tmp, 'missing-package.json'));
    expect(axiosVersions).toEqual([]);
  });

  it('covers parse lockfile errors and IOC detection branches', async () => {
    const tmp = mkTmpDir('parse-extra-');
    const project = path.join(tmp, 'project');
    await fsp.mkdir(project, { recursive: true });

    await fsp.writeFile(path.join(project, 'package-lock.json'), '{oops', 'utf8');
    const parsed = await parseLockfiles(project);
    expect(parsed.errors.length).toBe(1);

    const iocs = detectSystemIocs({
      env: { PROGRAMDATA: 'C:\\ProgramData' },
      existsFn: (candidate) => candidate.includes('wt.exe') || candidate.includes('com.apple.act.mond'),
    });
    expect(iocs.some((entry) => entry.includes('windows'))).toBe(true);
    expect(iocs.some((entry) => entry.includes('darwin'))).toBe(true);
  });

  it('covers CI and secret hunts plus text classifier fallbacks', async () => {
    const tmp = mkTmpDir('hunt-extra-');
    const wf = path.join(tmp, '.github', 'workflows', 'ci.yml');
    const envFile = path.join(tmp, 'service', '.env.production');
    const keyFile = path.join(tmp, 'service', 'secrets.txt');
    const binFile = path.join(tmp, 'service', 'asset.bin');

    await fsp.mkdir(path.dirname(wf), { recursive: true });
    await fsp.mkdir(path.dirname(envFile), { recursive: true });

    await fsp.writeFile(wf, 'steps:\n  - run: npm ci\n', 'utf8');
    await fsp.writeFile(envFile, 'DB_PASSWORD=secret\n', 'utf8');
    await fsp.writeFile(keyFile, 'AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n', 'utf8');
    await fsp.writeFile(binFile, '010101', 'utf8');
    await fsp.chmod(binFile, 0o000);
    await fsp.writeFile(path.join(tmp, 'Jenkinsfile'), 'sh \"npm install\"', 'utf8');

    const ci = await findCiPipelinesWithNpm([tmp]);
    expect(ci.length).toBe(2);

    const secrets = await huntProbableSecrets([tmp], 2);
    expect(secrets.length).toBe(2);
    expect(looksTextual(binFile)).toBe(false);
    await fsp.chmod(binFile, 0o644);
  });

  it('covers risk and confidence helpers across branches', () => {
    expect(inferLateralPaths([], [], [])).toEqual([]);
    expect(inferLateralPaths([{}], ['ci'], ['sec']).length).toBeGreaterThan(2);

    expect(inferProductionExposure([{}], ['u'], ['ci'], ['s'])).toBe('Critical');
    expect(inferProductionExposure([{}], [], ['ci'], [])).toBe('High');
    expect(inferProductionExposure([{}], [], [], [])).toBe('Medium');
    expect(inferProductionExposure([], ['u'], ['ci'], ['s'])).toBe('High');
    expect(inferProductionExposure([], ['u'], [], [])).toBe('Medium');
    expect(inferProductionExposure([], [], [], [])).toBe('Low');

    expect(computeRiskLevel([], [], [], [], [])).toBe('Low');
    expect(computeRiskLevel(['ioc'], [], [], [], [])).toBe('Critical');
    expect(computeRiskLevel([], [{}], [], [], [])).toBe('High');
    expect(computeRiskLevel([], [], [{}], ['ci'], ['sec'])).toBe('High');
    expect(computeRiskLevel([], [], [{}], [], [])).toBe('Medium');
    expect(computeRiskLevel([], [], [], [], ['sec'])).toBe('Low');

    expect(computeConfidence(true, [], [], ['scan_error'])).toBe('Low');
    expect(computeConfidence(true, ['ioc'], [], [])).toBe('High');
    expect(computeConfidence(true, [], [{
      malicious_axios_versions: [],
      malicious_dependency_hits: [],
      plain_crypto_node_modules_present: false,
    }], [])).toBe('Medium');

    expect(buildImmediateActions(false).length).toBe(3);
    expect(buildImmediateActions(true).length).toBeGreaterThan(3);
    expect(buildRemediationPlan(false).length).toBe(3);
    expect(buildRemediationPlan(true).length).toBeGreaterThan(3);
    expect(buildPreventiveMeasures().length).toBeGreaterThan(5);

    expect(projectIsImpacted({
      malicious_axios_versions: [],
      malicious_dependency_hits: [],
      plain_crypto_node_modules_present: false,
      uncertainty_flags: [],
    })).toBe(false);
  });

  it('covers scanProjects and renderMarkdown optional evidence sections', async () => {
    const tmp = mkTmpDir('scan-projects-extra-');
    const project = path.join(tmp, 'p');
    await fsp.mkdir(path.join(project, 'node_modules', 'plain-crypto-js'), { recursive: true });
    await writeJson(path.join(project, 'package.json'), {
      name: 'p',
      dependencies: { axios: '1.14.1' },
    });
    await writeJson(path.join(project, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '1.14.1', 'plain-crypto-js': '4.2.1' } },
        'node_modules/axios': { version: '1.14.1' },
        'node_modules/plain-crypto-js': { version: '4.2.1' },
      },
    });

    const { findings } = await scanProjects([project]);
    expect(findings.length).toBe(1);

    const markdown = renderMarkdown({
      affected: true,
      affected_basis: 'direct_compromise_detected',
      confidence: 'High',
      evidence: ['ioc_file_present:linux:/tmp/ld.py'],
      direct_compromise_evidence: ['ioc_file_present:linux:/tmp/ld.py'],
      uncertainty_evidence: [],
      risk_level: 'Critical',
      impacted_projects: [{ root: '<R1>' }],
      direct_impacted_projects: [{ root: '<R1>' }],
      uncertainty_impacted_projects: [{ root: '<R2>' }],
      ci_pipelines_with_npm_install: ['<R1>/.github/workflows/ci.yml'],
      probable_secret_exposures: ['env_file_present:<R1>/.env'],
      lateral_movement_paths: ['path'],
      production_exposure_risk: 'Critical',
      immediate_actions: ['action1'],
      remediation_plan: ['plan1'],
      preventive_measures: ['measure1'],
    });

    expect(markdown).toContain('Impacted repositories: <R1>');
    expect(markdown).toContain('Directly compromised repositories: <R1>');
    expect(markdown).toContain('Uncertainty-driven repositories (assumed compromised): <R2>');
    expect(markdown).toContain('CI/CD pipelines with npm install/npm ci');
    expect(markdown).toContain('Probable credential/secret findings');
  });

  it('covers runScan not-affected basis', async () => {
    const tmp = mkTmpDir('runscan-extra-');
    const result = await runScan([tmp]);
    expect(result.affected).toBe(false);
    expect(result.affected_basis).toBe('no_compromise_indicators');
    expect(result.risk_level).toBe('Low');
  });

  it('covers runScan evidence branches for malicious dependency, plain crypto, and scan errors', async () => {
    const tmp = mkTmpDir('runscan-evidence-');
    const project = path.join(tmp, 'project');
    await fsp.mkdir(path.join(project, 'node_modules', 'plain-crypto-js'), { recursive: true });
    await writeJson(path.join(project, 'package.json'), { dependencies: { axios: '1.14.1' } });
    await writeJson(path.join(project, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '1.14.1', 'plain-crypto-js': '4.2.1' } },
        'node_modules/axios': { version: '1.14.1' },
        'node_modules/plain-crypto-js': { version: '4.2.1' },
      },
    });
    await fsp.writeFile(path.join(project, 'npm-shrinkwrap.json'), '{broken', 'utf8');

    const result = await runScan([tmp]);
    expect(result.evidence.some((item) => item.startsWith('malicious_dependency:'))).toBe(true);
    expect(result.evidence.some((item) => item.startsWith('plain_crypto_js_present:'))).toBe(true);
    expect(result.evidence.some((item) => item.startsWith('scan_error:'))).toBe(true);
  });

  it('covers matrix helpers and additional exit branches', async () => {
    const tmp = mkTmpDir('matrix-extra-');
    const lockfile = path.join(tmp, 'package-lock.json');
    await writeJson(lockfile, { lockfileVersion: 3, packages: { '': {} } });

    const discoveredFromFile = await discoverLockfiles([lockfile]);
    expect(discoveredFromFile).toEqual([lockfile]);
    const nonLockfile = path.join(tmp, 'not-lock.txt');
    await fsp.writeFile(nonLockfile, 'x', 'utf8');
    const discoveredFromTextFile = await discoverLockfiles([nonLockfile]);
    expect(discoveredFromTextFile).toEqual([]);

    const listed = path.join(tmp, 'list.txt');
    await fsp.writeFile(listed, `${lockfile}\n${path.join(tmp, 'ignore.txt')}\n${path.join(tmp, 'missing-lock/package-lock.json')}\n`, 'utf8');
    const parsedList = await readLockfilesFile(listed, ['/not-match/']);
    expect(parsedList).toEqual([lockfile]);

    expect(gitTopLevel('/definitely/not/a/repo')).toBe('');

    const workspace = mkTmpDir('matrix-exit-');
    const project = path.join(workspace, 'project');
    const outputDir = path.join(workspace, 'out');
    const policyPath = path.join(workspace, 'policy.json');
    const badScript = path.join(workspace, 'missing-script.js');
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
      denylist: {},
      allowlist: [],
    });

    execFileSync('git', ['init'], { cwd: workspace, stdio: 'ignore' });

    const errorResult = await runGuardrailMatrix({
      roots: [workspace],
      outputDir,
      policyFile: policyPath,
      guardrailScript: badScript,
      cacheFile: path.join(workspace, 'cache.json'),
      anonymizeOutput: false,
      cwd: workspace,
      logger: () => {},
    });

    expect(errorResult.exitCode).toBe(5);
    expect(errorResult.statusCounts.error).toBe(1);

    const lockfilesFile = path.join(workspace, 'lockfiles.txt');
    await fsp.writeFile(lockfilesFile, `${path.join(project, 'package-lock.json')}\n`, 'utf8');
    const blockResult = await runGuardrailMatrix({
      lockfilesFile,
      outputDir: path.join(workspace, 'block-out'),
      policyFile: path.join(repoRoot, 'policies/guardrail-policy.json'),
      guardrailScript: path.join(repoRoot, 'scripts/guardrail.js'),
      cacheFile: path.join(workspace, 'cache-block.json'),
      denylistOnly: true,
      cwd: repoRoot,
      logger: () => {},
    });
    expect(blockResult.exitCode).toBe(1);
    expect(blockResult.statusCounts.block).toBe(1);

    const timeoutScript = path.join(workspace, 'timeout-script.js');
    await fsp.writeFile(timeoutScript, 'setTimeout(()=>process.exit(0), 2000);\n', 'utf8');

    const timeoutResult = await runGuardrailMatrix({
      roots: [workspace],
      outputDir: path.join(workspace, 'timeout-out'),
      policyFile: policyPath,
      guardrailScript: timeoutScript,
      cacheFile: path.join(workspace, 'cache2.json'),
      runnerTimeoutSeconds: 0.01,
      cwd: workspace,
      logger: () => {},
    });

    expect(timeoutResult.exitCode).toBe(4);
    expect(timeoutResult.statusCounts.timeout).toBe(1);

    const quarantineScript = path.join(workspace, 'quarantine-script.js');
    await fsp.writeFile(quarantineScript, [
      'const fs = require(\"fs\");',
      'const out = process.env.GUARDRAIL_RESULT_FILE;',
      'fs.writeFileSync(out, JSON.stringify({ status: \"quarantine\", summary: { quarantined_count: 1 } }));',
      'process.exit(3);',
      '',
    ].join('\n'), 'utf8');

    const quarantineResult = await runGuardrailMatrix({
      roots: [workspace],
      outputDir: path.join(workspace, 'quarantine-out'),
      policyFile: policyPath,
      guardrailScript: quarantineScript,
      cacheFile: path.join(workspace, 'cache3.json'),
      cwd: workspace,
      logger: () => {},
    });
    expect(quarantineResult.exitCode).toBe(3);
    expect(quarantineResult.statusCounts.quarantine).toBe(1);

    const blockOnlyNoBlock = await runGuardrailMatrix({
      roots: [workspace],
      outputDir: path.join(workspace, 'block-only-no-block'),
      policyFile: policyPath,
      guardrailScript: quarantineScript,
      cacheFile: path.join(workspace, 'cache4.json'),
      exitOn: 'block-only',
      cwd: workspace,
      logger: () => {},
    });
    expect(blockOnlyNoBlock.exitCode).toBe(0);
  });

  it('covers security event defaults', () => {
    const payload = buildGuardrailEventPayload({ result: {} });
    expect(payload.pipeline_id).toBe('unknown');
    expect(payload.repository).toBe('unknown');
    expect(payload.commit_sha).toBe('unknown');

    const quarantineIncident = createIncident({ status: 'quarantine' }, () => '2026-04-01T00:00:00Z');
    expect(quarantineIncident.severity).toBe('high');
    expect(quarantineIncident.recommended_actions[0]).toBe('Quarantine artifact');
  });
});
