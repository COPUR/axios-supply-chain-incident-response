import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  anonymizeScanResult,
  findCiPipelinesWithNpm,
  huntProbableSecrets,
  parseLockfiles,
  parsePnpmLockCatalogs,
  parsePnpmLockPackages,
  parsePnpmWorkspaceCatalogs,
  renderMarkdown,
  runScan,
  scanProjects,
} from '../src/lib/incident-scan-core.js';

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'incident-scan-'));
}

async function writeJson(filePath, value) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

describe('incident scan core', () => {
  it('marks uncertainty-only findings as assumed compromise', async () => {
    const root = mkTmpDir();
    const project = path.join(root, 'project');
    await fsp.mkdir(project, { recursive: true });

    await writeJson(path.join(project, 'package.json'), {
      name: 'p',
      version: '1.0.0',
      dependencies: { axios: '^1.11.0' },
    });

    const result = await runScan([root]);
    expect(result.affected).toBe(true);
    expect(result.affected_basis).toBe('assumed_compromise_due_to_uncertainty');
    expect(result.direct_compromise_evidence.length).toBe(0);
    expect(result.uncertainty_evidence.length).toBeGreaterThanOrEqual(1);
  });

  it('detects direct malicious axios lockfile version', async () => {
    const root = mkTmpDir();
    const project = path.join(root, 'project');
    await fsp.mkdir(project, { recursive: true });

    await writeJson(path.join(project, 'package.json'), {
      name: 'p',
      version: '1.0.0',
      dependencies: { axios: '1.14.1' },
    });

    await writeJson(path.join(project, 'package-lock.json'), {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '1.14.1' } },
        'node_modules/axios': { name: 'axios', version: '1.14.1' },
      },
    });

    const result = await runScan([root]);
    expect(result.affected).toBe(true);
    expect(result.affected_basis).toBe('direct_compromise_detected');
    expect(result.direct_compromise_evidence.some((item) => item.includes('malicious_axios'))).toBe(true);
  });

  it('detects host IOC as direct compromise evidence', async () => {
    const root = mkTmpDir();

    const result = await runScan([root], {
      existsFn: (target) => target === '/tmp/ld.py',
    });

    expect(result.affected).toBe(true);
    expect(result.affected_basis).toBe('direct_compromise_detected');
    expect(result.direct_compromise_evidence).toContain('ioc_file_present:linux:/tmp/ld.py');
  });

  it('parses pnpm catalog and lockfile package versions', () => {
    const workspace = [
      'packages:',
      '  - packages/*',
      'catalog:',
      '  axios: 1.8.3',
      'catalogs:',
      '  frontend:',
      '    vue: ^3.5.0',
      '',
    ].join('\n');

    const lock = [
      "lockfileVersion: '9.0'",
      'catalogs:',
      '  default:',
      '    axios:',
      '      specifier: 1.8.3',
      '      version: 1.8.3',
      'packages:',
      '  axios@1.8.3:',
      '    resolution: {integrity: sha512-abc}',
      '  @scope/pkg@2.0.0:',
      '    resolution: {integrity: sha512-def}',
      '',
    ].join('\n');

    const catalogs = parsePnpmWorkspaceCatalogs(workspace);
    expect(catalogs.default.axios).toBe('1.8.3');
    expect(catalogs.frontend.vue).toBe('^3.5.0');

    const packages = parsePnpmLockPackages(lock);
    expect(packages).toContainEqual(['axios', '1.8.3']);
    expect(packages).toContainEqual(['@scope/pkg', '2.0.0']);
  });

  it('handles pnpm parser edge branches and quoted catalog values', () => {
    expect(parsePnpmLockPackages(null)).toEqual([]);

    const lockPackages = parsePnpmLockPackages([
      "lockfileVersion: '9.0'",
      'packages:',
      '  axios@1.8.4:',
      '    resolution: {integrity: sha512-1}',
      '  /axios@1.8.3(debug@4.0.0):',
      '    resolution: {integrity: sha512-abc}',
      '  plain-crypto-js@4.2.1:',
      '    resolution: {integrity: sha512-def}',
      '  invalid@not-semver:',
      '    resolution: {integrity: sha512-zzz}',
      '  - ignored-list-item:',
      '',
    ].join('\n'));

    expect(lockPackages).toContainEqual(['axios', '1.8.3']);
    expect(lockPackages).toContainEqual(['plain-crypto-js', '4.2.1']);
    expect(lockPackages.some(([name]) => name === 'invalid')).toBe(false);

    const lockCatalogs = parsePnpmLockCatalogs([
      '# comment',
      "lockfileVersion: '9.0'",
      'catalogs:',
      '  default:',
      "    'axios':",
      "      version: '1.8.3'",
      '  frontend:',
      '    axios:',
      '      version: ^1.8.3',
      'importers:',
      '  .:',
      '    dependencies: {}',
      '',
    ].join('\n'));

    expect(lockCatalogs.default.axios).toBe('1.8.3');
    expect(lockCatalogs.frontend.axios).toBe('^1.8.3');

    const workspaceCatalogs = parsePnpmWorkspaceCatalogs([
      'catalog:',
      "  'axios': \"1.8.3\"",
      '',
    ].join('\n'));
    expect(workspaceCatalogs.default.axios).toBe('1.8.3');
  });

  it('resolves catalog axios declarations from pnpm workspace without uncertainty', async () => {
    const root = mkTmpDir();
    const workspaceRoot = path.join(root, 'workspace');
    const project = path.join(workspaceRoot, 'packages', 'service');
    await fsp.mkdir(project, { recursive: true });

    await fsp.writeFile(path.join(workspaceRoot, 'pnpm-workspace.yaml'), [
      'packages:',
      '  - packages/*',
      'catalog:',
      '  axios: 1.8.3',
      '',
    ].join('\n'), 'utf8');

    await fsp.writeFile(path.join(workspaceRoot, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'catalogs:',
      '  default:',
      '    axios:',
      '      specifier: 1.8.3',
      '      version: 1.8.3',
      'packages:',
      '  axios@1.8.3:',
      '    resolution: {integrity: sha512-abc}',
      '',
    ].join('\n'), 'utf8');

    await writeJson(path.join(project, 'package.json'), {
      name: 'service',
      version: '1.0.0',
      dependencies: { axios: 'catalog:' },
    });

    const result = await runScan([workspaceRoot]);
    expect(result.affected).toBe(false);
    expect(result.affected_basis).toBe('no_compromise_indicators');
    expect(result.impacted_projects.length).toBe(0);
    expect(result.evidence.some((entry) => entry.includes('axios_versions:'))).toBe(true);
  });

  it('flags unresolved catalog spec when catalog namespace has no axios entry', async () => {
    const root = mkTmpDir();
    const workspaceRoot = path.join(root, 'workspace');
    const project = path.join(workspaceRoot, 'packages', 'service');
    await fsp.mkdir(project, { recursive: true });

    await fsp.writeFile(path.join(workspaceRoot, 'pnpm-workspace.yaml'), [
      'packages:',
      '  - packages/*',
      'catalogs:',
      '  frontend:',
      '    vue: ^3.5.0',
      '',
    ].join('\n'), 'utf8');

    await writeJson(path.join(project, 'package.json'), {
      name: 'service',
      version: '1.0.0',
      dependencies: { axios: 'catalog:frontend' },
    });

    const result = await runScan([workspaceRoot]);
    expect(result.affected).toBe(true);
    expect(result.affected_basis).toBe('assumed_compromise_due_to_uncertainty');
    expect(result.uncertainty_evidence.some((entry) => entry.includes('unresolved_catalog_spec:catalog:frontend'))).toBe(true);
  });

  it('handles malicious and non-exact catalog resolutions in one pnpm workspace', async () => {
    const root = mkTmpDir();
    const workspaceRoot = path.join(root, 'workspace');
    const p1 = path.join(workspaceRoot, 'packages', 'malicious');
    const p2 = path.join(workspaceRoot, 'packages', 'nonexact');
    await fsp.mkdir(p1, { recursive: true });
    await fsp.mkdir(p2, { recursive: true });

    await fsp.writeFile(path.join(workspaceRoot, 'pnpm-workspace.yaml'), [
      'packages:',
      '  - packages/*',
      'catalog:',
      '  axios: 1.14.1',
      'catalogs:',
      '  frontend:',
      '    axios: ^1.8.3',
      '',
    ].join('\n'), 'utf8');

    await writeJson(path.join(p1, 'package.json'), {
      name: 'malicious',
      version: '1.0.0',
      dependencies: { axios: 'catalog:' },
    });
    await writeJson(path.join(p2, 'package.json'), {
      name: 'nonexact',
      version: '1.0.0',
      dependencies: { axios: 'catalog:frontend' },
    });

    const result = await runScan([workspaceRoot]);
    expect(result.affected).toBe(true);
    expect(result.affected_basis).toBe('direct_compromise_detected');
    expect(result.direct_compromise_evidence.some((entry) => entry.includes('malicious_axios'))).toBe(true);
    expect(result.uncertainty_evidence.some((entry) => entry.includes('non_exact_catalog_resolution:catalog:frontend'))).toBe(true);
  });

  it('records pnpm parse errors when lockfile path is unreadable', async () => {
    const root = mkTmpDir();
    const project = path.join(root, 'project');
    await fsp.mkdir(project, { recursive: true });

    await writeJson(path.join(project, 'package.json'), {
      name: 'p',
      dependencies: { axios: 'catalog:' },
    });

    await fsp.mkdir(path.join(root, 'pnpm-lock.yaml'), { recursive: true });

    const parsed = await parseLockfiles(project);
    expect(parsed.errors.some((entry) => entry.includes('pnpm-lock.yaml'))).toBe(true);
  });

  it('covers scanProjects empty-findings path and CI candidate filtering', async () => {
    const root = mkTmpDir();
    const emptyProject = path.join(root, 'empty-project');
    await fsp.mkdir(emptyProject, { recursive: true });

    const scanned = await scanProjects([emptyProject]);
    expect(scanned.findings).toEqual([]);

    const wfDir = path.join(root, '.github', 'workflows');
    await fsp.mkdir(wfDir, { recursive: true });
    const workflowYml = path.join(wfDir, 'ci.yml');
    const workflowTxt = path.join(wfDir, 'notes.txt');
    const rootYaml = path.join(root, 'random.yml');
    await fsp.writeFile(workflowYml, 'steps:\n  - run: npm ci\n', 'utf8');
    await fsp.writeFile(workflowTxt, 'npm ci\n', 'utf8');
    await fsp.writeFile(rootYaml, 'npm ci\n', 'utf8');

    const ciHits = await findCiPipelinesWithNpm([root]);
    expect(ciHits).toEqual([workflowYml]);
  });

  it('skips unreadable files during secret hunting', async () => {
    const root = mkTmpDir();
    const filePath = path.join(root, 'secrets.txt');
    await fsp.writeFile(filePath, 'AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n', 'utf8');
    await fsp.chmod(filePath, 0o000);

    const hits = await huntProbableSecrets([root], 10);
    expect(hits).toEqual([]);

    await fsp.chmod(filePath, 0o644);
  });

  it('anonymizes absolute paths in result output', () => {
    const root = path.resolve('/tmp/redaction-root');

    const result = {
      affected: true,
      affected_basis: 'assumed_compromise_due_to_uncertainty',
      confidence: 'Medium',
      evidence: [`uncertainty:${root}/project:flag`],
      direct_compromise_evidence: [],
      uncertainty_evidence: [`uncertainty:${root}/project:flag`],
      risk_level: 'Medium',
      impacted_projects: [
        {
          root: `${root}/project`,
          axios_versions_in_lock: [],
          axios_declared_versions: ['^1.0.0'],
          malicious_axios_versions: [],
          malicious_dependency_hits: [],
          plain_crypto_node_modules_present: false,
          uncertainty_flags: [`scan_error:${root}/project/package-lock.json`],
          lockfile_paths: [`${root}/project/package-lock.json`],
        },
      ],
      direct_impacted_projects: [],
      uncertainty_impacted_projects: [],
      ci_pipelines_with_npm_install: [`${root}/.github/workflows/ci.yml`],
      probable_secret_exposures: [`env_file_present:${root}/project/.env`],
      lateral_movement_paths: [`path:${root}/project`],
      production_exposure_risk: 'Low',
      immediate_actions: [],
      remediation_plan: [],
      preventive_measures: [],
    };

    const anon = anonymizeScanResult(result, [root]);
    const serialized = JSON.stringify(anon);
    expect(serialized.includes(root)).toBe(false);
    expect(serialized.includes('<SCAN_ROOT_1>')).toBe(true);
  });

  it('renders required incident response report sections', () => {
    const markdown = renderMarkdown({
      affected: false,
      affected_basis: 'no_compromise_indicators',
      confidence: 'High',
      evidence: [],
      direct_compromise_evidence: [],
      uncertainty_evidence: [],
      risk_level: 'Low',
      impacted_projects: [],
      direct_impacted_projects: [],
      uncertainty_impacted_projects: [],
      ci_pipelines_with_npm_install: [],
      probable_secret_exposures: [],
      lateral_movement_paths: [],
      production_exposure_risk: 'Low',
      immediate_actions: ['action'],
      remediation_plan: ['plan'],
      preventive_measures: ['measure'],
    });

    expect(markdown).toContain('## SECTION 1: Detection Result');
    expect(markdown).toContain('## SECTION 2: Risk Level');
    expect(markdown).toContain('## SECTION 3: Immediate Actions');
    expect(markdown).toContain('## SECTION 4: Remediation Plan');
    expect(markdown).toContain('## SECTION 5: Preventive Measures');
  });
});
