import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  anonymizeScanResult,
  renderMarkdown,
  runScan,
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
