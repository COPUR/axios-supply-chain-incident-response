#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import {
  anonymizeScanResult,
  renderMarkdown,
  runScan,
} from '../src/lib/incident-scan-core.js';
import { runWithObservability } from '../src/lib/observability.js';

const argv = await yargs(hideBin(process.argv))
  .option('roots', {
    type: 'array',
    default: [process.cwd()],
    describe: 'One or more root directories to scan',
  })
  .option('output', {
    type: 'string',
    default: '',
    describe: 'Optional markdown output file path',
  })
  .option('json-out', {
    type: 'string',
    default: '',
    describe: 'Optional JSON output file path',
  })
  .option('no-anonymize-output', {
    type: 'boolean',
    default: false,
    describe: 'Disable output anonymization/redaction',
  })
  .strict()
  .parse();

const roots = (argv.roots || []).map((item) => path.resolve(String(item)));

const outcome = await runWithObservability({
  tool: 'incident_scan',
  execute: async () => {
    let result = await runScan(roots);

    if (!argv.noAnonymizeOutput) {
      result = anonymizeScanResult(result, roots);
    }

    const markdown = renderMarkdown(result);
    if (argv.output) {
      await fs.writeFile(path.resolve(String(argv.output)), markdown, 'utf8');
    } else {
      process.stdout.write(markdown);
    }

    if (argv.jsonOut) {
      await fs.writeFile(path.resolve(String(argv.jsonOut)), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
    }

    return {
      exitCode: result.affected ? 2 : 0,
      metrics: {
        status: result.affected ? 'affected' : 'not_affected',
        risk_level: result.risk_level,
        affected_basis: result.affected_basis,
        impacted_projects: result.impacted_projects.length,
        direct_impacted_projects: result.direct_impacted_projects.length,
        uncertainty_impacted_projects: result.uncertainty_impacted_projects.length,
        ci_hits: result.ci_pipelines_with_npm_install.length,
        secret_hits: result.probable_secret_exposures.length,
      },
    };
  },
});

process.exit(outcome.exitCode);
