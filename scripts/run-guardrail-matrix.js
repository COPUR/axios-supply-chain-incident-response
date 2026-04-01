#!/usr/bin/env node
import path from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { runGuardrailMatrix } from '../src/lib/matrix-core.js';
import { runWithObservability } from '../src/lib/observability.js';

const argv = await yargs(hideBin(process.argv))
  .option('roots', {
    type: 'array',
    default: ['.'],
    describe: 'Root paths to discover lockfiles from',
  })
  .option('lockfiles-file', {
    type: 'string',
    default: '',
    describe: 'Optional file listing lockfiles',
  })
  .option('output-dir', {
    type: 'string',
    default: 'guardrail-matrix-output',
    describe: 'Directory for result artifacts',
  })
  .option('policy-file', {
    type: 'string',
    default: 'policies/guardrail-policy.json',
    describe: 'Guardrail policy file path',
  })
  .option('guardrail-script', {
    type: 'string',
    default: 'scripts/guardrail.js',
    describe: 'Path to guardrail script',
  })
  .option('cache-file', {
    type: 'string',
    default: '.guardrail-npm-metadata-cache.json',
    describe: 'Shared metadata cache file',
  })
  .option('denylist-only', {
    type: 'boolean',
    default: false,
    describe: 'Enable denylist-only mode',
  })
  .option('age-scope', {
    type: 'string',
    default: 'all',
    choices: ['all', 'direct'],
    describe: 'Scope for package age checks',
  })
  .option('http-timeout-seconds', {
    type: 'number',
    default: 10,
    describe: 'HTTP timeout for npm metadata calls',
  })
  .option('runner-timeout-seconds', {
    type: 'number',
    default: 240,
    describe: 'Timeout per lockfile guardrail subprocess',
  })
  .option('exclude-substring', {
    type: 'array',
    default: [],
    describe: 'Exclude lockfile paths containing substring',
  })
  .option('exit-on', {
    type: 'string',
    default: 'all',
    choices: ['all', 'block-only'],
    describe: 'Exit policy',
  })
  .option('no-anonymize-output', {
    type: 'boolean',
    default: false,
    describe: 'Disable anonymization/redaction in summary output',
  })
  .option('max-workers', {
    type: 'number',
    default: Number(process.env.GUARDRAIL_MAX_WORKERS || 4),
    describe: 'Parallel lockfile workers for matrix execution',
  })
  .strict()
  .parse();

const outcome = await runWithObservability({
  tool: 'guardrail_matrix',
  execute: async () => {
    const result = await runGuardrailMatrix({
      roots: (argv.roots || []).map((item) => String(item)),
      lockfilesFile: argv.lockfilesFile,
      outputDir: argv.outputDir,
      policyFile: argv.policyFile,
      guardrailScript: argv.guardrailScript,
      cacheFile: argv.cacheFile,
      denylistOnly: argv.denylistOnly,
      ageScope: argv.ageScope,
      httpTimeoutSeconds: Number(argv.httpTimeoutSeconds),
      runnerTimeoutSeconds: Number(argv.runnerTimeoutSeconds),
      excludeSubstring: (argv.excludeSubstring || []).map((item) => String(item)),
      exitOn: argv.exitOn,
      anonymizeOutput: !argv.noAnonymizeOutput,
      maxWorkers: Math.max(1, Number(argv.maxWorkers || 1)),
      cwd: path.resolve(process.cwd()),
    });

    return {
      exitCode: result.exitCode,
      metrics: {
        lockfile_count: result.lockfileCount,
        worker_count: result.workerCount,
        status_counts: result.statusCounts,
      },
    };
  },
});

process.exit(outcome.exitCode);
