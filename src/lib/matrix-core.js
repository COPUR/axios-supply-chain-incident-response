import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';

import { anonymizePath, sanitizeText } from './anonymize.js';
import { LOCKFILE_NAMES } from './lockfile-utils.js';

const MATRIX_SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.runtime',
  '.npm-cache',
  'dist',
  'build',
  'target',
  'vendor',
]);

function isExcluded(candidatePath, excludes) {
  return excludes.some((pattern) => candidatePath.includes(pattern));
}

export async function discoverLockfiles(roots, extraExcludes = []) {
  const lockfiles = new Set();

  for (const rootItem of roots) {
    const root = path.resolve(rootItem);
    let stat;
    try {
      stat = await fsp.stat(root);
    } catch {
      continue;
    }

    if (stat.isFile() && LOCKFILE_NAMES.includes(path.basename(root))) {
      if (!isExcluded(root, extraExcludes)) {
        lockfiles.add(root);
      }
      continue;
    }

    if (!stat.isDirectory()) {
      continue;
    }

    const stack = [root];
    while (stack.length > 0) {
      const current = stack.pop();
      let entries = [];
      try {
        entries = await fsp.readdir(current, { withFileTypes: true });
      } catch {
        continue;
      }

      for (const entry of entries) {
        const candidate = path.join(current, entry.name);
        if (entry.isDirectory()) {
          if (!MATRIX_SKIP_DIRS.has(entry.name)) {
            stack.push(candidate);
          }
          continue;
        }

        if (!entry.isFile()) {
          continue;
        }

        if (!LOCKFILE_NAMES.includes(entry.name)) {
          continue;
        }

        const resolved = path.resolve(candidate);
        if (!isExcluded(resolved, extraExcludes)) {
          lockfiles.add(resolved);
        }
      }
    }
  }

  return [...lockfiles].sort();
}

export async function readLockfilesFile(filePath, extraExcludes = []) {
  const text = await fsp.readFile(path.resolve(filePath), 'utf8');
  const lockfiles = new Set();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }

    const candidate = path.resolve(line);
    if (!LOCKFILE_NAMES.includes(path.basename(candidate))) {
      continue;
    }

    if (!fs.existsSync(candidate)) {
      continue;
    }

    if (!isExcluded(candidate, extraExcludes)) {
      lockfiles.add(candidate);
    }
  }

  return [...lockfiles].sort();
}

export function gitTopLevel(projectDir) {
  try {
    return execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return '';
  }
}

function csvEscape(value) {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function runGuardrailChildProcess(scriptPath, { cwd, env, timeoutMs }) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const child = spawn(process.execPath, [scriptPath], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        status: 1,
        stdout,
        stderr: `${stderr}${String(error?.message || error)}`,
        error,
      });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        status: code ?? 1,
        stdout,
        stderr,
        error: timedOut ? { code: 'ETIMEDOUT' } : null,
      });
    });
  });
}

async function writeCsv(filePath, rows, headers) {
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map((header) => csvEscape(row[header])).join(','));
  }
  await fsp.writeFile(filePath, `${lines.join('\n')}\n`, 'utf8');
}

export async function runGuardrailMatrix(options = {}) {
  const {
    roots = ['.'],
    lockfilesFile = '',
    outputDir = 'guardrail-matrix-output',
    policyFile = 'policies/guardrail-policy.json',
    guardrailScript = 'scripts/guardrail.js',
    cacheFile = '.guardrail-npm-metadata-cache.json',
    denylistOnly = false,
    ageScope = 'all',
    httpTimeoutSeconds = 10,
    runnerTimeoutSeconds = 240,
    excludeSubstring = [],
    exitOn = 'all',
    anonymizeOutput = true,
    maxWorkers = 1,
    cwd = process.cwd(),
    env = process.env,
    logger = console.log,
  } = options;

  const outputDirAbs = path.resolve(cwd, outputDir);
  const resultsDir = path.join(outputDirAbs, 'results');
  const summaryCsv = path.join(outputDirAbs, 'summary.csv');
  const summaryJson = path.join(outputDirAbs, 'summary.json');

  await fsp.mkdir(resultsDir, { recursive: true });

  let lockfiles;
  if (lockfilesFile) {
    lockfiles = await readLockfilesFile(path.resolve(cwd, lockfilesFile), excludeSubstring);
  } else {
    lockfiles = await discoverLockfiles(roots.map((root) => path.resolve(cwd, root)), excludeSubstring);
  }

  logger(`LOCKFILE_COUNT=${lockfiles.length}`);
  if (lockfiles.length === 0) {
    logger('No lockfiles found. Nothing to do.');
    return {
      exitCode: 0,
      lockfileCount: 0,
      statusCounts: {},
      summaryCsv,
      summaryJson,
      rows: [],
    };
  }

  const rows = [];
  const repoAliases = new Map();
  const normalizedWorkers = Math.max(1, Math.floor(Number(maxWorkers) || 1));

  const getRepoAlias = (repoRoot) => {
    if (!repoRoot) {
      return '<REPO_UNKNOWN>';
    }

    if (!repoAliases.has(repoRoot)) {
      repoAliases.set(repoRoot, `<REPO_${repoAliases.size + 1}>`);
    }

    return repoAliases.get(repoRoot);
  };

  const scriptPath = path.resolve(cwd, guardrailScript);

  const processLockfile = async (idx, lockfile) => {
    const projectDir = path.dirname(lockfile);
    const repoRoot = gitTopLevel(projectDir);
    const hash = crypto.createHash('sha256').update(lockfile).digest('hex').slice(0, 16);
    const safeName = `lockfile-${String(idx + 1).padStart(4, '0')}-${hash}`;
    const resultFile = path.join(resultsDir, `${safeName}.json`);

    const childEnv = {
      ...env,
      GUARDRAIL_POLICY_FILE: path.resolve(cwd, policyFile),
      GUARDRAIL_RESULT_FILE: resultFile,
      GUARDRAIL_CACHE_FILE: path.resolve(cwd, cacheFile),
      GUARDRAIL_HTTP_TIMEOUT_SECONDS: String(httpTimeoutSeconds),
      GUARDRAIL_AGE_SCOPE: ageScope,
    };

    if (denylistOnly) {
      childEnv.GUARDRAIL_DENYLIST_ONLY = '1';
    }

    const startedAt = Date.now();
    const proc = await runGuardrailChildProcess(scriptPath, {
      cwd: projectDir,
      env: childEnv,
      timeoutMs: runnerTimeoutSeconds * 1000,
    });

    const durationSeconds = Number(((Date.now() - startedAt) / 1000).toFixed(2));
    const timedOut = proc.error?.code === 'ETIMEDOUT';

    let status = timedOut ? 'timeout' : 'error';
    let mode = 'unknown';
    let resolvedAgeScope = 'unknown';
    let blockedCount = 0;
    let quarantinedCount = 0;
    let allowedCount = 0;
    let errorsCount = 0;

    if (fs.existsSync(resultFile)) {
      try {
        const payload = JSON.parse(await fsp.readFile(resultFile, 'utf8'));
        status = payload.status || status;
        mode = payload.mode || mode;
        resolvedAgeScope = payload.age_scope || resolvedAgeScope;
        blockedCount = Number(payload.summary?.blocked_count || 0);
        quarantinedCount = Number(payload.summary?.quarantined_count || 0);
        allowedCount = Number(payload.summary?.allowed_count || 0);
        errorsCount = Number(payload.summary?.errors_count || 0);
      } catch {
        status = 'error';
      }
    }

    const row = {
      repo_root: repoRoot,
      project_dir: projectDir,
      lockfile,
      mode,
      age_scope: resolvedAgeScope,
      status,
      exit_code: timedOut ? 124 : (proc.status ?? 1),
      blocked_count: blockedCount,
      quarantined_count: quarantinedCount,
      allowed_count: allowedCount,
      errors_count: errorsCount,
      duration_seconds: durationSeconds,
      stderr_tail: (proc.stderr || '').trim().split(/\r?\n/).slice(-3).join('\n'),
    };

    if (anonymizeOutput) {
      const repoAlias = getRepoAlias(repoRoot);
      row.repo_root = repoAlias;
      row.project_dir = anonymizePath(projectDir, repoRoot, repoAlias);
      row.lockfile = anonymizePath(lockfile, repoRoot, repoAlias);
      row.stderr_tail = sanitizeText(row.stderr_tail);
    }

    logger(
      `[${idx + 1}/${lockfiles.length}] ${status.toUpperCase()} mode=${mode} `
      + `age_scope=${resolvedAgeScope} blocked=${blockedCount} quarantined=${quarantinedCount} `
      + `errors=${errorsCount} path=${row.lockfile}`,
    );
    return {
      idx,
      row,
    };
  };

  let cursor = 0;
  const workers = Array.from({ length: Math.min(normalizedWorkers, lockfiles.length) }, async () => {
    const localRows = [];
    while (cursor < lockfiles.length) {
      const idx = cursor;
      cursor += 1;
      const processed = await processLockfile(idx, lockfiles[idx]);
      localRows.push(processed);
    }
    return localRows;
  });

  const workerResults = await Promise.all(workers);
  const flattened = workerResults.flat().sort((a, b) => a.idx - b.idx);
  for (const item of flattened) {
    rows.push(item.row);
  }

  const headers = [
    'repo_root',
    'project_dir',
    'lockfile',
    'mode',
    'age_scope',
    'status',
    'exit_code',
    'blocked_count',
    'quarantined_count',
    'allowed_count',
    'errors_count',
    'duration_seconds',
    'stderr_tail',
  ];

  await writeCsv(summaryCsv, rows, headers);

  const statusCounts = {};
  for (const row of rows) {
    statusCounts[row.status] = (statusCounts[row.status] || 0) + 1;
  }

  const aggregate = {
    output_dir: outputDirAbs,
    lockfile_count: lockfiles.length,
    worker_count: normalizedWorkers,
    anonymized_output: anonymizeOutput,
    status_counts: statusCounts,
    rows,
  };

  await fsp.writeFile(summaryJson, `${JSON.stringify(aggregate, null, 2)}\n`, 'utf8');

  logger('--- AGGREGATE ---');
  logger(JSON.stringify(statusCounts, null, 2));
  logger(`SUMMARY_CSV=${summaryCsv}`);
  logger(`SUMMARY_JSON=${summaryJson}`);

  const blocks = Number(statusCounts.block || 0);
  const quarantines = Number(statusCounts.quarantine || 0);
  const timeouts = Number(statusCounts.timeout || 0);
  const errors = Number(statusCounts.error || 0);

  let exitCode = 0;
  if (exitOn === 'block-only') {
    exitCode = blocks > 0 ? 1 : 0;
  } else if (blocks > 0) {
    exitCode = 1;
  } else if (quarantines > 0) {
    exitCode = 3;
  } else if (timeouts > 0) {
    exitCode = 4;
  } else if (errors > 0) {
    exitCode = 5;
  }

  return {
    exitCode,
    lockfileCount: lockfiles.length,
    workerCount: normalizedWorkers,
    statusCounts,
    summaryCsv,
    summaryJson,
    rows,
  };
}
