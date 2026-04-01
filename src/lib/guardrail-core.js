import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';

import {
  extractDirectPackagesFromLock,
  extractPackagesFromLock,
  findFirstLockfile,
} from './lockfile-utils.js';

export const DEFAULT_POLICY_FILE = 'policies/guardrail-policy.json';
export const DEFAULT_RESULT_FILE = 'guardrail-result.json';
export const DEFAULT_CACHE_FILE = '.guardrail-npm-metadata-cache.json';

export function nowUtc() {
  return new Date();
}

export function parseIso8601(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('invalid iso8601 timestamp');
  }

  if (value.endsWith('Z')) {
    return new Date(value);
  }

  return new Date(value);
}

export function computeAgeHours(publishedAt, nowFn = nowUtc) {
  const publishTime = parseIso8601(publishedAt).getTime();
  if (Number.isNaN(publishTime)) {
    throw new Error(`invalid publish timestamp: ${publishedAt}`);
  }

  const now = nowFn().getTime();
  return (now - publishTime) / (1000 * 60 * 60);
}

export function isTruthy(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

export function isAllowlisted(name, allowlist = []) {
  for (const pattern of allowlist) {
    if (String(pattern).endsWith('/*')) {
      const prefix = String(pattern).slice(0, -1);
      if (name.startsWith(prefix)) {
        return true;
      }
      continue;
    }

    if (name === pattern) {
      return true;
    }
  }

  return false;
}

export async function loadJson(jsonPath) {
  const text = await fsp.readFile(jsonPath, 'utf8');
  return JSON.parse(text);
}

export async function loadCache(cachePath) {
  try {
    const payload = await loadJson(cachePath);
    if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
      return payload;
    }
  } catch {
    return {};
  }

  return {};
}

export async function saveCache(cachePath, cache) {
  const parent = path.dirname(cachePath);
  await fsp.mkdir(parent, { recursive: true });
  await fsp.writeFile(cachePath, JSON.stringify(cache), 'utf8');
}

export async function fetchNpmMetadata(pkgName, options) {
  const {
    cache,
    useCache,
    httpTimeoutSeconds,
    fetchFn,
  } = options;

  if (useCache && cache[pkgName]) {
    return cache[pkgName];
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), httpTimeoutSeconds * 1000);

  try {
    const encodedName = encodeURIComponent(pkgName);
    const url = `https://registry.npmjs.org/${encodedName}`;
    const response = await fetchFn(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'guardrail-agent/2.0',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`registry error ${response.status}`);
    }

    const payload = await response.json();
    if (useCache) {
      cache[pkgName] = payload;
    }
    return payload;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function getPublishTime(pkgName, version, options) {
  const metadata = await fetchNpmMetadata(pkgName, options);
  const publishedAt = metadata?.time?.[version];

  if (!publishedAt) {
    throw new Error(`publish time not found for ${pkgName}@${version}`);
  }

  return publishedAt;
}

export function buildGuardrailConfig({ cwd = process.cwd(), env = process.env } = {}) {
  const policyFile = path.resolve(cwd, env.GUARDRAIL_POLICY_FILE || DEFAULT_POLICY_FILE);
  const resultFile = path.resolve(cwd, env.GUARDRAIL_RESULT_FILE || DEFAULT_RESULT_FILE);
  const cacheFile = path.resolve(cwd, env.GUARDRAIL_CACHE_FILE || DEFAULT_CACHE_FILE);

  let ageScope = String(env.GUARDRAIL_AGE_SCOPE || 'all').trim().toLowerCase();
  if (!['all', 'direct'].includes(ageScope)) {
    ageScope = 'all';
  }

  return {
    cwd,
    policyFile,
    resultFile,
    cacheFile,
    denylistOnlyMode: isTruthy(env.GUARDRAIL_DENYLIST_ONLY),
    useCache: !isTruthy(env.GUARDRAIL_DISABLE_CACHE),
    httpTimeoutSeconds: Number(env.GUARDRAIL_HTTP_TIMEOUT_SECONDS || 10),
    ageScope,
  };
}

export async function runGuardrail(options = {}) {
  const {
    cwd = process.cwd(),
    env = process.env,
    fetchFn = fetch,
    nowFn = nowUtc,
    log = console.log,
    errorLog = console.error,
  } = options;

  const cfg = buildGuardrailConfig({ cwd, env });
  const existsFn = (candidate) => fs.existsSync(candidate);
  const lockfile = findFirstLockfile(cfg.cwd, existsFn);

  if (!lockfile) {
    errorLog('ERROR: package-lock.json or npm-shrinkwrap.json not found');
    return { exitCode: 2, result: null };
  }

  const policy = await loadJson(cfg.policyFile);
  const lockData = await loadJson(lockfile);

  const packages = extractPackagesFromLock(lockData);
  const directPackages = extractDirectPackagesFromLock(lockData);

  const denylist = policy?.denylist || {};
  const allowlist = Array.isArray(policy?.allowlist) ? policy.allowlist : [];
  const minPackageAgeHours = Number(policy?.min_package_age_hours ?? 48);
  const strictMode = Boolean(policy?.strict_mode ?? true);

  const cache = cfg.useCache ? await loadCache(cfg.cacheFile) : {};
  const agePackages = new Set(
    (cfg.ageScope === 'direct' && directPackages.length > 0 ? directPackages : packages).map(
      ([name, version]) => `${name}@@${version}`,
    ),
  );

  const blocked = [];
  const quarantined = [];
  const allowed = [];
  const errors = [];
  let ageCheckedCount = 0;

  for (const [name, version] of packages) {
    if (isAllowlisted(name, allowlist)) {
      allowed.push({ name, version, reason: 'allowlisted' });
      continue;
    }

    if (denylist[name] && Array.isArray(denylist[name]) && denylist[name].includes(version)) {
      blocked.push({ name, version, reason: 'denylisted_version' });
      continue;
    }

    if (cfg.denylistOnlyMode) {
      allowed.push({ name, version, reason: 'denylist_only_mode' });
      continue;
    }

    if (!agePackages.has(`${name}@@${version}`)) {
      allowed.push({ name, version, reason: 'age_scope_excluded' });
      continue;
    }

    try {
      ageCheckedCount += 1;
      const publishedAt = await getPublishTime(name, version, {
        cache,
        useCache: cfg.useCache,
        httpTimeoutSeconds: cfg.httpTimeoutSeconds,
        fetchFn,
      });
      const ageHours = computeAgeHours(publishedAt, nowFn);

      if (ageHours < minPackageAgeHours) {
        quarantined.push({
          name,
          version,
          published_at: publishedAt,
          age_hours: Number(ageHours.toFixed(2)),
          reason: `package_younger_than_${minPackageAgeHours}_hours`,
        });
      } else {
        allowed.push({
          name,
          version,
          published_at: publishedAt,
          age_hours: Number(ageHours.toFixed(2)),
          reason: 'age_ok',
        });
      }
    } catch (err) {
      const message = String(err?.message || err);
      errors.push({ name, version, error: message });
      if (strictMode) {
        quarantined.push({
          name,
          version,
          reason: 'metadata_unavailable_strict_mode',
          error: message,
        });
      } else {
        allowed.push({
          name,
          version,
          reason: 'metadata_unavailable_non_strict_mode',
        });
      }
    }
  }

  let status = 'allow';
  let exitCode = 0;
  if (blocked.length > 0) {
    status = 'block';
    exitCode = 1;
  } else if (quarantined.length > 0) {
    status = 'quarantine';
    exitCode = 3;
  }

  const result = {
    status,
    mode: cfg.denylistOnlyMode ? 'denylist_only' : 'full',
    age_scope: cfg.ageScope,
    lockfile,
    policy_file: cfg.policyFile,
    cache_file: cfg.useCache ? cfg.cacheFile : '',
    summary: {
      total_packages: packages.length,
      age_checked_count: ageCheckedCount,
      blocked_count: blocked.length,
      quarantined_count: quarantined.length,
      allowed_count: allowed.length,
      errors_count: errors.length,
    },
    blocked,
    quarantined,
    allowed: allowed.slice(0, 25),
    errors,
  };

  await fsp.writeFile(cfg.resultFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  if (cfg.useCache) {
    await saveCache(cfg.cacheFile, cache);
  }

  log(JSON.stringify(result.summary, null, 2));

  if (status === 'block') {
    errorLog('BUILD BLOCKED: denylisted dependency detected');
  } else if (status === 'quarantine') {
    errorLog('BUILD QUARANTINED: dependency newer than policy threshold');
  } else {
    log('BUILD ALLOWED');
  }

  return { exitCode, result };
}
