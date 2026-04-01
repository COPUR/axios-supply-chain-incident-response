import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { buildRootAliases, sanitizeText } from './anonymize.js';
import {
  extractPackagesFromLock,
  isExactSemver,
  LOCKFILE_NAMES,
} from './lockfile-utils.js';

export const MALICIOUS_AXIOS_VERSIONS = new Set(['1.14.1', '0.30.4']);
export const MALICIOUS_DEPENDENCIES = {
  'plain-crypto-js': new Set(['4.2.1']),
};

export const SYSTEM_IOCS = [
  ['linux', '/tmp/ld.py'],
  ['darwin', '/Library/Caches/com.apple.act.mond'],
];

export const CI_FILE_CANDIDATES = new Set([
  '.gitlab-ci.yml',
  'Jenkinsfile',
  'azure-pipelines.yml',
  'bitbucket-pipelines.yml',
  'circle.yml',
  'buildspec.yml',
]);

export const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  '.next',
  '.turbo',
  '.venv',
  'venv',
  'coverage',
  '.idea',
  '.gradle',
]);

const PNPM_LOCKFILE_NAME = 'pnpm-lock.yaml';
const PNPM_WORKSPACE_FILE_NAME = 'pnpm-workspace.yaml';
const SEMVER_EXACT_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

export const TEXT_FILE_EXTENSIONS = new Set([
  '.env',
  '.txt',
  '.md',
  '.json',
  '.yaml',
  '.yml',
  '.js',
  '.cjs',
  '.mjs',
  '.ts',
  '.tsx',
  '.sh',
  '.properties',
  '.tf',
  '.ini',
  '.conf',
  '.cfg',
  '.dockerfile',
]);

export const SECRET_PATTERNS = {
  aws_access_key: /\bAKIA[0-9A-Z]{16}\b/g,
  aws_secret_key: /aws[^\n]{0,20}(secret|access)[^\n]{0,10}[=:]\s*["']?([A-Za-z0-9/+=]{40})/gi,
  npm_token: /\bnpm_[A-Za-z0-9]{36}\b/g,
  private_key: /-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) PRIVATE KEY-----/g,
};

export async function safeReadText(filePath) {
  try {
    return await fsp.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
}

function unquoteYamlScalar(value) {
  const trimmed = String(value || '').trim();
  if ((trimmed.startsWith("'") && trimmed.endsWith("'"))
    || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

export function parsePnpmLockPackages(lockText) {
  const found = new Set();

  for (const rawLine of String(lockText || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.endsWith(':') || line.startsWith('- ')) {
      continue;
    }

    let key = line.slice(0, -1);
    if (key.startsWith('/')) {
      key = key.slice(1);
    }

    const peerInfoIndex = key.indexOf('(');
    if (peerInfoIndex > 0) {
      key = key.slice(0, peerInfoIndex);
    }

    const atIndex = key.lastIndexOf('@');
    if (atIndex <= 0) {
      continue;
    }

    const name = key.slice(0, atIndex);
    const version = key.slice(atIndex + 1);
    if (!name || !SEMVER_EXACT_PATTERN.test(version)) {
      continue;
    }

    found.add(`${name}@@${version}`);
  }

  return [...found]
    .map((item) => item.split('@@'))
    .sort(([aName, aVersion], [bName, bVersion]) => {
      if (aName === bName) {
        return aVersion.localeCompare(bVersion);
      }
      return aName.localeCompare(bName);
    });
}

export function parsePnpmWorkspaceCatalogs(workspaceText) {
  const catalogs = {};
  let section = '';
  let activeCatalog = '';

  const ensureCatalog = (name) => {
    if (!catalogs[name]) {
      catalogs[name] = {};
    }
  };

  for (const rawLine of String(workspaceText || '').split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) {
      continue;
    }

    const indent = rawLine.match(/^ */)?.[0]?.length || 0;
    const line = rawLine.trim();

    if (indent === 0) {
      if (line === 'catalog:') {
        section = 'catalog';
        activeCatalog = 'default';
        ensureCatalog(activeCatalog);
      } else if (line === 'catalogs:') {
        section = 'catalogs';
        activeCatalog = '';
      } else {
        section = '';
        activeCatalog = '';
      }
      continue;
    }

    if (section === 'catalog') {
      if (indent < 2) {
        section = '';
        activeCatalog = '';
        continue;
      }

      if (indent === 2) {
        const match = line.match(/^(.+?):\s*(.+)$/);
        if (match) {
          const pkg = unquoteYamlScalar(match[1]);
          const version = unquoteYamlScalar(match[2]);
          if (pkg && version) {
            catalogs.default[pkg] = version;
          }
        }
      }
      continue;
    }

    if (section === 'catalogs') {
      if (indent < 2) {
        section = '';
        activeCatalog = '';
        continue;
      }

      if (indent === 2) {
        const catalogMatch = line.match(/^(.+?):\s*$/);
        if (catalogMatch) {
          activeCatalog = unquoteYamlScalar(catalogMatch[1]);
          ensureCatalog(activeCatalog);
        }
        continue;
      }

      if (indent === 4 && activeCatalog) {
        const pkgMatch = line.match(/^(.+?):\s*(.+)$/);
        if (pkgMatch) {
          const pkg = unquoteYamlScalar(pkgMatch[1]);
          const version = unquoteYamlScalar(pkgMatch[2]);
          if (pkg && version) {
            catalogs[activeCatalog][pkg] = version;
          }
        }
      }
    }
  }

  return catalogs;
}

export function parsePnpmLockCatalogs(lockText) {
  const catalogs = {};
  let inCatalogs = false;
  let activeCatalog = '';
  let activePackage = '';

  const ensureCatalog = (name) => {
    if (!catalogs[name]) {
      catalogs[name] = {};
    }
  };

  for (const rawLine of String(lockText || '').split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) {
      continue;
    }

    const indent = rawLine.match(/^ */)?.[0]?.length || 0;
    const line = rawLine.trim();

    if (indent === 0) {
      if (line === 'catalogs:') {
        inCatalogs = true;
        activeCatalog = '';
        activePackage = '';
      } else {
        inCatalogs = false;
        activeCatalog = '';
        activePackage = '';
      }
      continue;
    }

    if (!inCatalogs) {
      continue;
    }

    if (indent === 2) {
      const catalogMatch = line.match(/^(.+?):\s*$/);
      if (catalogMatch) {
        activeCatalog = unquoteYamlScalar(catalogMatch[1]);
        activePackage = '';
        ensureCatalog(activeCatalog);
      }
      continue;
    }

    if (indent === 4) {
      const packageMatch = line.match(/^(.+?):\s*$/);
      if (packageMatch) {
        activePackage = unquoteYamlScalar(packageMatch[1]);
      }
      continue;
    }

    if (indent === 6 && line.startsWith('version:') && activeCatalog && activePackage) {
      const version = unquoteYamlScalar(line.slice('version:'.length));
      if (version) {
        catalogs[activeCatalog][activePackage] = version;
      }
    }
  }

  return catalogs;
}

function findNearestFile(startDir, fileName) {
  let current = path.resolve(startDir);
  while (true) {
    const candidate = path.join(current, fileName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return '';
}

function mergeCatalogMaps(primary = {}, secondary = {}) {
  const merged = {};

  for (const [catalogName, values] of Object.entries(secondary)) {
    if (!merged[catalogName]) {
      merged[catalogName] = {};
    }
    Object.assign(merged[catalogName], values || {});
  }

  for (const [catalogName, values] of Object.entries(primary)) {
    if (!merged[catalogName]) {
      merged[catalogName] = {};
    }
    Object.assign(merged[catalogName], values || {});
  }

  return merged;
}

async function getProjectCatalogMap(projectRoot, catalogCache) {
  const pnpmWorkspacePath = findNearestFile(projectRoot, PNPM_WORKSPACE_FILE_NAME);
  const pnpmLockPath = findNearestFile(projectRoot, PNPM_LOCKFILE_NAME);
  const workspaceRoot = pnpmWorkspacePath
    ? path.dirname(pnpmWorkspacePath)
    : (pnpmLockPath ? path.dirname(pnpmLockPath) : '');

  if (!workspaceRoot) {
    return {};
  }

  if (catalogCache.has(workspaceRoot)) {
    return catalogCache.get(workspaceRoot);
  }

  const workspaceCatalogs = pnpmWorkspacePath
    ? parsePnpmWorkspaceCatalogs(await safeReadText(pnpmWorkspacePath))
    : {};

  const lockCatalogs = pnpmLockPath
    ? parsePnpmLockCatalogs(await safeReadText(pnpmLockPath))
    : {};

  const merged = mergeCatalogMaps(workspaceCatalogs, lockCatalogs);
  catalogCache.set(workspaceRoot, merged);
  return merged;
}

async function resolveCatalogVersion(projectRoot, packageName, declaredVersion, catalogCache) {
  const raw = String(declaredVersion || '');
  if (!raw.startsWith('catalog:')) {
    return '';
  }

  const requestedCatalog = raw.slice('catalog:'.length).trim() || 'default';
  const catalogs = await getProjectCatalogMap(projectRoot, catalogCache);
  return String(catalogs?.[requestedCatalog]?.[packageName] || '').trim();
}

export async function safeLoadJson(filePath) {
  const text = await safeReadText(filePath);
  if (text == null) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export async function walkFiles(rootPath) {
  const files = [];
  const root = path.resolve(rootPath);
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
        if (!SKIP_DIRS.has(entry.name)) {
          stack.push(candidate);
        }
      } else if (entry.isFile()) {
        files.push(candidate);
      }
    }
  }

  return files;
}

export async function discoverProjects(roots) {
  const found = new Set();

  for (const rootItem of roots) {
    const root = path.resolve(rootItem);
    let stat;
    try {
      stat = await fsp.stat(root);
    } catch {
      continue;
    }

    if (stat.isFile() && path.basename(root) === 'package.json') {
      found.add(path.dirname(root));
      continue;
    }

    if (!stat.isDirectory()) {
      continue;
    }

    const files = await walkFiles(root);
    for (const filePath of files) {
      if (path.basename(filePath) === 'package.json') {
        found.add(path.dirname(filePath));
      }
    }
  }

  return [...found].sort();
}

export async function extractAxiosFromPackageJson(packageJsonPath) {
  const data = await safeLoadJson(packageJsonPath);
  if (!data || typeof data !== 'object') {
    return [];
  }

  const versions = new Set();
  for (const section of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    const deps = data[section];
    if (deps && typeof deps === 'object' && deps.axios) {
      versions.add(String(deps.axios));
    }
  }

  return [...versions].sort();
}

export async function parseLockfiles(projectRoot) {
  const packages = new Set();
  const parsedLockfiles = [];
  const errors = [];

  for (const lockfileName of LOCKFILE_NAMES) {
    const lockfilePath = path.join(projectRoot, lockfileName);
    if (!fs.existsSync(lockfilePath)) {
      continue;
    }

    const data = await safeLoadJson(lockfilePath);
    if (data == null) {
      errors.push(`could_not_parse:${lockfilePath}`);
      continue;
    }

    parsedLockfiles.push(lockfilePath);
    const extracted = extractPackagesFromLock(data);
    for (const [name, version] of extracted) {
      packages.add(`${name}@@${version}`);
    }
  }

  const pnpmLockPath = findNearestFile(projectRoot, PNPM_LOCKFILE_NAME);
  if (pnpmLockPath && !parsedLockfiles.includes(pnpmLockPath)) {
    const pnpmLockText = await safeReadText(pnpmLockPath);
    if (pnpmLockText == null) {
      errors.push(`could_not_parse:${pnpmLockPath}`);
    } else {
      parsedLockfiles.push(pnpmLockPath);
      const pnpmPackages = parsePnpmLockPackages(pnpmLockText);
      for (const [name, version] of pnpmPackages) {
        packages.add(`${name}@@${version}`);
      }
    }
  }

  return {
    packages: [...packages].map((entry) => entry.split('@@')),
    parsedLockfiles,
    errors,
  };
}

export function detectSystemIocs({ env = process.env, existsFn = fs.existsSync } = {}) {
  const evidence = [];

  for (const [osName, iocPath] of SYSTEM_IOCS) {
    if (existsFn(iocPath)) {
      evidence.push(`ioc_file_present:${osName}:${iocPath}`);
    }
  }

  const programData = env.PROGRAMDATA || 'C:\\ProgramData';
  const windowsIoc = path.join(programData, 'wt.exe');
  if (existsFn(windowsIoc)) {
    evidence.push(`ioc_file_present:windows:${windowsIoc}`);
  }

  return evidence;
}

export function looksTextual(filePath) {
  const name = path.basename(filePath);
  const lowerName = name.toLowerCase();
  if (lowerName.startsWith('.env')) {
    return true;
  }

  if (TEXT_FILE_EXTENSIONS.has(path.extname(lowerName))) {
    return true;
  }

  return name === 'Dockerfile' || name === 'dockerfile' || name === 'Jenkinsfile';
}

export async function findCiPipelinesWithNpm(roots) {
  const hits = new Set();
  const pattern = /\bnpm\s+(ci|install)\b/;

  for (const rootItem of roots) {
    const root = path.resolve(rootItem);
    const files = await walkFiles(root);
    for (const filePath of files) {
      const name = path.basename(filePath);
      const inGitHubWorkflow = filePath.includes(`${path.sep}.github${path.sep}workflows${path.sep}`);
      const ciCandidate = CI_FILE_CANDIDATES.has(name)
        || (inGitHubWorkflow && (name.endsWith('.yml') || name.endsWith('.yaml')));

      if (!ciCandidate) {
        continue;
      }

      const content = await safeReadText(filePath);
      if (content && pattern.test(content)) {
        hits.add(filePath);
      }
    }
  }

  return [...hits].sort();
}

export async function huntProbableSecrets(roots, maxHits = 100) {
  const hits = new Set();

  for (const rootItem of roots) {
    const root = path.resolve(rootItem);
    const files = await walkFiles(root);

    for (const filePath of files) {
      if (!looksTextual(filePath)) {
        continue;
      }

      const content = await safeReadText(filePath);
      if (content == null) {
        continue;
      }

      if (path.basename(filePath).startsWith('.env')) {
        hits.add(`env_file_present:${filePath}`);
      }

      for (const [label, regex] of Object.entries(SECRET_PATTERNS)) {
        regex.lastIndex = 0;
        if (regex.test(content)) {
          hits.add(`${label}:${filePath}`);
        }
      }

      if (hits.size >= maxHits) {
        return [...hits].sort().slice(0, maxHits);
      }
    }
  }

  return [...hits].sort();
}

export function inferLateralPaths(impactedProjects, ciHits, secretHits) {
  const paths = [];

  if (impactedProjects.length > 0) {
    paths.push('Compromised dependency execution during install can execute arbitrary code in developer/CI context.');
  }

  if (ciHits.length > 0) {
    paths.push('CI pipelines invoking npm install/npm ci may expose runner identity, repository tokens, and artifact credentials.');
  }

  if (secretHits.length > 0) {
    paths.push('Probable secret exposure increases risk of cloud account takeover, source control abuse, and registry poisoning.');
  }

  if (impactedProjects.length > 0 && ciHits.length > 0) {
    paths.push('Potential movement path: compromised package -> CI runner -> secret exfiltration -> container registry/IaC/prod deployment chain.');
  }

  return paths;
}

export function inferProductionExposure(directImpactedProjects, uncertaintyImpactedProjects, ciHits, secretHits) {
  if (directImpactedProjects.length > 0 && ciHits.length > 0 && secretHits.length > 0) {
    return 'Critical';
  }
  if (directImpactedProjects.length > 0 && ciHits.length > 0) {
    return 'High';
  }
  if (directImpactedProjects.length > 0) {
    return 'Medium';
  }
  if (uncertaintyImpactedProjects.length > 0 && ciHits.length > 0 && secretHits.length > 0) {
    return 'High';
  }
  if (uncertaintyImpactedProjects.length > 0) {
    return 'Medium';
  }
  return 'Low';
}

export function computeRiskLevel(directIocs, directImpactedProjects, uncertaintyImpactedProjects, ciHits, secretHits) {
  const maliciousHit = directImpactedProjects.length > 0;
  const uncertaintyHit = uncertaintyImpactedProjects.length > 0;
  const incidentSignal = directIocs.length > 0 || maliciousHit || uncertaintyHit;

  if (!incidentSignal) {
    return 'Low';
  }

  if (directIocs.length > 0 || (maliciousHit && ciHits.length > 0)) {
    return 'Critical';
  }
  if (maliciousHit) {
    return 'High';
  }
  if (uncertaintyHit && ciHits.length > 0 && secretHits.length > 0) {
    return 'High';
  }
  if (uncertaintyHit || secretHits.length > 0) {
    return 'Medium';
  }
  return 'Low';
}

export function computeConfidence(affected, directIocs, impactedProjects, scanErrors) {
  const directProjectIoc = impactedProjects.some(
    (project) => project.malicious_axios_versions.length > 0
      || project.malicious_dependency_hits.length > 0
      || project.plain_crypto_node_modules_present,
  );

  const uncertaintyOnly = affected && !(directIocs.length > 0 || directProjectIoc);

  if (scanErrors.length > 0) {
    return 'Low';
  }
  if (directIocs.length > 0 || directProjectIoc) {
    return 'High';
  }
  if (uncertaintyOnly) {
    return 'Medium';
  }
  return 'High';
}

export function buildImmediateActions(affected) {
  if (!affected) {
    return [
      'Keep monitoring; no direct indicators found in scanned scope.',
      'Run the scan across all remaining repositories and build environments to confirm global status.',
      'Apply preventive controls now (exact pinning, package age gating, SBOM policy checks).',
    ];
  }

  return [
    'Freeze all deployments and disable release promotion immediately.',
    'Isolate all hosts and CI runners that executed npm install/npm ci during exposure window.',
    'Revoke and rotate all credentials: AWS keys, SSH keys, npm tokens, CI tokens, API secrets, .env secrets.',
    'Audit CI/CD logs for npm install/npm ci executions and map impacted commits, runners, and artifacts.',
    'Invalidate and re-issue artifact registry credentials; quarantine images/build artifacts from impacted pipelines.',
    'Open security incident and preserve forensic logs before rebuild actions.',
  ];
}

export function buildRemediationPlan(affected) {
  if (!affected) {
    return [
      'Establish an immutable rebuild procedure and test it quarterly.',
      'Convert CI pipelines to deterministic installs with script restrictions.',
      'Treat this scan as baseline and run scheduled recurring scans.',
    ];
  }

  return [
    '1) Declare incident severity High/Critical and assume compromise where visibility is incomplete.',
    '2) Stop all deployment and package-promotion pipelines that consumed Node dependencies in exposure window.',
    '3) Isolate compromised/suspected systems (dev workstations, CI runners, build agents).',
    '4) Capture forensic artifacts (runner logs, host telemetry, lockfiles, pipeline metadata) before wipe.',
    '5) Revoke all long-lived and short-lived credentials and tokens across cloud, SCM, CI, package registries.',
    '6) Rebuild systems from trusted immutable images; do not perform in-place cleaning.',
    '7) Recreate secrets from clean control plane and enforce least-privilege scopes.',
    '8) Re-run full scan and validate zero indicators before restoring deployment paths.',
    '9) Review lateral movement evidence and production access logs for unauthorized activity.',
    '10) Close incident only after security sign-off with documented evidence and timeline.',
  ];
}

export function buildPreventiveMeasures() {
  return [
    'Enforce exact dependency version pinning in package.json and lockfiles (no caret ^ or tilde ~).',
    'Use npm ci --ignore-scripts by default in CI; allow scripts only in explicitly approved jobs.',
    'Implement dependency allowlist and denylist policy with central governance.',
    'Block packages younger than 48 hours unless manually approved by security.',
    'Generate SBOM on every build and enforce policy checks before deploy.',
    'Use ephemeral CI runners with no persistent disk and strong network egress restrictions.',
    'Isolate secrets per pipeline/job; use short-lived credentials from a secret manager.',
    'Add artifact quarantine and promotion gates integrated with security findings.',
  ];
}

export function projectIsImpacted(project) {
  return project.malicious_axios_versions.length > 0
    || project.malicious_dependency_hits.length > 0
    || project.plain_crypto_node_modules_present
    || project.uncertainty_flags.length > 0;
}

export async function scanProjects(projects) {
  const findings = [];
  const scanErrors = [];
  const catalogCache = new Map();

  for (const projectRoot of projects) {
    const finding = {
      root: projectRoot,
      axios_versions_in_lock: [],
      axios_declared_versions: [],
      malicious_axios_versions: [],
      malicious_dependency_hits: [],
      plain_crypto_node_modules_present: false,
      uncertainty_flags: [],
      lockfile_paths: [],
    };

    const packageJsonPath = path.join(projectRoot, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      finding.axios_declared_versions = await extractAxiosFromPackageJson(packageJsonPath);
    }

    const parsed = await parseLockfiles(projectRoot);
    finding.lockfile_paths = parsed.parsedLockfiles;
    scanErrors.push(...parsed.errors);

    const axiosVersions = [...new Set(
      parsed.packages
        .filter(([name]) => name === 'axios')
        .map(([, version]) => version),
    )].sort();

    finding.axios_versions_in_lock = axiosVersions;
    finding.malicious_axios_versions = axiosVersions.filter((version) => MALICIOUS_AXIOS_VERSIONS.has(version));

    for (const [depName, badVersions] of Object.entries(MALICIOUS_DEPENDENCIES)) {
      const depVersions = [...new Set(
        parsed.packages
          .filter(([name]) => name === depName)
          .map(([, version]) => version),
      )].sort();

      for (const version of depVersions) {
        if (badVersions.has(version)) {
          finding.malicious_dependency_hits.push(`${depName}@${version}`);
        }
      }
    }

    const plainCryptoPath = path.join(projectRoot, 'node_modules', 'plain-crypto-js');
    finding.plain_crypto_node_modules_present = fs.existsSync(plainCryptoPath);

    if (finding.axios_declared_versions.length > 0 && finding.axios_versions_in_lock.length === 0) {
      finding.uncertainty_flags.push('axios_declared_but_no_resolved_lockfile_version');
    }

    for (const declaredVersion of finding.axios_declared_versions) {
      if (declaredVersion.startsWith('catalog:')) {
        const catalogResolvedVersion = await resolveCatalogVersion(
          projectRoot,
          'axios',
          declaredVersion,
          catalogCache,
        );
        if (!catalogResolvedVersion) {
          finding.uncertainty_flags.push(`unresolved_catalog_spec:${declaredVersion}`);
        } else {
          if (!finding.axios_versions_in_lock.includes(catalogResolvedVersion)) {
            finding.axios_versions_in_lock.push(catalogResolvedVersion);
          }
          if (MALICIOUS_AXIOS_VERSIONS.has(catalogResolvedVersion)) {
            finding.malicious_axios_versions.push(catalogResolvedVersion);
          }
          if (!isExactSemver(catalogResolvedVersion)) {
            finding.uncertainty_flags.push(`non_exact_catalog_resolution:${declaredVersion}->${catalogResolvedVersion}`);
          }
        }
      } else if (MALICIOUS_AXIOS_VERSIONS.has(declaredVersion)) {
        finding.malicious_axios_versions.push(declaredVersion);
      } else if (!isExactSemver(declaredVersion)) {
        finding.uncertainty_flags.push(`non_exact_axios_version_spec:${declaredVersion}`);
      }
    }

    if (parsed.errors.length > 0) {
      finding.uncertainty_flags.push('lockfile_parse_error');
    }

    if (
      finding.axios_versions_in_lock.length > 0
      || finding.axios_declared_versions.length > 0
      || finding.malicious_dependency_hits.length > 0
      || finding.plain_crypto_node_modules_present
      || finding.uncertainty_flags.length > 0
    ) {
      finding.axios_versions_in_lock = [...new Set(finding.axios_versions_in_lock)].sort();
      finding.malicious_axios_versions = [...new Set(finding.malicious_axios_versions)].sort();
      finding.malicious_dependency_hits = [...new Set(finding.malicious_dependency_hits)].sort();
      finding.uncertainty_flags = [...new Set(finding.uncertainty_flags)].sort();
      findings.push(finding);
    }
  }

  return { findings, scanErrors };
}

export async function runScan(roots, options = {}) {
  const normalizedRoots = roots.map((root) => path.resolve(root));
  const { existsFn = fs.existsSync, env = process.env } = options;

  const projects = await discoverProjects(normalizedRoots);
  const { findings: projectFindings, scanErrors } = await scanProjects(projects);

  const directSystemIocs = detectSystemIocs({ env, existsFn });
  const impactedProjects = projectFindings.filter((project) => projectIsImpacted(project));

  const directImpactedProjects = impactedProjects.filter(
    (project) => project.malicious_axios_versions.length > 0
      || project.malicious_dependency_hits.length > 0
      || project.plain_crypto_node_modules_present,
  );

  const uncertaintyImpactedProjects = impactedProjects.filter(
    (project) => project.uncertainty_flags.length > 0
      && project.malicious_axios_versions.length === 0
      && project.malicious_dependency_hits.length === 0
      && !project.plain_crypto_node_modules_present,
  );

  const ciHits = await findCiPipelinesWithNpm(normalizedRoots);
  const secretHits = await huntProbableSecrets(normalizedRoots);

  const evidence = [];
  evidence.push(...directSystemIocs);

  for (const project of projectFindings) {
    if (project.axios_versions_in_lock.length > 0) {
      evidence.push(`axios_versions:${project.root}:${project.axios_versions_in_lock.join(',')}`);
    }
    if (project.malicious_axios_versions.length > 0) {
      evidence.push(`malicious_axios:${project.root}:${project.malicious_axios_versions.join(',')}`);
    }
    if (project.malicious_dependency_hits.length > 0) {
      evidence.push(`malicious_dependency:${project.root}:${project.malicious_dependency_hits.join(',')}`);
    }
    if (project.plain_crypto_node_modules_present) {
      evidence.push(`plain_crypto_js_present:${project.root}`);
    }
    for (const flag of project.uncertainty_flags) {
      evidence.push(`uncertainty:${project.root}:${flag}`);
    }
  }

  for (const scanError of scanErrors) {
    evidence.push(`scan_error:${scanError}`);
  }

  const affected = directSystemIocs.length > 0
    || directImpactedProjects.length > 0
    || uncertaintyImpactedProjects.length > 0;

  let affectedBasis = 'no_compromise_indicators';
  if (directSystemIocs.length > 0 || directImpactedProjects.length > 0) {
    affectedBasis = 'direct_compromise_detected';
  } else if (uncertaintyImpactedProjects.length > 0) {
    affectedBasis = 'assumed_compromise_due_to_uncertainty';
  }

  const directCompromiseEvidence = [...new Set(evidence.filter((item) => item.startsWith('ioc_file_present:')
    || item.startsWith('malicious_axios:')
    || item.startsWith('malicious_dependency:')
    || item.startsWith('plain_crypto_js_present:')))].sort();

  const uncertaintyEvidence = [...new Set(evidence.filter((item) => item.startsWith('uncertainty:')
    || item.startsWith('scan_error:')))].sort();

  const confidence = computeConfidence(affected, directSystemIocs, projectFindings, scanErrors);
  const riskLevel = computeRiskLevel(
    directSystemIocs,
    directImpactedProjects,
    uncertaintyImpactedProjects,
    ciHits,
    secretHits,
  );

  const lateralMovementPaths = inferLateralPaths(impactedProjects, ciHits, secretHits);
  const productionExposureRisk = inferProductionExposure(
    directImpactedProjects,
    uncertaintyImpactedProjects,
    ciHits,
    secretHits,
  );

  return {
    affected,
    affected_basis: affectedBasis,
    confidence,
    evidence: [...new Set(evidence)].sort(),
    direct_compromise_evidence: directCompromiseEvidence,
    uncertainty_evidence: uncertaintyEvidence,
    risk_level: riskLevel,
    impacted_projects: impactedProjects,
    direct_impacted_projects: directImpactedProjects,
    uncertainty_impacted_projects: uncertaintyImpactedProjects,
    ci_pipelines_with_npm_install: ciHits,
    probable_secret_exposures: secretHits,
    lateral_movement_paths: lateralMovementPaths,
    production_exposure_risk: productionExposureRisk,
    immediate_actions: buildImmediateActions(affected),
    remediation_plan: buildRemediationPlan(affected),
    preventive_measures: buildPreventiveMeasures(),
  };
}

export function anonymizeProjectFinding(project, rootAliases) {
  return {
    ...project,
    root: sanitizeText(project.root, rootAliases),
    lockfile_paths: project.lockfile_paths.map((item) => sanitizeText(item, rootAliases)),
    uncertainty_flags: project.uncertainty_flags.map((item) => sanitizeText(item, rootAliases)),
    malicious_dependency_hits: project.malicious_dependency_hits.map((item) => sanitizeText(item, rootAliases)),
  };
}

export function anonymizeScanResult(result, roots) {
  const aliases = buildRootAliases(roots.map((root) => path.resolve(root)));

  return {
    ...result,
    evidence: result.evidence.map((item) => sanitizeText(item, aliases)),
    direct_compromise_evidence: result.direct_compromise_evidence.map((item) => sanitizeText(item, aliases)),
    uncertainty_evidence: result.uncertainty_evidence.map((item) => sanitizeText(item, aliases)),
    impacted_projects: result.impacted_projects.map((project) => anonymizeProjectFinding(project, aliases)),
    direct_impacted_projects: result.direct_impacted_projects.map((project) => anonymizeProjectFinding(project, aliases)),
    uncertainty_impacted_projects: result.uncertainty_impacted_projects.map((project) => anonymizeProjectFinding(project, aliases)),
    ci_pipelines_with_npm_install: result.ci_pipelines_with_npm_install.map((item) => sanitizeText(item, aliases)),
    probable_secret_exposures: result.probable_secret_exposures.map((item) => sanitizeText(item, aliases)),
    lateral_movement_paths: result.lateral_movement_paths.map((item) => sanitizeText(item, aliases)),
  };
}

export function renderMarkdown(result) {
  const impactedPaths = result.impacted_projects.map((project) => project.root);
  const directImpactedPaths = result.direct_impacted_projects.map((project) => project.root);
  const uncertaintyImpactedPaths = result.uncertainty_impacted_projects.map((project) => project.root);

  const evidenceLines = result.evidence.length > 0
    ? [...result.evidence]
    : ['No direct indicators found in scanned scope.'];

  evidenceLines.unshift(`affected_basis:${result.affected_basis}`);

  if (impactedPaths.length > 0) {
    evidenceLines.push(`Impacted repositories: ${impactedPaths.join(', ')}`);
  }
  if (directImpactedPaths.length > 0) {
    evidenceLines.push(`Directly compromised repositories: ${directImpactedPaths.join(', ')}`);
  }
  if (uncertaintyImpactedPaths.length > 0) {
    evidenceLines.push(`Uncertainty-driven repositories (assumed compromised): ${uncertaintyImpactedPaths.join(', ')}`);
  }
  if (result.ci_pipelines_with_npm_install.length > 0) {
    evidenceLines.push(`CI/CD pipelines with npm install/npm ci: ${result.ci_pipelines_with_npm_install.join(', ')}`);
  }
  if (result.probable_secret_exposures.length > 0) {
    evidenceLines.push(`Probable credential/secret findings: ${result.probable_secret_exposures.slice(0, 15).join(', ')}`);
  }

  const lines = [];

  lines.push('## SECTION 1: Detection Result');
  lines.push('');
  lines.push(`- Status: ${result.affected ? 'Affected' : 'Not affected'}`);
  lines.push(`- Evidence: Confidence=${result.confidence}; Basis=${result.affected_basis}`);
  for (const item of evidenceLines) {
    lines.push(`  - ${item}`);
  }

  lines.push('');
  lines.push('## SECTION 2: Risk Level');
  lines.push('');
  lines.push(`- ${result.risk_level}`);

  lines.push('');
  lines.push('## SECTION 3: Immediate Actions');
  lines.push('');
  for (const item of result.immediate_actions) {
    lines.push(`- ${item}`);
  }

  lines.push('');
  lines.push('## SECTION 4: Remediation Plan');
  lines.push('');
  for (const item of result.remediation_plan) {
    lines.push(`- ${item}`);
  }

  lines.push('');
  lines.push('## SECTION 5: Preventive Measures');
  lines.push('');
  for (const item of result.preventive_measures) {
    lines.push(`- ${item}`);
  }

  return `${lines.join('\n')}\n`;
}
