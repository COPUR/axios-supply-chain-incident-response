import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

export function buildRootAliases(roots) {
  const aliases = new Map();
  const normalized = [...new Set((roots || []).map((item) => path.resolve(String(item))))].sort();

  normalized.forEach((root, index) => {
    aliases.set(root, `<SCAN_ROOT_${index + 1}>`);
  });

  return aliases;
}

export function sanitizeText(value, rootAliases = new Map()) {
  let redacted = String(value || '');

  const replacements = [...rootAliases.entries()].sort((a, b) => b[0].length - a[0].length);
  for (const [root, alias] of replacements) {
    redacted = redacted.split(root).join(alias);
  }

  const home = os.homedir();
  if (home) {
    redacted = redacted.split(home).join('$HOME');
  }

  redacted = redacted.replace(/\/Users\/[^/]+/g, '/Users/<redacted>');
  redacted = redacted.replace(/\/home\/[^/]+/g, '/home/<redacted>');
  redacted = redacted.replace(/([A-Za-z]:\\Users\\)[^\\]+/g, '$1<redacted>');
  redacted = redacted.replace(/([A-Za-z]:\\Documents and Settings\\)[^\\]+/g, '$1<redacted>');

  return redacted;
}

export function anonymizePath(pathValue, repoRoot, repoAlias) {
  if (!pathValue) {
    return pathValue;
  }

  if (repoRoot) {
    const resolvedPath = (() => {
      try {
        return fs.realpathSync(pathValue);
      } catch {
        return path.resolve(pathValue);
      }
    })();
    const resolvedRoot = (() => {
      try {
        return fs.realpathSync(repoRoot);
      } catch {
        return path.resolve(repoRoot);
      }
    })();

    if (resolvedPath === resolvedRoot) {
      return repoAlias;
    }

    if (resolvedPath.startsWith(`${resolvedRoot}${path.sep}`)) {
      const rel = path.relative(resolvedRoot, resolvedPath).split(path.sep).join('/');
      return `${repoAlias}/${rel}`;
    }
  }

  return sanitizeText(pathValue);
}
