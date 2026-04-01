import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  extractDirectPackagesFromLock,
  extractPackagesFromLock,
  findFirstLockfile,
  isExactSemver,
  normalizePkgNameFromLockPath,
} from '../src/lib/lockfile-utils.js';

describe('lockfile-utils', () => {
  it('normalizes package name from lock path', () => {
    expect(normalizePkgNameFromLockPath('node_modules/@scope/pkg')).toBe('@scope/pkg');
    expect(normalizePkgNameFromLockPath('axios')).toBe('axios');
  });

  it('extracts packages from lockfile v2+ and v1 trees', () => {
    const lockData = {
      packages: {
        '': { dependencies: { axios: '1.14.1' } },
        'node_modules/axios': { name: 'axios', version: '1.14.1' },
        'node_modules/chalk': { version: '5.3.0' },
      },
      dependencies: {
        lodash: {
          version: '4.17.21',
          dependencies: {
            debug: { version: '4.3.4' },
          },
        },
      },
    };

    const packages = extractPackagesFromLock(lockData);
    expect(packages).toContainEqual(['axios', '1.14.1']);
    expect(packages).toContainEqual(['chalk', '5.3.0']);
    expect(packages).toContainEqual(['lodash', '4.17.21']);
    expect(packages).toContainEqual(['debug', '4.3.4']);
  });

  it('extracts only direct packages from lockfile', () => {
    const lockData = {
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { axios: '1.14.1' },
          optionalDependencies: { chalk: '5.3.0' },
        },
        'node_modules/axios': { version: '1.14.1' },
        'node_modules/chalk': { version: '5.3.0' },
        'node_modules/debug': { version: '4.3.4' },
      },
    };

    const direct = extractDirectPackagesFromLock(lockData);
    expect(direct).toContainEqual(['axios', '1.14.1']);
    expect(direct).toContainEqual(['chalk', '5.3.0']);
    expect(direct).not.toContainEqual(['debug', '4.3.4']);
  });

  it('falls back to lockfile v1 dependencies for direct packages', () => {
    const lockData = {
      dependencies: {
        axios: { version: '1.14.1' },
        chalk: { version: '5.3.0' },
      },
    };

    const direct = extractDirectPackagesFromLock(lockData);
    expect(direct).toContainEqual(['axios', '1.14.1']);
    expect(direct).toContainEqual(['chalk', '5.3.0']);
  });

  it('finds first lockfile in cwd', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lock-utils-'));
    const lockPath = path.join(tmpDir, 'npm-shrinkwrap.json');
    fs.writeFileSync(lockPath, '{}', 'utf8');

    const found = findFirstLockfile(tmpDir, fs.existsSync);
    expect(found).toBe(lockPath);
  });

  it('validates exact semver strings', () => {
    expect(isExactSemver('1.2.3')).toBe(true);
    expect(isExactSemver('^1.2.3')).toBe(false);
    expect(isExactSemver('1.2')).toBe(false);
  });
});
