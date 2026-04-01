import path from 'node:path';

export const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json'];

export function normalizePkgNameFromLockPath(lockPath) {
  const marker = 'node_modules/';
  if (lockPath.includes(marker)) {
    return lockPath.split(marker).at(-1) || lockPath;
  }
  return lockPath;
}

export function extractPackagesFromLock(lockData) {
  const found = new Set();

  const lockPackages = lockData?.packages;
  if (lockPackages && typeof lockPackages === 'object') {
    for (const [pkgPath, meta] of Object.entries(lockPackages)) {
      if (pkgPath === '' || !meta || typeof meta !== 'object') {
        continue;
      }
      const name = meta.name || normalizePkgNameFromLockPath(pkgPath);
      const version = meta.version;
      if (name && version) {
        found.add(`${String(name)}@@${String(version)}`);
      }
    }
  }

  const walkDeps = (deps) => {
    for (const [name, meta] of Object.entries(deps || {})) {
      if (!meta || typeof meta !== 'object') {
        continue;
      }
      if (meta.version) {
        found.add(`${String(name)}@@${String(meta.version)}`);
      }
      if (meta.dependencies && typeof meta.dependencies === 'object') {
        walkDeps(meta.dependencies);
      }
    }
  };

  if (lockData?.dependencies && typeof lockData.dependencies === 'object') {
    walkDeps(lockData.dependencies);
  }

  return [...found]
    .map((entry) => {
      const [name, version] = entry.split('@@');
      return [name, version];
    })
    .sort(([aName, aVersion], [bName, bVersion]) => {
      if (aName === bName) {
        return aVersion.localeCompare(bVersion);
      }
      return aName.localeCompare(bName);
    });
}

export function extractDirectPackagesFromLock(lockData) {
  const found = new Set();

  const lockPackages = lockData?.packages;
  if (lockPackages && typeof lockPackages === 'object') {
    const rootMeta = lockPackages[''];
    if (rootMeta && typeof rootMeta === 'object') {
      for (const section of ['dependencies', 'optionalDependencies']) {
        const deps = rootMeta[section];
        if (!deps || typeof deps !== 'object') {
          continue;
        }
        for (const depName of Object.keys(deps)) {
          const depMeta = lockPackages[`node_modules/${depName}`];
          if (depMeta && typeof depMeta === 'object' && depMeta.version) {
            found.add(`${depName}@@${String(depMeta.version)}`);
          }
        }
      }
    }
  }

  const deps = lockData?.dependencies;
  if (deps && typeof deps === 'object') {
    for (const [name, meta] of Object.entries(deps)) {
      if (meta && typeof meta === 'object' && meta.version) {
        found.add(`${String(name)}@@${String(meta.version)}`);
      }
    }
  }

  return [...found]
    .map((entry) => {
      const [name, version] = entry.split('@@');
      return [name, version];
    })
    .sort(([aName, aVersion], [bName, bVersion]) => {
      if (aName === bName) {
        return aVersion.localeCompare(bVersion);
      }
      return aName.localeCompare(bName);
    });
}

export function findFirstLockfile(cwd, existsFn) {
  for (const lockfileName of LOCKFILE_NAMES) {
    const candidate = path.resolve(cwd, lockfileName);
    if (existsFn(candidate)) {
      return candidate;
    }
  }
  return '';
}

export function isExactSemver(value) {
  return /^\d+\.\d+\.\d+$/.test(String(value || ''));
}
