'use strict';

const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const object = (value) => value && typeof value === 'object' && !Array.isArray(value);
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const packageName = /^(?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+$/;

function parsePnpm(source) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (['NODE_OPTIONS', 'NODE_PATH'].includes(key.toUpperCase())) delete env[key];
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', path.join(__dirname, 'yaml-worker.js')], {
    input: source, encoding: 'utf8', cwd: __dirname, env, timeout: 5000,
    killSignal: 'SIGKILL', maxBuffer: 32 * 1024 * 1024, windowsHide: true,
  });
  if (child.error || child.status !== 0) throw new Error('pnpm YAML parser failed or exceeded its resource limit');
  let result;
  try { result = JSON.parse(child.stdout); } catch (_) { throw new Error('Invalid YAML worker response'); }
  if (result.error) throw new Error(result.error);
  return result.lock;
}

function identity(key) {
  const base = key.split('(')[0];
  const split = base.lastIndexOf('@');
  const name = base.slice(0, split), version = base.slice(split + 1);
  if (split < 1 || !packageName.test(name) || !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(version)) {
    throw new Error(`unsupported pnpm package identity: ${key}`);
  }
  let depth = 0;
  const suffix = key.slice(base.length);
  for (const char of suffix) {
    if (char === '(') depth++;
    else if (char === ')') { if (--depth < 0) throw new Error(`invalid pnpm peer context: ${key}`); }
    else if (!depth || !/[A-Za-z0-9.@_~+\/-]/.test(char)) throw new Error(`unsupported pnpm peer context: ${key}`);
  }
  if (depth || suffix.includes('patch_hash')) throw new Error(`unsupported pnpm peer context: ${key}`);
  return { base, name, version };
}

function pnpmEntries(lock) {
  if (!object(lock) || !['9.0', 9].includes(lock.lockfileVersion) || !object(lock.importers) || !own(lock.importers, '.')) {
    throw new Error('scan-lock requires a pnpm v9 lockfile with a root importer');
  }
  if (lock.patchedDependencies && Object.keys(lock.patchedDependencies).length) throw new Error('pnpm patched dependencies are unsupported');
  const packages = lock.packages === undefined ? {} : lock.packages;
  const snapshots = lock.snapshots === undefined ? {} : lock.snapshots;
  if (!object(packages) || !object(snapshots)) throw new Error('Invalid pnpm packages or snapshots');
  if (Object.keys(snapshots).length > 10000 || Object.keys(packages).length > 10000 || Object.keys(lock.importers).length > 10000) throw new Error('pnpm lockfile exceeds the 10,000-entry limit');
  const entries = new Map(), used = new Set();
  for (const key of Object.keys(packages)) {
    if (identity(key).base !== key) throw new Error(`unsupported pnpm package key: ${key}`);
  }
  for (const [key, snapshot] of Object.entries(snapshots)) {
    const id = identity(key), pkg = own(packages, id.base) && packages[id.base];
    if (!object(snapshot) || !object(pkg) || !object(pkg.resolution) || typeof pkg.resolution.integrity !== 'string' ||
        Object.keys(pkg.resolution).some((field) => !['integrity', 'tarball'].includes(field)) ||
        (pkg.resolution.tarball !== undefined && (typeof pkg.resolution.tarball !== 'string' || !/^https?:\/\//.test(pkg.resolution.tarball)))) {
      throw new Error(`unsupported pnpm registry resolution: ${key}`);
    }
    used.add(id.base);
    entries.set(key, { key, name: id.name, version: id.version, integrity: pkg.resolution.integrity,
      archiveKey: id.base, installPath: 'pnpm/' + crypto.createHash('sha256').update(key).digest('hex'),
      scanOrigin: 'pnpm-tarball-v1', artifact: { lockfileVersion: '9.0', packageId: id.base,
        snapshotKey: key, ...(pkg.resolution.tarball ? { resolved: pkg.resolution.tarball } : {}), importers: [], parents: [] } });
  }
  for (const key of Object.keys(packages)) if (!used.has(key)) throw new Error(`pnpm package has no snapshot: ${key}`);
  for (const [importer, value] of Object.entries(lock.importers)) {
    if (importer !== '.' && (!importer || importer.includes('\\') || importer.startsWith('/') || importer.includes(':') || importer.split('/').some((s) => !s || s === '.' || s === '..'))) throw new Error(`unsupported pnpm workspace path: ${importer}`);
    if (!object(value) || ['configDependencies', 'packageManagerDependencies'].some((key) => value[key] && Object.keys(value[key]).length)) throw new Error(`unsupported pnpm importer: ${importer}`);
  }
  let edgeCount = 0;
  function edges(from, data, importer) {
    for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      if (data[kind] === undefined) continue;
      if (!object(data[kind])) throw new Error(`invalid pnpm dependencies: ${from}`);
      for (const [alias, dependency] of Object.entries(data[kind])) {
        if (++edgeCount > 100000) throw new Error('pnpm dependency edge limit exceeded');
        const ref = importer && object(dependency) ? dependency.version : dependency;
        if (!packageName.test(alias) || typeof ref !== 'string') throw new Error(`invalid pnpm dependency: ${from}/${alias}`);
        if (ref.startsWith('link:') && importer) {
          const target = path.posix.normalize(path.posix.join(from, ref.slice(5)));
          if (!ref.slice(5) || ref.slice(5).startsWith('/') || !own(lock.importers, target)) throw new Error(`unresolved pnpm workspace link: ${from}/${alias}`);
          continue; // Workspace source is outside this registry-tarball scan.
        }
        const target = entries.get(`${alias}@${ref}`) || entries.get(ref);
        if (!target) throw new Error(`unresolved or unsupported pnpm dependency: ${from}/${alias} (${ref})`);
        target.artifact[importer ? 'importers' : 'parents'].push({ [importer ? 'path' : 'snapshotKey']: from, alias, kind });
      }
    }
  }
  for (const [key, value] of Object.entries(lock.importers)) edges(key, value, true);
  for (const [key, value] of Object.entries(snapshots)) edges(key, value, false);
  return [...entries.values()];
}

module.exports = { parsePnpm, pnpmEntries };
