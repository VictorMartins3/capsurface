'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { unpackTarball, readBounded } = require('./tarball');
const { scanPackageDir } = require('./scanner');
const { beginSnapshot } = require('./snapshot');
const { isAnalysisIncomplete } = require('./diff');
const object = (value) => value && typeof value === 'object' && !Array.isArray(value);

function removeDirectory(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) removeDirectory(file);
    else fs.unlinkSync(file);
  }
  fs.rmdirSync(directory);
}

function scanLockfile(lockfile, tarballMap, output, options = {}) {
  const snapshot = beginSnapshot(output);
  let temporary;
  try {
    const lock = JSON.parse(readBounded(lockfile, 32 * 1024 * 1024));
    const archives = JSON.parse(readBounded(tarballMap, 8 * 1024 * 1024));
    if (![2, 3].includes(lock.lockfileVersion) || !object(lock.packages) || !object(lock.packages[''])) throw new Error('scan-lock requires an npm lockfile v2/v3 with a root package entry');
    if (!object(archives)) throw new Error('tarball map must be an object mapping resolved URLs to local files');
    const entries = Object.entries(lock.packages).filter(([key]) => key !== '');
    if (entries.length > 10000) throw new Error('lockfile exceeds the 10,000-installation limit');
    for (const [key, pkg] of entries) {
      if (!/^(?:node_modules\/(?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+)(?:\/node_modules\/(?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+)*$/.test(key) || key.split('/').some((part) => part === '.' || part === '..')) throw new Error(`unsupported lockfile installation path: ${key}`);
      if (!object(pkg) || pkg.link || pkg.inBundle || typeof pkg.version !== 'string' || !pkg.version || typeof pkg.resolved !== 'string' || !/^https?:\/\//.test(pkg.resolved)) throw new Error(`unsupported registry package entry: ${key}`);
      if (!Object.prototype.hasOwnProperty.call(archives, pkg.resolved) || typeof archives[pkg.resolved] !== 'string' || !archives[pkg.resolved]) throw new Error(`missing local tarball for ${key}`);
    }
    if (options.deep) require('./ast-imports').loadParser();
    temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'capsurface-tarballs-'));
    let count = 0;
    let incomplete = 0;
    const budget = { compressed: 1024 * 1024 * 1024, expanded: 2 * 1024 * 1024 * 1024 };
    for (const [key, pkg] of entries) {
      if (budget.compressed <= 0 || budget.expanded <= 0) throw new Error('lockfile archive byte budget exhausted');
      const directory = path.join(temporary, 'package');
      fs.mkdirSync(directory, { mode: 0o700 });
      try {
        const archive = path.resolve(path.dirname(tarballMap), archives[pkg.resolved]);
        const unpacked = unpackTarball(archive, pkg.integrity, directory, budget);
        budget.compressed -= unpacked.compressedBytes;
        budget.expanded -= unpacked.expandedBytes;
        const expectedName = pkg.name || key.slice(key.lastIndexOf('node_modules/') + 13);
        if (unpacked.pkg.name !== expectedName || unpacked.pkg.version !== pkg.version) throw new Error(`tarball identity differs from lockfile: ${key}`);
        const manifest = scanPackageDir(directory, { deep: options.deep });
        manifest.installPath = key.slice(13);
        manifest.scanOrigin = 'npm-tarball-v1';
        manifest.artifact = { resolved: pkg.resolved, integrity: unpacked.integrity, lockfileVersion: lock.lockfileVersion };
        if (isAnalysisIncomplete(manifest)) incomplete++;
        const filename = 'tarball-' + crypto.createHash('sha256').update(key).digest('hex') + '.json';
        snapshot.write(filename, manifest);
        count++;
      } catch (error) {
        throw new Error(`${key}: ${error.message}`);
      } finally { removeDirectory(directory); }
    }
    snapshot.complete();
    return { count, incomplete };
  } finally {
    try { if (temporary) removeDirectory(temporary); }
    finally { snapshot.close(); }
  }
}

module.exports = { scanLockfile };
