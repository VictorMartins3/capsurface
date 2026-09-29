'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const yaml = require('yaml');
const { gzipSync } = require('zlib');
const { parsePnpm, pnpmEntries } = require('../lib/pnpm-lock');
const { scanLockfile } = require('../lib/lockfile-scan');
const { readManifests } = require('../lib/snapshot');
const { tar, integrity } = require('./tarball-fixture');
const { mkTmpDir, runCli } = require('./helpers');

function fixture() {
  const dir = mkTmpDir('pnpm');
  const lock = { lockfileVersion: '9.0', importers: {
    '.': { dependencies: { app: { specifier: 'workspace:*', version: 'link:apps/web' } } },
    'apps/web': { dependencies: {
      decoder: { specifier: 'npm:string_decoder@1.0.0', version: 'string_decoder@1.0.0' },
      '@types/babel__core': { specifier: '1.0.0', version: '1.0.0' },
      plugin: { specifier: '1.0.0', version: '1.0.0(string_decoder@1.0.0)' },
    } },
  }, packages: {}, snapshots: {} };
  const map = {};
  for (const name of ['string_decoder', '@types/babel__core', 'plugin']) {
    const key = `${name}@1.0.0`;
    const data = gzipSync(tar([
      { name: 'package/package.json', body: JSON.stringify({ name, version: '1.0.0', scripts: { postinstall: 'node index.js' } }) },
      { name: 'package/index.js', body: 'module.exports = 1;' },
    ]));
    const file = `${Object.keys(map).length}.tgz`;
    fs.writeFileSync(path.join(dir, file), data);
    map[key] = file;
    lock.packages[key] = { resolution: { integrity: integrity(data) } };
    lock.snapshots[key] = {};
  }
  lock.snapshots['plugin@1.0.0(string_decoder@1.0.0)'] = { dependencies: { string_decoder: '1.0.0' } };
  const lockfile = path.join(dir, 'pnpm-lock.yaml'), mapfile = path.join(dir, 'map.json');
  const out = path.join(dir, 'scan');
  function save() {
    fs.writeFileSync(lockfile, yaml.stringify(lock));
    fs.writeFileSync(mapfile, JSON.stringify(map));
  }
  save();
  return { dir, lock, map, lockfile, mapfile, out, save };
}

test('pnpm CLI scans aliases, underscore names, workspaces and distinct peer contexts offline', () => {
  const f = fixture();
  const result = runCli(['scan-lock', f.lockfile, '--tarballs', f.mapfile, '--out', f.out]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /workspace source files were not scanned/);
  const manifests = readManifests(f.out);
  assert.equal(manifests.length, 4);
  const decoder = manifests.find((m) => m.name === 'string_decoder');
  assert.equal(decoder.scanOrigin, 'pnpm-tarball-v1');
  assert.equal(decoder.artifact.resolved, undefined, 'do not invent a registry URL');
  assert.deepEqual(decoder.artifact.importers, [{ path: 'apps/web', alias: 'decoder', kind: 'dependencies' }]);
  assert.equal(decoder.artifact.parents[0].snapshotKey, 'plugin@1.0.0(string_decoder@1.0.0)');
  assert.equal(manifests.filter((m) => m.name === '@types/babel__core').length, 1);
  assert.equal(new Set(manifests.filter((m) => m.name === 'plugin').map((m) => m.installPath)).size, 2);
  const baseline = path.join(f.dir, 'baseline.json');
  assert.equal(runCli(['baseline', f.out, '--out', baseline]).status, 0);
  assert.equal(runCli(['check', f.out, '--baseline', baseline]).status, 0);
  // Change bytes and version: verified archives still require capability review.
  const bytes = gzipSync(tar([
    { name: 'package/package.json', body: JSON.stringify({ name: 'string_decoder', version: '2.0.0' }) },
    { name: 'package/index.js', body: "require('child_process').exec('echo unexpected');" },
  ]));
  fs.writeFileSync(path.join(f.dir, 'new.tgz'), bytes);
  delete f.lock.packages['string_decoder@1.0.0'];
  delete f.lock.snapshots['string_decoder@1.0.0'];
  f.lock.packages['string_decoder@2.0.0'] = { resolution: { integrity: integrity(bytes) } };
  f.lock.snapshots['string_decoder@2.0.0'] = {};
  f.lock.importers['apps/web'].dependencies.decoder.version = 'string_decoder@2.0.0';
  delete f.lock.snapshots['plugin@1.0.0(string_decoder@1.0.0)'];
  f.lock.snapshots['plugin@1.0.0(string_decoder@2.0.0)'] = { dependencies: { string_decoder: '2.0.0' } };
  f.lock.importers['apps/web'].dependencies.plugin.version = '1.0.0(string_decoder@2.0.0)';
  f.map['string_decoder@2.0.0'] = 'new.tgz';
  f.save();
  assert.equal(scanLockfile(f.lockfile, f.mapfile, f.out).count, 4);
  const review = runCli(['review', f.out, '--baseline', baseline]);
  assert.equal(review.status, 1, review.stderr);
  assert.ok(review.stdout.includes('pnpm snapshot: string\\_decoder@2'));
  assert.match(review.stdout, /Direct workspace reference: apps\/web via decoder/);
});

test('pnpm rejects unsupported graph entries instead of silently omitting packages', () => {
  const f = fixture();
  const cases = [
    (lock) => { lock.lockfileVersion = '6.0'; },
    (lock) => { lock.patchedDependencies = { plugin: { path: 'patch.diff' } }; },
    (lock) => { lock.packages['plugin@1.0.0'].resolution = { repo: 'git://example' }; },
    (lock) => { lock.packages['plugin@1.0.0'].resolution.integrity = null; },
    (lock) => { lock.importers['apps/web'].dependencies.plugin.version = 'file:../plugin'; },
    (lock) => { lock.importers['.'].dependencies.app.version = 'link:../../outside'; },
    (lock) => { lock.importers['apps/web'].optionalDependencies = { missing: { version: '1.0.0' } }; },
    (lock) => { delete lock.snapshots['@types/babel__core@1.0.0']; },
    (lock) => { lock.snapshots['missing@1.0.0'] = {}; },
    (lock) => { lock.importers['../outside'] = {}; },
    (lock) => { lock.importers['.'].configDependencies = { hook: '1.0.0' }; },
    (lock) => { lock.packages = null; },
  ];
  for (const mutate of cases) {
    const lock = JSON.parse(JSON.stringify(f.lock));
    mutate(lock);
    assert.throws(() => pnpmEntries(lock), undefined, mutate.toString());
  }
});

test('pnpm integrity, identity and missing-archive failures invalidate the snapshot', () => {
  const f = fixture();
  for (const failure of ['missing', 'integrity', 'identity']) {
    f.map['string_decoder@1.0.0'] = failure === 'missing' ? 'absent.tgz' : '0.tgz';
    f.lock.packages['string_decoder@1.0.0'].resolution.integrity = integrity(fs.readFileSync(path.join(f.dir, '0.tgz')));
    if (failure === 'integrity') f.lock.packages['string_decoder@1.0.0'].resolution.integrity = integrity(Buffer.from('wrong'));
    if (failure === 'identity') {
      f.map['string_decoder@1.0.0'] = '1.tgz';
      f.lock.packages['string_decoder@1.0.0'].resolution.integrity = integrity(fs.readFileSync(path.join(f.dir, '1.tgz')));
    }
    f.save();
    assert.throws(() => scanLockfile(f.lockfile, f.mapfile, f.out));
    assert.throws(() => readManifests(f.out), /incomplete/);
  }
});

test('YAML parsing rejects duplicate keys, aliases, tags and multiple documents', () => {
  for (const source of ['a: 1\na: 2', 'a: &a [1]\nb: *a', 'a: !custom 1', 'a: 1\n---\nb: 2']) {
    assert.throws(() => parsePnpm(source));
  }
  assert.deepEqual(parsePnpm("lockfileVersion: '9.0'\nimporters:\n  .: {}\n"), { lockfileVersion: '9.0', importers: { '.': {} } });
});

test('pnpm tarball scans retain deep analysis and cannot reuse installed-package baselines', () => {
  const f = fixture();
  const result = scanLockfile(f.lockfile, f.mapfile, f.out, { deep: true });
  assert.equal(result.incomplete, 0);
  const manifest = readManifests(f.out)[0];
  assert.equal(manifest.astCoverage.complete, true);
  const { diffManifests } = require('../lib/diff');
  assert.equal(diffManifests({ ...manifest, scanOrigin: 'installed-package-v1' }, manifest).escalated, true);
});

test('isolated YAML parsing enforces the pin, terminates a stalled parser and recovers', { timeout: 15000 }, () => {
  const dir = mkTmpDir('yaml-isolation');
  for (const file of ['pnpm-lock.js', 'yaml-worker.js']) {
    fs.copyFileSync(path.join(__dirname, '../lib', file), path.join(dir, file));
  }
  const parserDir = path.join(dir, 'node_modules/yaml');
  fs.mkdirSync(parserDir, { recursive: true });
  const metadata = path.join(parserDir, 'package.json');
  const implementation = path.join(parserDir, 'index.js');
  fs.writeFileSync(metadata, JSON.stringify({ version: '0.0.0' }));
  fs.writeFileSync(implementation, 'while (true) {}');
  const parse = require(path.join(dir, 'pnpm-lock')).parsePnpm;
  assert.throws(() => parse('a: 1'), /Install yaml@2\.9\.1/);
  fs.writeFileSync(metadata, JSON.stringify({ version: '2.9.1' }));
  assert.throws(() => parse('a: 1'), /exceeded its resource limit/);
  fs.writeFileSync(implementation, `module.exports = require(${JSON.stringify(require.resolve('yaml'))});`);
  assert.deepEqual(parse('a: 1'), { a: 1 });
});
