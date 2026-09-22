'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { tar, integrity } = require('./tarball-fixture');
const { readManifests } = require('../lib/snapshot');
const { runCli } = require('./helpers');

test('tarball deep scans retain operation evidence and cannot certify unsupported syntax', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'capsurface-tarball-deep-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const lock = path.join(root, 'lock.json'); const map = path.join(root, 'map.json'); const out = path.join(root, 'out');
  fs.writeFileSync(map, JSON.stringify({ 'https://registry.example/pkg.tgz': 'pkg.tgz' }));
  function scan(source) {
    const bytes = zlib.gzipSync(tar([{ name: 'package/package.json', body: '{"name":"pkg","version":"1"}' }, { name: 'package/index.ts', body: source }]));
    fs.writeFileSync(path.join(root, 'pkg.tgz'), bytes);
    fs.writeFileSync(lock, JSON.stringify({ lockfileVersion: 2, packages: { '': {}, 'node_modules/pkg': { version: '1', resolved: 'https://registry.example/pkg.tgz', integrity: integrity(bytes) } } }));
    return runCli(['scan-lock', lock, '--tarballs', map, '--out', out, '--deep']);
  }
  assert.equal(scan("const load = require as NodeRequire;\nload('https').request(url);").status, 0);
  const complete = readManifests(out)[0];
  assert.equal(complete.scanOrigin, 'npm-tarball-v1');
  assert.equal(complete.analysisProfile, 'source-ast-v1');
  assert.equal(complete.capabilities.networkRequest.evidence[0].line, 2);
  assert.equal(scan('namespace Unsupported { export const n = 1; }').status, 2);
  const incomplete = readManifests(out)[0];
  assert.equal(incomplete.astCoverage.complete, false);
  const baseline = path.join(root, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: { pkg: [complete] } }));
  assert.equal(runCli(['check', out, '--baseline', baseline]).status, 1);
});
