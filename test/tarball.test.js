'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { unpackTarball, verifyIntegrity } = require('../lib/tarball');
const { scanLockfile } = require('../lib/lockfile-scan');
const { scanPackageDir } = require('../lib/scanner');
const { readManifests } = require('../lib/snapshot');
const { diffManifests, unionOfManifests, isAnalysisIncomplete } = require('../lib/diff');
const { selectBaseline } = require('../lib/comparison');
const { runCli } = require('./helpers');

const { header, tar, integrity, paxRecord } = require('./tarball-fixture');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'capsurface-tarball-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  let n = 0;
  return { root, archive(entries, end) {
    const data = zlib.gzipSync(tar(entries, end));
    const file = path.join(root, `archive-${n++}.tgz`); fs.writeFileSync(file, data);
    return { file, integrity: integrity(data), data };
  }, destination() { return fs.mkdtempSync(path.join(root, 'unpacked-')); } };
}
const pkg = { name: 'pkg', version: '1.0.0' };
const packageEntry = { name: 'package/package.json', body: JSON.stringify(pkg) };

test('verifies strongest integrity, checksum, PAX and GNU long names before extraction', (t) => {
  const f = fixture(t);
  const long = 'package/' + 'segment/'.repeat(20) + 'entry.js';
  const a = f.archive([packageEntry,
    { name: 'package/./same.js', body: 'same' }, { name: 'package/same.js', body: 'same' },
    { name: 'PaxHeader', type: 'x', body: paxRecord('path', long) }, { name: 'entry.js', body: "require('https');" },
    { name: '././@LongLink', type: 'L', body: 'package/other.js\0' }, { name: 'ignored.js', body: 'module.exports = 1;' },
  ]);
  const dest = f.destination(); const result = unpackTarball(a.file, a.integrity, dest);
  assert.deepEqual(result.pkg, pkg);
  assert.equal(fs.readFileSync(path.join(dest, long.slice(8)), 'utf8'), "require('https');");
  assert.ok(fs.existsSync(path.join(dest, 'other.js')));
  assert.equal(verifyIntegrity(a.data, integrity(a.data, 'sha256') + ' ' + a.integrity), a.integrity);
  assert.throws(() => verifyIntegrity(a.data, integrity(a.data, 'sha256') + ' ' + integrity(Buffer.from('wrong'))), /mismatch/);
  for (const bad of ['', 'sha1-' + 'a'.repeat(28), 'sha512-a===', a.integrity + '?option']) assert.throws(() => verifyIntegrity(a.data, bad));
});

for (const name of ['../outside', '/absolute', 'package/../outside', 'package/a/../../outside', 'package/C:/escape', 'package/a\\b', 'package/CON.txt', 'package/COM¹.txt', 'package/LPT²', 'package/NUL .txt', 'package/CONOUT$', 'package/end.', 'package/end ', 'package/a//b', 'package/node_modules/x/a.js', 'package/.git/config', 'package/control\nname']) {
  test(`rejects unsafe archive path: ${JSON.stringify(name)}`, (t) => {
    const f = fixture(t); const a = f.archive([packageEntry, { name, body: 'payload' }]); const dest = f.destination();
    assert.throws(() => unpackTarball(a.file, a.integrity, dest));
    assert.deepEqual(fs.readdirSync(dest), [], 'validation precedes writes');
  });
}

test('rejects links, special entries, duplicate and portable-colliding paths', (t) => {
  const f = fixture(t);
  const cases = [
    [{ name: 'package/link', type: '2', link: '../outside' }],
    [{ name: 'package/link', type: '1', link: 'package/package.json' }],
    [{ name: 'package/device', type: '3' }],
    [{ name: 'package/a', body: 'x' }, { name: 'package/a', body: 'y' }],
    [{ name: 'package/A/x', body: 'x' }, { name: 'package/a/y', body: 'y' }],
    [{ name: 'package/a', body: 'x' }, { name: 'package/a/b', body: 'y' }],
    [{ name: 'package/a/b', body: 'x' }, { name: 'package/a', body: 'y' }],
    [{ name: 'package/é', body: 'x' }, { name: 'package/e\u0301', body: 'y' }],
    [{ name: 'package/dir', type: '5', body: 'hidden' }],
  ];
  for (const entries of cases) {
    const a = f.archive([packageEntry, ...entries]); const dest = f.destination();
    assert.throws(() => unpackTarball(a.file, a.integrity, dest));
    assert.deepEqual(fs.readdirSync(dest), []);
  }
});

test('rejects malformed metadata, truncation, trailing archives and decompression beyond limits', (t) => {
  const f = fixture(t);
  for (const entries of [
    [{ name: 'Pax', type: 'x', body: '999 path=package/a\n' }],
    [{ name: 'Pax', type: 'x', body: paxRecord('GNU.sparse.size', '100') }],
    [{ name: 'Pax', type: 'x', body: paxRecord('path', '../escape') }, { name: 'package/a', body: 'x' }],
    [{ name: 'Pax', type: 'x', body: paxRecord('path', 'package/a') + paxRecord('path', 'package/b') }],
  ]) { const a = f.archive([packageEntry, ...entries]); assert.throws(() => unpackTarball(a.file, a.integrity, f.destination())); }
  for (const ending of [Buffer.alloc(0), Buffer.alloc(512), Buffer.concat([Buffer.alloc(1024), tar([{ name: 'package/hidden', body: 'x' }])])]) {
    const a = f.archive([packageEntry], ending); assert.throws(() => unpackTarball(a.file, a.integrity, f.destination()), /terminator/);
  }
  const a = f.archive([packageEntry]);
  assert.throws(() => unpackTarball(a.file, a.integrity, f.destination(), { expanded: 1024 }));
  assert.throws(() => unpackTarball(a.file, a.integrity, f.destination(), { compressed: 1 }), /limit/);
  const oversized = zlib.gzipSync(Buffer.concat([header('package/huge', 1024 * 1024 * 1024), Buffer.alloc(1024)]));
  fs.writeFileSync(a.file, oversized);
  assert.throws(() => unpackTarball(a.file, integrity(oversized), f.destination()), /size limit/);
  const corrupted = tar([packageEntry]); corrupted[100] ^= 1;
  const compressed = zlib.gzipSync(corrupted); fs.writeFileSync(a.file, compressed);
  assert.throws(() => unpackTarball(a.file, integrity(compressed), f.destination()), /checksum/);
});

test('scans lockfile archives before installation, preserves provenance and gates an upgrade', (t) => {
  const f = fixture(t);
  const marker = path.join(f.root, 'executed');
  const before = f.archive([packageEntry, { name: 'package/index.js', body: 'module.exports = 1;' }]);
  const after = f.archive([{ name: 'package/package.json', body: JSON.stringify({ ...pkg, version: '2.0.0', scripts: { install: 'node index.js' } }) },
    { name: 'package/index.js', body: `require('fs').writeFileSync(${JSON.stringify(marker)}, 'executed');\nrequire('child_process').exec('echo fixture');` }]);
  const map = path.join(f.root, 'archives.json'); const lock = path.join(f.root, 'package-lock.json');
  const url = 'https://registry.example/pkg.tgz';
  function scan(archive, version, destination) {
    fs.writeFileSync(map, JSON.stringify({ [url]: path.basename(archive.file) }));
    fs.writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { pkg: version } }, 'node_modules/pkg': { version, resolved: url, integrity: archive.integrity } } }));
    const result = runCli(['scan-lock', lock, '--tarballs', map, '--out', destination]);
    assert.equal(result.status, 0, result.stderr);
    return readManifests(destination)[0];
  }
  const oldDir = path.join(f.root, 'old'); const newDir = path.join(f.root, 'new');
  const old = scan(before, '1.0.0', oldDir); const current = scan(after, '2.0.0', newDir);
  assert.equal(fs.existsSync(marker), false);
  assert.equal(fs.existsSync(path.join(f.root, 'node_modules')), false);
  assert.equal(current.installPath, 'pkg');
  assert.equal(current.artifact.integrity, after.integrity);
  assert.equal(current.scanOrigin, 'npm-tarball-v1');
  assert.equal(diffManifests(old, current).escalated, true);
  const baseline = path.join(f.root, 'baseline.json');
  assert.equal(runCli(['baseline', oldDir, '--out', baseline]).status, 0);
  const review = runCli(['review', newDir, '--baseline', baseline, '--lockfile', lock, '--project-root', f.root, '--json']);
  assert.equal(review.status, 1, review.stderr);
  const report = JSON.parse(review.stdout);
  assert.equal(report.entries[0].provenance.status, 'resolved');
  assert.equal(report.entries[0].artifact.integrity, after.integrity);
  assert.equal(runCli(['approve', newDir, '--baseline', baseline, '--id', report.entries[0].id, '--reason', 'Reviewed archive changes']).status, 0);
  assert.equal(runCli(['check', newDir, '--baseline', baseline]).status, 0);
  const installedDir = f.destination(); unpackTarball(after.file, after.integrity, installedDir);
  const installed = scanPackageDir(installedDir); installed.installPath = 'pkg';
  assert.ok(diffManifests(current, installed).changes.some((c) => c.type === 'scan-origin-changed'));
  assert.ok(diffManifests(installed, current).changes.some((c) => c.type === 'scan-origin-changed'));
  assert.equal(isAnalysisIncomplete(unionOfManifests([current, installed])), true);
  assert.equal(selectBaseline([current, installed], { ...current, installPath: 'other' }).kind, 'ambiguous');
});

test('rejects missing, mismatched and unsupported lockfile inputs without publishing partial inventory', (t) => {
  const f = fixture(t); const a = f.archive([packageEntry]);
  const map = path.join(f.root, 'map.json'); const lock = path.join(f.root, 'lock.json'); const out = path.join(f.root, 'out');
  const url = 'https://registry.example/pkg.tgz'; fs.writeFileSync(map, JSON.stringify({ [url]: a.file }));
  const entry = { version: '1.0.0', resolved: url, integrity: a.integrity };
  for (const bad of [{ ...entry, integrity: integrity(Buffer.from('wrong')) }, { ...entry, version: '2' }, { ...entry, link: true }, { ...entry, resolved: 'git+https://repo' }, { ...entry, resolved: 'https://registry.example/missing.tgz' }, { ...entry, integrity: undefined }, { ...entry, inBundle: true }]) {
    fs.writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/pkg': entry, 'node_modules/second': bad } }));
    assert.throws(() => scanLockfile(lock, map, out));
    assert.throws(() => readManifests(out), /incomplete/);
  }
  for (const key of ['../pkg', 'node_modules/../pkg', 'packages/workspace']) {
    fs.writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: { '': {}, [key]: entry } }));
    assert.throws(() => scanLockfile(lock, map, out), /path/);
  }
  fs.writeFileSync(lock, JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
  assert.throws(() => scanLockfile(lock, map, out), /v2\/v3/);
});
