'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { contentIntegrity } = require('../lib/content-integrity');
const { approvalChanges, expiryTime } = require('../lib/approval-policy');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { buildReview } = require('../lib/review');
const { selectBaseline } = require('../lib/comparison');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function fixture() {
  const root = mkTmpDir('content-approval');
  const pkg = writePackage(root, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': 'module.exports = 1;', 'data.txt': 'old' });
  const out = path.join(root, 'manifests');
  fs.mkdirSync(out);
  const baseline = path.join(root, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: {} }));
  function scan() {
    const manifest = scanPackageDir(pkg);
    manifest.installPath = 'pkg';
    fs.writeFileSync(path.join(out, 'pkg.json'), JSON.stringify(manifest));
    return manifest;
  }
  function review() {
    const result = runCli(['review', out, '--baseline', baseline, '--json']);
    assert.ok([0, 1].includes(result.status), result.stderr);
    return JSON.parse(result.stdout);
  }
  function approve(extra = []) {
    return runCli(['approve', out, '--baseline', baseline, '--id', review().entries[0].id, '--reason', 'Reviewed package files', ...extra]);
  }
  function lock() { return JSON.parse(fs.readFileSync(baseline)); }
  scan();
  return { root, pkg, out, baseline, scan, review, approve, lock };
}

test('content digest is deterministic across copies, ordering and timestamps', () => {
  const a = mkTmpDir('digest-a');
  const b = mkTmpDir('digest-b');
  for (const [root, files] of [[a, ['a', 'b']], [b, ['b', 'a']]]) {
    for (const file of files) fs.writeFileSync(path.join(root, file), file);
  }
  fs.utimesSync(path.join(b, 'a'), new Date(0), new Date(0));
  assert.equal(contentIntegrity(a).digest, contentIntegrity(b).digest);
});

test('digest includes binary bytes, filenames, deletion and package metadata', () => {
  const f = fixture();
  let previous = contentIntegrity(f.pkg).digest;
  for (const change of [
    () => fs.writeFileSync(path.join(f.pkg, 'asset.bin'), Buffer.from([0, 255, 1])),
    () => fs.writeFileSync(path.join(f.pkg, 'asset.bin'), Buffer.from([0, 255, 2])),
    () => fs.renameSync(path.join(f.pkg, 'asset.bin'), path.join(f.pkg, 'other.bin')),
    () => fs.unlinkSync(path.join(f.pkg, 'other.bin')),
    () => fs.appendFileSync(path.join(f.pkg, 'package.json'), '\n'),
  ]) {
    change();
    const current = contentIntegrity(f.pkg);
    assert.equal(current.complete, true);
    assert.notEqual(current.digest, previous);
    previous = current.digest;
  }
});

test('nested dependencies and Git directories are outside the package content scope', () => {
  const f = fixture();
  const before = contentIntegrity(f.pkg).digest;
  for (const name of ['node_modules', '.git']) {
    fs.mkdirSync(path.join(f.pkg, name));
    fs.writeFileSync(path.join(f.pkg, name, 'unrelated'), 'changed');
  }
  assert.equal(contentIntegrity(f.pkg).digest, before);
});

test('internal symlinks prevent content approval without reading their targets', () => {
  const f = fixture();
  fs.symlinkSync(f.root, path.join(f.pkg, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  const manifest = f.scan();
  assert.equal(manifest.contentIntegrity.complete, false);
  assert.equal(manifest.contentIntegrity.digest, undefined);
  assert.equal(f.review().entries[0].approvable, false);
  assert.match(f.approve().stderr, /complete content integrity/);
});

test('unreadable paths and oversized packages never publish a complete digest', () => {
  const f = fixture();
  const missing = contentIntegrity(path.join(f.root, 'missing'));
  assert.equal(missing.complete, false);
  assert.equal(missing.digest, undefined);
  const file = path.join(f.pkg, 'oversized.bin');
  fs.writeFileSync(file, '');
  const fd = fs.openSync(file, 'r+');
  try { fs.ftruncateSync(fd, 1024 * 1024 * 1024 + 1); }
  finally { fs.closeSync(fd); }
  const oversized = contentIntegrity(f.pkg);
  assert.equal(oversized.complete, false);
  assert.equal(oversized.digest, undefined);
  assert.match(oversized.error.reason, /byte budget/);
  fs.unlinkSync(file);
});

test('selective approval binds content even when capability evidence is unchanged', () => {
  const f = fixture();
  const before = f.scan();
  assert.equal(f.approve().status, 0);
  assert.equal(f.review().wouldFail, false);
  fs.writeFileSync(path.join(f.pkg, 'data.txt'), 'new');
  const after = f.scan();
  assert.deepEqual(after.capabilities, before.capabilities);
  const report = f.review();
  assert.equal(report.wouldFail, true);
  assert.equal(report.entries[0].changes[0].type, 'approval-content-changed');
  assert.equal(runCli(['check', f.out, '--baseline', f.baseline]).status, 1);
  const sarif = runCli(['review', f.out, '--baseline', f.baseline, '--format', 'sarif']);
  assert.equal(sarif.status, 1);
  assert.match(JSON.parse(sarif.stdout).runs[0].results[0].message.text, /content differs/);
  assert.equal(f.approve().status, 0);
  assert.equal(f.review().wouldFail, false);
  assert.equal(f.lock().approvals.length, 2);
});

test('changing non-source content invalidates an outstanding review ID', () => {
  const f = fixture();
  const id = f.review().entries[0].id;
  fs.writeFileSync(path.join(f.pkg, 'data.txt'), 'changed');
  f.scan();
  const result = runCli(['approve', f.out, '--baseline', f.baseline, '--id', id, '--reason', 'Stale review']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /stale/);
  assert.deepEqual(f.lock().packages, {});
});

test('expiry blocks at its exact boundary and permits explicit renewal', () => {
  const f = fixture();
  const expires = new Date(Date.now() + 86400000).toISOString();
  assert.equal(f.approve(['--expires', expires]).status, 0);
  let lock = f.lock();
  const approved = lock.packages.pkg[0];
  assert.equal(lock.approvals[0].expiresAt, expires);
  const current = f.scan();
  const time = Date.parse(expires);
  assert.deepEqual(approvalChanges(approved, current, time - 1), []);
  assert.equal(approvalChanges(approved, current, time)[0].type, 'approval-expired');
  approved.approval.expiresAt = '2000-01-01T00:00:00Z';
  fs.writeFileSync(f.baseline, JSON.stringify(lock));
  const report = f.review();
  assert.equal(report.wouldFail, true);
  assert.equal(report.entries[0].changes[0].type, 'approval-expired');
  assert.equal(runCli(['check', f.out, '--baseline', f.baseline]).status, 1);
  assert.equal(f.approve(['--expires', expires]).status, 0);
  assert.equal(f.review().wouldFail, false);
});

test('invalid and past expiry values leave the baseline untouched', () => {
  const f = fixture();
  const original = fs.readFileSync(f.baseline, 'utf8');
  for (const value of ['2000-01-01T00:00:00Z', '2099-02-30T00:00:00Z', '2099-01-01', 'tomorrow', '2099-01-01T00:00:00+00:00']) {
    assert.equal(f.approve(['--expires', value]).status, 2, value);
    assert.equal(fs.readFileSync(f.baseline, 'utf8'), original);
  }
  assert.equal(f.approve(['--expires']).status, 2);
  assert.ok(Number.isFinite(expiryTime('2099-01-01T00:00:00Z')));
});

test('missing digest, malformed policy and malformed expiry fail closed', () => {
  const f = fixture();
  assert.equal(f.approve().status, 0);
  const approved = f.lock().packages.pkg[0];
  const current = f.scan();
  delete current.contentIntegrity;
  assert.equal(diffManifests(approved, current).changes[0].type, 'approval-content-unavailable');
  approved.approval.expiresAt = 'invalid';
  assert.equal(diffManifests(approved, f.scan()).changes[0].type, 'approval-invalid');
  approved.approval = null;
  assert.equal(diffManifests(approved, f.scan()).changes[0].type, 'approval-invalid');
});

test('content approval cannot lend permissions to another installation or version', () => {
  const f = fixture();
  assert.equal(f.approve().status, 0);
  const approved = f.lock().packages.pkg[0];
  const current = f.scan();
  assert.equal(diffManifests(approved, { ...current, version: '2' }).escalated, true);
  assert.equal(diffManifests(approved, { ...current, installPath: 'nested/pkg' }).escalated, true);
  const other = JSON.parse(JSON.stringify(approved));
  other.approval.contentIntegrity.digest = 'a'.repeat(64);
  assert.equal(selectBaseline([approved, other], { ...current, installPath: 'elsewhere' }).kind, 'ambiguous');
});

test('general baselines retain capability comparison without forcing content pins', () => {
  const f = fixture();
  const before = f.scan();
  fs.writeFileSync(path.join(f.pkg, 'data.txt'), 'changed');
  const current = f.scan();
  assert.equal(diffManifests(before, current).escalated, false);
  delete before.contentIntegrity;
  before.schemaVersion = 5;
  assert.equal(diffManifests(before, current).escalated, false);
  const report = buildReview(new Map(), new Map([['pkg', [{ ...current, contentIntegrity: undefined }]]]));
  assert.equal(report.report.entries[0].approvable, false);
});
