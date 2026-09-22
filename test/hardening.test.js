'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { discoverPackageDirs } = require('../lib/discovery');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function scanSource(source, extra = {}, files = {}) {
  return scanPackageDir(writePackage(mkTmpDir('hardening'), 'pkg', { name: 'p', version: '1.0.0', ...extra }, {
    'index.js': source, ...files,
  }));
}

// Inject a filesystem failure deterministically: chmod-based tests pass
// accidentally under root and do not behave the same way on Windows.
function withFailure(method, target, action, code = 'EACCES') {
  const original = fs[method];
  fs[method] = function (file, ...args) {
    if (String(file) === target) throw Object.assign(new Error(code), { code });
    return original.call(this, file, ...args);
  };
  try { return action(); } finally { fs[method] = original; }
}

describe('indicator collection is independent of evidence quotas', () => {
  const urls = Array.from({ length: 20 }, (_, i) => `const u${i} = 'https://host${i}.example.com';`).join('\n');
  const vars = Array.from({ length: 40 }, (_, i) => `process.env.SETTING_${i};`).join('\n');

  test('a new host after 20 existing URLs still escalates', () => {
    const source = `require('https'); process.env.NPM_TOKEN;\n${urls}`;
    const before = scanSource(source);
    const after = scanSource(`${source}\nconst endpoint = 'https://new.example.net';`);
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
    assert.ok(report.changes.some((c) => c.type === 'new-network-endpoints' && c.detail.includes('new.example.net')));
  });

  test('a service credential after 40 ordinary env vars still escalates', () => {
    const before = scanSource(vars);
    const after = scanSource(`${vars}\nprocess.env.STRIPE_SECRET_KEY;`);
    assert.equal(diffManifests(before, after).escalated, true);
    assert.ok(after.capabilities.env.vars.includes('STRIPE_SECRET_KEY'));
  });

  test('extra ordinary variables and documentation paths remain nonblocking', () => {
    const before = scanSource(`${urls}\n${vars}`);
    const after = scanSource(`${urls}\n${vars}\nprocess.env.NO_COLOR;\nconst doc = 'https://host0.example.com/new';`);
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
    assert.equal(report.changes.filter((c) => c.type.startsWith('new-')).length, 2);
  });

  test('script commands and source share a complete, deduplicated indicator set', () => {
    const manifest = scanSource(`${urls}\n${vars}`, {
      scripts: { postinstall: `node -e "${urls}\n${vars}\nprocess.env.SERVICE_TOKEN;"` },
    }, { 'other.js': `${urls}\n${vars}\nconst extra='https://another.example.net';` });
    assert.equal(manifest.capabilities.network.endpoints.length, 21);
    assert.equal(manifest.capabilities.env.vars.length, 41);
    assert.equal(manifest.coverage.complete, true);
  });

  for (const kind of ['endpoints', 'env-vars']) {
    test(`${kind} resource exhaustion stays bounded and cannot be approved away`, () => {
      const source = Array.from({ length: 10001 }, (_, i) => kind === 'endpoints'
        ? `const u${i}='https://h${i}.example.com';`
        : `process.env.VAR_${i};`).join('\n');
      const manifest = scanSource(source);
      const values = kind === 'endpoints' ? manifest.capabilities.network.endpoints : manifest.capabilities.env.vars;
      assert.equal(values.length, 10000);
      assert.equal(manifest.coverage.complete, false);
      assert.ok(manifest.capabilities.analysisIncomplete.reasons.includes(`${kind}-limit`));
      assert.equal(diffManifests(manifest, manifest).escalated, true);
    });
  }

  test('indicator text also has a memory budget, independent of the entry count', () => {
    const manifest = scanSource(`const u='https://host.example.com/${'a'.repeat(1024 * 1024)}';`);
    assert.equal(manifest.capabilities.network.endpoints.length, 0);
    assert.equal(manifest.coverage.complete, false);
    assert.ok(manifest.capabilities.analysisIncomplete.reasons.includes('endpoints-limit'));
  });
});

describe('coverage records actual reads and errors', () => {
  for (const method of ['statSync', 'readFileSync']) {
    test(`a failed ${method} cannot be counted as scanned source`, () => {
      const dir = writePackage(mkTmpDir('read-error'), 'pkg', { name: 'p', version: '1' }, { 'index.js': 'module.exports = 1;' });
      const manifest = withFailure(method, path.join(dir, 'index.js'), () => scanPackageDir(dir));
      assert.equal(manifest.sourceFilesScanned, 0);
      assert.equal(manifest.sourceFilesSkipped, 1);
      assert.equal(manifest.capabilities.noReadableSource.present, true);
      assert.equal(manifest.coverage.errorCount, 1);
      assert.equal(manifest.coverage.errors[0].file, 'index.js');
      assert.equal(diffManifests(manifest, manifest).escalated, true);
    });
  }

  test('unreadable source subdirectories are not an empty, complete scan', () => {
    const dir = writePackage(mkTmpDir('walk-error'), 'pkg', { name: 'p' }, { 'dist/index.js': 'module.exports = 1;' });
    const manifest = withFailure('readdirSync', path.join(dir, 'dist'), () => scanPackageDir(dir));
    assert.equal(manifest.coverage.complete, false);
    assert.equal(manifest.coverage.errors[0].operation, 'readdir');
  });

  test('unreadable package.json is different from an absent package.json', () => {
    const dir = writePackage(mkTmpDir('metadata-error'), 'pkg', { name: 'p' }, { 'index.js': 'module.exports = 1;' });
    const manifest = withFailure('readFileSync', path.join(dir, 'package.json'), () => scanPackageDir(dir));
    assert.equal(manifest.coverage.complete, false);
    assert.equal(manifest.coverage.errors[0].operation, 'read-package-json');
  });

  test('an unreadable extensionless script is recorded even before classification', () => {
    const dir = writePackage(mkTmpDir('shebang-error'), 'pkg', { name: 'p' }, { cli: '#!/usr/bin/env node\n' });
    const manifest = withFailure('openSync', path.join(dir, 'cli'), () => scanPackageDir(dir));
    assert.equal(manifest.coverage.complete, false);
    assert.equal(manifest.coverage.errors[0].operation, 'read-shebang');
  });

  test('a data-only package is distinguished from an I/O failure', () => {
    const manifest = scanPackageDir(writePackage(mkTmpDir('data-only'), 'pkg', { name: 'p' }));
    assert.equal(manifest.coverage.complete, true);
    assert.equal(manifest.capabilities.noReadableSource.present, true);
  });

  test('byte counts describe the bytes read, including invalid UTF-8', () => {
    const manifest = scanSource(Buffer.from([0xff, 0xfe, 0x0a]));
    assert.equal(manifest.coverage.bytesRead, 3);
    assert.equal(manifest.coverage.filesRead, 1);
  });

  test('discovery exposes an unreadable scope instead of silently dropping it', () => {
    const tmp = mkTmpDir('scope-error');
    const nm = path.join(tmp, 'node_modules');
    writePackage(tmp, 'node_modules/@scope/pkg', { name: '@scope/pkg' });
    const result = withFailure('readdirSync', path.join(nm, '@scope'), () => discoverPackageDirs(nm));
    assert.equal(result.errorCount, 1);
    assert.equal(result.errors[0].code, 'EACCES');
  });
});

describe('npm implicit native install', () => {
  test('binding.gyp adds the implicit install to the manifest and the diff', () => {
    const before = scanSource('module.exports = 1;');
    const after = scanSource('module.exports = 1;', {}, { 'binding.gyp': '{"targets":[]}' });
    assert.equal(after.capabilities.lifecycleScripts.installTriggering, true);
    assert.equal(after.capabilities.lifecycleScripts.scripts.install, 'node-gyp rebuild');
    assert.equal(after.capabilities.lifecycleScripts.implicit.install, 'binding.gyp');
    assert.ok(diffManifests(before, after).changes.some((c) => c.type === 'lifecycle-script-changed' && c.escalates));
  });

  for (const extra of [{ scripts: { install: 'echo custom' } }, { scripts: { preinstall: 'echo custom' } }, { gypfile: false }]) {
    test(`respects npm override ${JSON.stringify(extra)}`, () => {
      const manifest = scanSource('module.exports = 1;', extra, { 'binding.gyp': '{"targets":[]}' });
      assert.equal(manifest.capabilities.lifecycleScripts.implicit, undefined);
      assert.notEqual(manifest.capabilities.lifecycleScripts.scripts.install, 'node-gyp rebuild');
    });
  }

  test('an implicit install is included in the generated allowlist', () => {
    const tmp = mkTmpDir('gyp-allowlist');
    writePackage(tmp, 'node_modules/native', { name: 'native', version: '1.0.0' }, { 'binding.gyp': '{"targets":[]}' });
    const out = path.join(tmp, 'out');
    assert.equal(runCli(['scan-tree', path.join(tmp, 'node_modules'), '--out', out]).status, 0);
    const result = runCli(['allowlist', out, '--format', 'json']);
    assert.equal(result.status, 0);
    assert.deepEqual(JSON.parse(result.stdout).allow, ['native@1.0.0']);
  });
});

describe('scan snapshots', () => {
  function tree() {
    const tmp = mkTmpDir('snapshot');
    const nm = path.join(tmp, 'node_modules');
    const out = path.join(tmp, 'out');
    writePackage(tmp, 'node_modules/p', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = 1;' });
    assert.equal(runCli(['scan-tree', nm, '--out', out]).status, 0);
    return { tmp, nm, out };
  }

  test('reusing output excludes old versions and removed packages without deleting user files', () => {
    const { tmp, nm, out } = tree();
    fs.writeFileSync(path.join(out, 'notes.json'), '{"note":"keep me"}');
    writePackage(tmp, 'node_modules/p', { name: 'p', version: '2.0.0' }, { 'index.js': "require('fs');" });
    assert.equal(runCli(['scan-tree', nm, '--out', out]).status, 0);
    const lock = path.join(tmp, 'lock.json');
    assert.equal(runCli(['baseline', out, '--out', lock]).status, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(lock)).packages.p.map((m) => m.version), ['2.0.0']);
    fs.renameSync(path.join(nm, 'p'), path.join(tmp, 'removed'));
    assert.equal(runCli(['scan-tree', nm, '--out', out]).status, 0);
    assert.equal(runCli(['baseline', out, '--out', lock]).status, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(lock)).packages, {});
    assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'notes.json'))).note, 'keep me');
  });

  test('changed or missing manifest contents invalidate the snapshot', () => {
    const { tmp, out } = tree();
    const manifest = path.join(out, 'p@1.0.0.json');
    fs.writeFileSync(manifest, '{}');
    assert.match(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).stderr, /snapshot manifest changed/);
    fs.unlinkSync(manifest);
    assert.equal(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).status, 2);
  });

  test('an interrupted snapshot cannot fall back to old JSON files, even in report-only mode', () => {
    const { tmp, out } = tree();
    const lock = path.join(tmp, 'lock.json');
    assert.equal(runCli(['baseline', out, '--out', lock]).status, 0);
    fs.writeFileSync(path.join(out, '.capsurface-snapshot'), JSON.stringify({ schemaVersion: 1, complete: false }));
    assert.equal(runCli(['check', out, '--baseline', lock, '--report-only']).status, 2);
    assert.equal(runCli(['allowlist', out]).status, 2);
  });

  test('a discovery failure invalidates an earlier successful inventory', () => {
    const { tmp, nm, out } = tree();
    fs.symlinkSync(path.join(tmp, 'missing'), path.join(nm, 'broken'), 'junction');
    const result = runCli(['scan-tree', nm, '--out', out]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /inventory is incomplete/);
    assert.equal(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).status, 2);
  });

  test('writers and readers refuse an output directory locked by another scan', () => {
    const { tmp, nm, out } = tree();
    fs.writeFileSync(path.join(out, '.capsurface-write.lock'), '');
    assert.match(runCli(['scan-tree', nm, '--out', out]).stderr, /snapshot is locked/);
    assert.equal(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).status, 2);
  });

  test('snapshot file paths cannot escape the output directory', () => {
    const { tmp, out } = tree();
    fs.writeFileSync(path.join(out, '.capsurface-snapshot'), JSON.stringify({
      schemaVersion: 1, complete: true, manifests: [{ file: '../outside.json', sha256: '' }],
    }));
    assert.match(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).stderr, /invalid manifest entry/);
  });

  test('package metadata cannot write manifests outside the output directory', () => {
    const { tmp, nm, out } = tree();
    writePackage(tmp, 'node_modules/p', { name: 'p', version: 'x/../../escaped' });
    assert.equal(runCli(['scan-tree', nm, '--out', out]).status, 0);
    assert.equal(fs.existsSync(path.join(tmp, 'escaped.json')), false);
    assert.equal(runCli(['baseline', out, '--out', path.join(tmp, 'lock.json')]).status, 0);
  });
});

describe('incomplete analysis cannot become an approval', () => {
  test('scan, baseline and allowlist fail; check still reports incomplete new packages', () => {
    const tmp = mkTmpDir('incomplete-cli');
    const pkg = writePackage(tmp, 'pkg', { name: 'p' }, { 'index.js': 'module.exports = 1;' });
    fs.writeFileSync(path.join(pkg, 'package.json'), '{ invalid');
    const out = path.join(tmp, 'out');
    assert.equal(runCli(['scan', pkg, '--out', path.join(out, 'p.json')]).status, 2);
    assert.equal(runCli(['baseline', out, '--out', path.join(tmp, 'rejected.json')]).status, 2);
    assert.equal(runCli(['allowlist', out]).status, 2);
    const baseline = path.join(tmp, 'empty.json');
    fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: {} }));
    const result = runCli(['check', out, '--baseline', baseline, '--json']);
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).escalated, true);
    const report = runCli(['check', out, '--baseline', baseline, '--json', '--report-only']);
    assert.equal(report.status, 0);
    assert.equal(JSON.parse(report.stdout).escalated, true);
  });
});

describe('engine fingerprint portability', () => {
  test('normalization changes invalidate the fingerprint, while line endings do not', () => {
    const tmp = mkTmpDir('engine-fingerprint');
    const library = path.join(__dirname, '../lib');
    for (const file of fs.readdirSync(library).filter((f) => f.endsWith('.js'))) {
      fs.copyFileSync(path.join(library, file), path.join(tmp, file));
    }
    function fingerprint() {
      const result = spawnSync(process.execPath, ['-e', 'process.stdout.write(require(process.argv[1]).RULES_VERSION)', path.join(tmp, 'rules-version.js')], { encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      return result.stdout;
    }
    const original = fingerprint();
    for (const file of fs.readdirSync(tmp)) {
      const full = path.join(tmp, file);
      fs.writeFileSync(full, fs.readFileSync(full, 'utf8').replace(/\r\n/g, '\n').replace(/\n/g, '\r\n'));
    }
    assert.equal(fingerprint(), original);
    fs.appendFileSync(path.join(tmp, 'normalize.js'), '\nmodule.exports.normalizeLine = (line) => line;\n');
    assert.notEqual(fingerprint(), original);
  });
});
