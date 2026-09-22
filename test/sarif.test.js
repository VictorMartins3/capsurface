'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { renderSarif } = require('../lib/sarif');
const { buildReview } = require('../lib/review');
const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function report(failOnNew = true) {
  const tmp = mkTmpDir('sarif');
  const manifest = scanPackageDir(writePackage(tmp, 'p', { name: 'p', version: '1.0.0' }, { 'source #1.js': "require('child_process');" }));
  manifest.installPath = 'p';
  return buildReview(new Map(), new Map([['p', [manifest]]]), failOnNew).report;
}

test('SARIF rules, levels and fingerprints are stable across repeated scans and version changes', () => {
  const review = report();
  const first = renderSarif(review);
  assert.equal(first.version, '2.1.0');
  const run = first.runs[0];
  const result = run.results[0];
  assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
  assert.equal(result.level, 'error');
  assert.match(result.message.text, /New installation has no approved baseline/);
  assert.match(result.locations[0].physicalLocation.artifactLocation.uri, /source%20%231.js/);
  review.entries[0].id = 'another-review';
  review.entries[0].currentVersion = '2.0.0';
  assert.deepEqual(renderSarif(review).runs[0].results[0].partialFingerprints, result.partialFingerprints);
  assert.equal(renderSarif(report(false)).runs[0].results[0].level, 'note');
});

test('uses the committed lockfile line for PR annotations and retains source evidence', () => {
  const review = report();
  review.entries[0].provenance = { status: 'resolved', chain: [{ name: 'app' }, { name: 'p', version: '1.0.0' }],
    location: { file: 'apps/web/package-lock.json', line: 42 } };
  const result = renderSarif(review).runs[0].results[0];
  assert.deepEqual(result.locations, [{ physicalLocation: { artifactLocation: { uri: 'apps/web/package-lock.json' }, region: { startLine: 42 } } }]);
  assert.match(result.message.text, /Dependency chain: app -> p@1.0.0/);
  assert.match(result.message.text, /source #1.js:1/);
  assert.ok(result.properties.evidence.length);
});

test('never emits absolute or traversal URIs from untrusted manifests', () => {
  const review = report();
  review.entries[0].installPath = '../../escape';
  assert.equal(renderSarif(review).runs[0].results[0].locations, undefined);
  review.entries[0].provenance = { status: 'unavailable', location: { file: '/etc/passwd', line: 0 } };
  assert.equal(renderSarif(review).runs[0].results[0].locations, undefined);
});

test('CLI exports SARIF without suppressing gate failures and validates format flags', () => {
  const tmp = mkTmpDir('sarif-cli');
  const pkg = writePackage(tmp, 'p', { name: 'p', version: '1' }, { 'index.js': "require('https');" });
  const out = path.join(tmp, 'out');
  const baseline = path.join(tmp, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: {} }));
  assert.equal(runCli(['scan', pkg, '--out', path.join(out, 'p.json')]).status, 0);
  const args = ['review', out, '--baseline', baseline, '--fail-on-new', '--format', 'sarif'];
  const result = runCli(args);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).runs[0].results[0].level, 'error');
  assert.equal(runCli([...args, '--report-only']).status, 0);
  assert.equal(runCli([...args, '--json']).status, 2);
  assert.equal(runCli([...args, '--format', 'xml']).status, 2);
  assert.equal(runCli([...args, '--lockfile']).status, 2);
});
