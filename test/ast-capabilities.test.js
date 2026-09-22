'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests, isAnalysisIncomplete, unionOfManifests } = require('../lib/diff');
const { selectBaseline } = require('../lib/comparison');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { approve } = require('../lib/approval');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function fixture(t, source, pkg = {}, other = {}) {
  const root = mkTmpDir('ast-capabilities');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'pkg', version: '1', ...pkg }, { 'index.js': source, ...other });
  return { root, dir, basic: () => scanPackageDir(dir), deep: () => scanPackageDir(dir, { deep: true }) };
}

test('detects acquired modules behind aliases without an installation hook', (t) => {
  const f = fixture(t, "const load = require;\nload(`node:${'child_process'}`);\nload('node:fs/promises'); load('https'); load('vm'); load('bindings');");
  const basic = f.basic(), deep = f.deep();
  for (const key of ['exec', 'filesystem', 'network', 'dynamicEval', 'nativeFfi']) {
    assert.equal(basic.capabilities[key].present, false, key);
    assert.equal(deep.capabilities[key].present, true, key);
  }
  assert.equal(deep.capabilities.exec.evidence[0].line, 2);
  assert.equal(deep.capabilities.exec.evidence[0].snippet, "load(`node:${'child_process'}`);");
  assert.equal(deep.capabilities.exec.evidence[0].specifier, 'node:child_process');
  assert.equal(deep.analysisProfile, 'source-ast-v1');
  assert.equal(deep.astCoverage.complete, true);
  assert.equal(deep.astCoverage.filesAnalyzed, 1);
  assert.equal(deep.installContext.hooks.length, 0);
  assert.equal(diffManifests(basic, deep).escalated, true);
});

test('supports createRequire and preserves scopes without claiming to remove source-text false positives', (t) => {
  const f = fixture(t, "import { createRequire as make } from 'node:module';\nconst load = make(import.meta.url);\nload('node:child_process');\nfunction example(load) { load('https'); }", { type: 'module' });
  const deep = f.deep();
  assert.equal(deep.capabilities.exec.present, true);
  assert.equal(deep.capabilities.network.present, false);
  assert.equal(deep.capabilities.exec.evidence[0].line, 3);
});

test('only exact module names and native loads add capabilities', (t) => {
  const f = fixture(t, "const load = require; load('not-child_process'); load('node:axios'); load('./https.js'); load('./addon.node');");
  const deep = f.deep();
  assert.equal(deep.capabilities.exec.present, false);
  assert.equal(deep.capabilities.network.present, false);
  assert.equal(deep.capabilities.nativeFfi.present, true);
});

test('unresolved aliased loads retain uncertainty rather than acquiring invented modules', (t) => {
  const f = fixture(t, 'const load = require; load(moduleName);');
  const deep = f.deep();
  assert.equal(deep.capabilities.unresolvedRequire.present, true);
  assert.equal(deep.capabilities.network.present, false);
  assert.equal(deep.capabilities.exec.present, false);
});

test('AST network indicators reach file correlation, installation paths and review exports', (t) => {
  const f = fixture(t, "const load = require; load('https'); process.env.SERVICE_TOKEN;", { scripts: { postinstall: 'node index.js' } });
  const basic = f.basic(), deep = f.deep();
  assert.equal(basic.sourceContext.matchingFiles, 0);
  assert.equal(deep.sourceContext.matchingFiles, 1);
  assert.ok(deep.installContext.hooks[0].paths[0].network);
  const report = buildReview(new Map([['pkg', [basic]]]), new Map([['pkg', [deep]]])).report;
  assert.match(renderMarkdown(report), /Network access/);
  assert.ok(renderSarif(report).runs[0].results.length > 0);
});

test('deep failures block scans and selective approvals with bounded coverage evidence', (t) => {
  const other = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`bad${i}.ts`, 'const x: = ;']));
  const f = fixture(t, 'const =', {}, other);
  const deep = f.deep();
  assert.equal(deep.astCoverage.filesFailed, 13);
  assert.equal(deep.astCoverage.errors.length, 10);
  assert.equal(deep.astCoverage.complete, false);
  assert.equal(isAnalysisIncomplete(deep), true);
  assert.equal(diffManifests(deep, deep).escalated, true);
  assert.equal(runCli(['scan', f.dir, '--deep']).status, 2);
  const baseline = path.join(f.root, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: {} }));
  const current = new Map([['pkg', [deep]]]);
  const review = buildReview(new Map(), current);
  assert.throws(() => approve(baseline, current, review.selections[0].id, 'reviewed'), /cannot approve incomplete analysis/);
  assert.match(renderMarkdown(review.report).replace(/\\/g, ''), /ast-parse-error/);
  assert.deepEqual(renderSarif(review.report).runs[0].results[0].properties.astCoverage, deep.astCoverage);
});

test('a deep baseline rejects downgrade, missing AST coverage and equivalent-surface pooling', (t) => {
  const f = fixture(t, 'module.exports = 1;');
  const basic = f.basic(), deep = f.deep();
  const report = diffManifests(deep, basic);
  assert.ok(report.changes.some((c) => c.type === 'analysis-profile-downgrade' && c.escalates));
  assert.equal(diffManifests(unionOfManifests([deep]), basic).escalated, true);
  assert.equal(selectBaseline([basic, deep], basic).kind, 'ambiguous');
  const missing = { ...deep };
  delete missing.astCoverage;
  assert.equal(isAnalysisIncomplete(missing), true);
  const legacy = { ...basic };
  delete legacy.analysisProfile;
  assert.equal(diffManifests(legacy, basic).escalated, false);
  assert.equal(diffManifests(legacy, deep).escalated, false);
});

test('known source-text acquisitions do not duplicate evidence in deep mode', (t) => {
  const f = fixture(t, "require('child_process'); require('https');");
  assert.deepEqual(f.deep().capabilities, f.basic().capabilities);
});

test('CLI checks block aliased capability growth and scan-profile downgrade', (t) => {
  const f = fixture(t, 'module.exports = 1;');
  const oldDir = path.join(f.root, 'before');
  const currentDir = path.join(f.root, 'current');
  const baseline = path.join(f.root, 'baseline.json');
  assert.equal(runCli(['scan', f.dir, '--deep', '--out', path.join(oldDir, 'pkg.json')]).status, 0);
  assert.equal(runCli(['baseline', oldDir, '--out', baseline]).status, 0);
  assert.equal(runCli(['scan', f.dir, '--out', path.join(currentDir, 'pkg.json')]).status, 0);
  const downgrade = runCli(['check', currentDir, '--baseline', baseline, '--json']);
  assert.equal(downgrade.status, 1, downgrade.stderr);
  assert.match(downgrade.stdout, /analysis-profile-downgrade/);
  fs.writeFileSync(path.join(f.dir, 'index.js'), "const load = require; load('child_process');");
  assert.equal(runCli(['scan', f.dir, '--deep', '--out', path.join(currentDir, 'pkg.json')]).status, 0);
  const growth = runCli(['check', currentDir, '--baseline', baseline, '--json']);
  assert.equal(growth.status, 1, growth.stderr);
  assert.match(growth.stdout, /capability-added/);
  assert.match(growth.stdout, /Process execution/);
});
