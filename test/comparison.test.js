'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { compareTrees, selectBaseline } = require('../lib/comparison');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function manifest(version, source, installPath) {
  const result = scanPackageDir(writePackage(mkTmpDir('comparison'), 'p', { name: 'p', version }, { 'index.js': source }));
  if (installPath !== undefined) result.installPath = installPath;
  return result;
}

function compare(baselines, current) {
  return compareTrees(new Map([['p', baselines]]), new Map([['p', [current]]]))[0];
}

test('an upgrade cannot borrow exec from another installed version', () => {
  const before = manifest('1.0.0', "require('fs');", 'p');
  const sibling = manifest('2.0.0', "require('child_process');", 'other/node_modules/p');
  const current = manifest('1.0.1', "require('fs'); require('child_process');", 'p');
  const entry = compare([before, sibling], current);
  assert.equal(entry.match.kind, 'install-path');
  assert.equal(entry.report.baselineVersion, '1.0.0');
  assert.equal(entry.report.escalated, true);
  assert.ok(entry.report.changes.some((c) => c.category === 'exec'));
});

test('an installation path takes precedence over an approved version elsewhere', () => {
  const before = manifest('1', "require('fs');", 'p');
  const sibling = manifest('2', "require('child_process');", 'other/node_modules/p');
  const current = manifest('2', "require('fs'); require('child_process');", 'p');
  assert.equal(compare([before, sibling], current).report.escalated, true);
});

test('two physical copies of the same version retain separate approvals', () => {
  const before = manifest('1', "require('fs');", 'p');
  const sibling = manifest('1', "require('child_process');", 'other/node_modules/p');
  const current = manifest('1', "require('fs'); require('child_process');", 'p');
  assert.equal(compare([sibling, before], current).report.escalated, true);
});

test('paths from Windows and POSIX identify the same install slot', () => {
  const before = manifest('1', "require('fs');", 'other\\node_modules\\p');
  const sibling = manifest('2', "require('child_process');", 'p');
  const current = manifest('1.1', "require('fs');", 'other/node_modules/p');
  const entry = compare([before, sibling], current);
  assert.equal(entry.match.kind, 'install-path');
  assert.equal(entry.report.escalated, false);
});

test('a relocated exact version is compared with its own surface', () => {
  const before = manifest('1', "require('fs');", 'p');
  const sibling = manifest('2', "require('child_process');", 'other/node_modules/p');
  const current = manifest('1', "require('fs');", 'new/node_modules/p');
  const entry = compare([before, sibling], current);
  assert.equal(entry.match.kind, 'version');
  assert.equal(entry.report.escalated, false);
});

test('a pnpm path change with different possible predecessors requires review', () => {
  const before = manifest('1.0.0', "require('fs');", '.pnpm/p@1.0.0/node_modules/p');
  const sibling = manifest('2.0.0', "require('child_process');", '.pnpm/p@2.0.0/node_modules/p');
  const current = manifest('1.0.1', "require('fs'); require('child_process');", '.pnpm/p@1.0.1/node_modules/p');
  const entry = compare([before, sibling], current);
  assert.equal(entry.match.kind, 'ambiguous');
  assert.equal(entry.report.escalated, true);
  assert.equal(entry.report.changes[0].type, 'ambiguous-baseline');
});

test('equivalent approved surfaces do not create ambiguity just from evidence locations', () => {
  const before = manifest('1', "require('fs');");
  const sibling = manifest('2', "\n\nrequire('fs');");
  const current = manifest('3', "require('fs');");
  const entry = compare([before, sibling], current);
  assert.equal(entry.match.kind, 'equivalent-surface');
  assert.equal(entry.report.escalated, false);
});

test('a single legacy baseline still allows a clean upgrade', () => {
  const before = manifest('1', "require('fs');");
  const current = manifest('2', "require('fs');");
  assert.equal(compare([before], current).report.escalated, false);
  assert.equal(selectBaseline([], current).kind, 'new');
});

test('check uses the same conservative matching as the comparison library', () => {
  const tmp = mkTmpDir('comparison-cli');
  const before = manifest('1', "require('fs');");
  const sibling = manifest('2', "require('child_process');");
  const current = manifest('1.1', "require('fs'); require('child_process');");
  const lock = path.join(tmp, 'lock.json');
  fs.writeFileSync(lock, JSON.stringify({ schemaVersion: 2, packages: { p: [before, sibling] } }));
  const out = path.join(tmp, 'out');
  fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'p.json'), JSON.stringify(current));
  const result = runCli(['check', out, '--baseline', lock, '--json']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).escalations[0].match, 'ambiguous');
});
