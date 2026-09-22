'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadParser, astImports } = require('../lib/ast-imports');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const parser = loadParser();
const analyze = (code, file = 'index.js', mode = 'script') => astImports(parser, code, file, mode);
const categories = (result) => (result.operations || []).map((op) => op.category);

test('attributes launch modes to resolved child_process calls, including immutable aliases', () => {
  const result = analyze("const cp = require('node:child_process');\nconst { exec: run } = cp; const direct = cp.spawn;\nrun('echo hi');\ndirect('node', ['app.js']); cp.execFileSync('node'); cp.fork('app.js');");
  assert.equal(result.parsed, true);
  assert.deepEqual(categories(result), ['execShell', 'execDirect', 'execDirect', 'execDirect']);
  assert.equal(result.operations[0].line, 3);
  assert.equal(result.operations[0].method, 'exec');
  assert.deepEqual(categories(analyze("import { execSync as run } from 'node:child_process'; run('echo hi');", 'index.mjs', 'module')), ['execShell']);
  assert.deepEqual(categories(analyze("import cp from 'child_process'; cp.spawn('node');", 'index.mjs', 'module')), ['execDirect']);
  assert.deepEqual(categories(analyze("const { createRequire } = require('module'); const load = createRequire(__filename); load('child_process').exec('echo hi');")), ['execShell']);
});

test('classifies literal shell options and preserves uncertainty in dynamic options', () => {
  const cases = [
    ["spawn('node')", 'execDirect'],
    ["spawn('node', [])", 'execDirect'],
    ["spawn('node', { shell: true })", 'execShell'],
    ["spawnSync('node', [], { shell: '/bin/bash' })", 'execShell'],
    ["execFile('node', [], { shell: false }, () => {})", 'execDirect'],
    ["execFile('node', () => {})", 'execDirect'],
    ["execFileSync('node', { shell: '' })", 'execDirect'],
    ["fork('app.js', { shell: true })", 'execDirect'],
    ["exec('echo hi', options)", 'execShell'],
    ["spawn('node', { shell: flag })", 'execUnresolved'],
    ["spawn('node', args)", 'execUnresolved'],
    ["spawn('node', [], options)", 'execUnresolved'],
    ["spawn('node', { ...options, shell: false })", 'execUnresolved'],
    ["spawn('node', { ['shell']: true })", 'execUnresolved'],
    ["spawn('node', { get shell() { return true; } })", 'execUnresolved'],
    ["spawn('node', { __proto__: options })", 'execUnresolved'],
    ["spawn(...args)", 'execUnresolved'],
    ["spawn('node', { shell: true, shell: false })", 'execDirect'],
    ["execFile('node', callback)", 'execUnresolved'],
  ];
  for (const [call, expected] of cases) {
    assert.deepEqual(categories(analyze(`require('child_process').${call};`)), [expected], call);
  }
});

test('does not attribute unrelated methods, erased imports or shadowed and reassigned functions', () => {
  for (const code of [
    "const cp = require('other'); cp.exec('x'); /x/.exec('x');",
    "const cp = require('child_process'); function f(cp) { cp.exec('x'); }",
    "const { exec } = require('child_process'); function f(exec) { exec('x'); }",
    "const cp = require('child_process'); const run = cp.exec; run = fake; run('x');",
    "let cp = require('child_process'); cp.exec('x');",
    "const cp = require('child_process'); cp.exec;",
  ]) assert.deepEqual(categories(analyze(code)), [], code);
  assert.deepEqual(categories(analyze("import type { exec } from 'child_process'; exec('x');", 'index.ts')), []);
  assert.deepEqual(categories(analyze("const cp = require('child_process');\nconst run = cp.exec as Function; run!('x');", 'index.ts')), ['execShell']);
});

test('namespace mutation or escape leaves deep coverage explicitly unavailable', () => {
  for (const code of [
    "const cp = require('child_process'); cp.exec = fake; cp.exec('x');",
    "const cp = require('child_process'); Object.assign(cp, other); cp.exec('x');",
    "const cp = require('child_process'); const alias = cp; delete alias.exec; cp.exec('x');",
  ]) {
    const result = analyze(code);
    assert.equal(result.parsed, false);
    assert.match(result.references[0].reason, /^ast-module-(mutation|escape)$/);
  }
});

test('direct-to-shell changes block with source evidence, unchanged parent score and selective approval', (t) => {
  const root = mkTmpDir('process-detail');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'pkg', version: '1' }, {
    'index.js': "const cp = require('child_process');\ncp.spawn('node', []);",
  });
  const baseline = scanPackageDir(dir, { deep: true });
  fs.writeFileSync(path.join(dir, 'index.js'), "const cp = require('child_process');\ncp.spawn('node', [], { shell: true });");
  const current = scanPackageDir(dir, { deep: true });
  assert.equal(current.astCoverage.complete, true);
  assert.equal(current.riskScore, baseline.riskScore);
  assert.equal(scanPackageDir(dir).capabilities.execShell.present, false, 'detail requires deep mode');
  assert.deepEqual(diffManifests(baseline, current).changes.filter((c) => c.escalates).map((c) => c.category), ['execShell']);
  const report = buildReview(new Map([['pkg', [baseline]]]), new Map([['pkg', [current]]])).report;
  assert.match(renderMarkdown(report), /Shell execution/);
  assert.match(renderSarif(report).runs[0].results[0].message.text, /Shell execution/);
  assert.equal(current.capabilities.execShell.evidence[0].line, 2);
  assert.equal(current.capabilities.execShell.evidence[0].pattern, 'node:child_process.spawn');
  const out = path.join(root, 'manifests');
  fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'pkg.json'), JSON.stringify(current));
  const lock = path.join(root, 'baseline.json');
  fs.writeFileSync(lock, JSON.stringify({ schemaVersion: 2, packages: { pkg: [baseline] } }));
  assert.equal(runCli(['check', out, '--baseline', lock]).status, 1);
  assert.equal(runCli(['approve', out, '--baseline', lock, '--id', report.entries[0].id, '--reason', 'Reviewed shell command']).status, 0);
  assert.equal(runCli(['check', out, '--baseline', lock]).status, 0);
  const legacy = JSON.parse(JSON.stringify(baseline));
  for (const key of ['execShell', 'execDirect', 'execUnresolved']) delete legacy.capabilities[key];
  assert.ok(diffManifests(legacy, current).changes.some((c) => c.type === 'capability-detail-unreviewed'));
  fs.writeFileSync(path.join(dir, 'index.js'), "require('child_process').spawn('node', [], options);");
  assert.ok(diffManifests(baseline, scanPackageDir(dir, { deep: true })).changes.some((c) => c.category === 'execUnresolved' && c.escalates));
});
