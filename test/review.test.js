'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { buildReview, renderMarkdown } = require('../lib/review');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function fixture() {
  const tmp = mkTmpDir('review');
  const out = path.join(tmp, 'out');
  const baseline = path.join(tmp, 'lock.json');
  fs.mkdirSync(out);
  function manifest(name, version, source, location = name) {
    const result = scanPackageDir(writePackage(tmp, `${name}-${version}`, { name, version }, { 'index.js': source }));
    result.installPath = location;
    return result;
  }
  const p = manifest('p', '1', 'module.exports = 1;');
  const q = manifest('q', '1', 'module.exports = 1;');
  const currentP = manifest('p', '2', "require('child_process');");
  const currentQ = manifest('q', '2', "require('https');");
  const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2));
  save(baseline, { schemaVersion: 2, packages: { p: [p], q: [q] } });
  save(path.join(out, 'p.json'), currentP);
  save(path.join(out, 'q.json'), currentQ);
  function review() {
    const result = runCli(['review', out, '--baseline', baseline, '--json']);
    assert.ok(result.status === 0 || result.status === 1, result.stderr);
    return JSON.parse(result.stdout);
  }
  function approve(id, reason = 'Reviewed the new child process integration') {
    return runCli(['approve', out, '--baseline', baseline, '--id', id, '--reason', reason]);
  }
  return { tmp, out, baseline, p, q, currentP, currentQ, save, review, approve, manifest };
}

test('review exposes matching, file/line evidence, coverage and the same gate outcome as check', () => {
  const f = fixture();
  const report = f.review();
  assert.equal(report.wouldFail, true);
  assert.equal(report.entries.length, 2);
  const p = report.entries.find((entry) => entry.name === 'p');
  assert.equal(p.match.kind, 'install-path');
  assert.equal(p.evidence[0].file, 'index.js');
  assert.equal(p.evidence[0].line, 1);
  assert.match(p.evidence[0].snippet, /child_process/);
  assert.equal(p.coverage.complete, true);
  const check = runCli(['check', f.out, '--baseline', f.baseline, '--json']);
  assert.equal(check.status, 1);
  assert.equal(JSON.parse(check.stdout).escalations.find((entry) => entry.name === 'p').id, p.id);
});

test('explain reads one saved review entry without revalidating or changing approval inputs', () => {
  const f = fixture();
  const report = f.review();
  const entry = report.entries.find((item) => item.name === 'p');
  const file = path.join(f.tmp, 'review.json');
  f.save(file, report);
  const original = fs.readFileSync(file, 'utf8');
  // The saved report remains readable even when its original inputs are gone.
  fs.unlinkSync(f.baseline);
  fs.rmSync(f.out, { recursive: true });
  const args = ['explain', '--report', file, '--id', entry.id, '--json'];
  const result = runCli(args);
  assert.equal(result.status, 0, result.stderr);
  const explanation = JSON.parse(result.stdout);
  assert.deepEqual(explanation.entry, entry);
  assert.equal(explanation.source.freshness, 'not-checked');
  assert.equal(explanation.idKind, 'review-content-id');
  assert.equal(explanation.report.wouldFail, true, 'a successful lookup is not a passing gate');
  assert.deepEqual(explanation.audit, report.audit.installations.find((item) => item.name === 'p'));
  const output = path.join(f.tmp, 'details/entry.json');
  const saved = runCli([...args, '--out', output]);
  assert.equal(saved.status, 0, saved.stderr);
  assert.equal(saved.stdout, '');
  assert.deepEqual(JSON.parse(fs.readFileSync(output)), explanation);
  assert.equal(runCli([...args, '--out', file]).status, 2);
  assert.equal(fs.readFileSync(file, 'utf8'), original);
});

test('explain rejects missing, ambiguous and malformed IDs or reports', () => {
  const f = fixture();
  const report = f.review(), id = report.entries[0].id;
  const file = path.join(f.tmp, 'review.json');
  const args = ['explain', '--report', file, '--id', id];
  f.save(file, report);
  assert.equal(runCli([...args, '--unknown']).status, 2);
  assert.equal(runCli(['explain', '--report', file, '--id', id.slice(0, 8)]).status, 2);
  assert.equal(runCli(['explain', '--report', file, '--id', '0'.repeat(32)]).status, 2);
  for (const invalid of [null, { ...report, schemaVersion: 99 }, { runs: [] },
    { ...report, entries: [report.entries[0], report.entries[0]] },
    { ...report, entries: [{ ...report.entries[0], evidence: null }] }]) {
    f.save(file, invalid);
    const result = runCli(args);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  }
  fs.writeFileSync(file, '{');
  assert.equal(runCli(args).status, 2);
  fs.unlinkSync(file);
  assert.equal(runCli(args).status, 2);
});

test('approve changes only the selected installation and records the reason', () => {
  const f = fixture();
  const p = f.review().entries.find((entry) => entry.name === 'p');
  assert.equal(f.approve(p.id).status, 0);
  const lock = JSON.parse(fs.readFileSync(f.baseline));
  assert.equal(lock.packages.p[0].version, '2');
  assert.deepEqual(lock.packages.q, [f.q]);
  assert.equal(lock.approvals.length, 1);
  assert.equal(lock.approvals[0].id, p.id);
  assert.match(lock.approvals[0].reason, /child process/);
  assert.deepEqual(f.review().entries.map((entry) => entry.name), ['q']);
  assert.equal(runCli(['check', f.out, '--baseline', f.baseline]).status, 1);
  assert.match(f.approve(p.id).stderr, /already been approved/);
  assert.equal(f.approve(f.review().entries[0].id, 'Reviewed the HTTP client').status, 0);
  assert.equal(runCli(['check', f.out, '--baseline', f.baseline]).status, 0);
});

test('approvals are not reused when the reviewed manifest changes', () => {
  const f = fixture();
  const id = f.review().entries[0].id;
  const original = fs.readFileSync(f.baseline, 'utf8');
  f.currentP.capabilities.env.vars.push('SERVICE_TOKEN');
  f.save(path.join(f.out, 'p.json'), f.currentP);
  assert.equal(f.approve(id).status, 2);
  assert.equal(fs.readFileSync(f.baseline, 'utf8'), original);
});

test('approvals are not reused when the candidate baseline changes', () => {
  const f = fixture();
  const id = f.review().entries[0].id;
  f.p.version = '0';
  f.save(f.baseline, { schemaVersion: 2, packages: { p: [f.p], q: [f.q] } });
  assert.match(f.approve(id).stderr, /stale/);
});

test('review IDs survive rescans with different timestamps and object key ordering', () => {
  const f = fixture();
  const id = f.review().entries[0].id;
  f.currentP.scannedAt = '2099-01-01T00:00:00.000Z';
  f.save(path.join(f.out, 'p.json'), Object.fromEntries(Object.entries(f.currentP).reverse()));
  assert.equal(f.review().entries[0].id, id);
  assert.equal(f.approve(id).status, 0);
});

test('an empty reason or a concurrent approval cannot modify the baseline', () => {
  const f = fixture();
  const id = f.review().entries[0].id;
  const original = fs.readFileSync(f.baseline, 'utf8');
  assert.equal(f.approve(id, '   ').status, 2);
  fs.writeFileSync(`${f.baseline}.approval-lock`, '');
  assert.match(f.approve(id).stderr, /locked/);
  assert.equal(fs.readFileSync(f.baseline, 'utf8'), original);
});

test('incomplete coverage and scans from another engine cannot be approved', () => {
  const f = fixture();
  const original = fs.readFileSync(f.baseline, 'utf8');
  f.currentP.coverage.complete = false;
  f.save(path.join(f.out, 'p.json'), f.currentP);
  let entry = f.review().entries.find((e) => e.name === 'p');
  assert.equal(entry.approvable, false);
  assert.match(f.approve(entry.id).stderr, /incomplete/);
  f.currentP.coverage.complete = true;
  f.currentP.rulesVersion = 'old-rules';
  f.save(path.join(f.out, 'p.json'), f.currentP);
  entry = f.review().entries.find((e) => e.name === 'p');
  assert.equal(entry.approvable, false);
  assert.match(f.approve(entry.id).stderr, /current engine/);
  assert.equal(fs.readFileSync(f.baseline, 'utf8'), original);
});

test('ambiguous predecessors can be resolved without rewriting their existing approvals', () => {
  const f = fixture();
  const sibling = f.manifest('p', '3', "require('https');", 'other/node_modules/p');
  f.currentP.installPath = '.pnpm/p@2/node_modules/p';
  f.save(path.join(f.out, 'p.json'), f.currentP);
  f.save(f.baseline, { schemaVersion: 2, packages: { p: [f.p, sibling], q: [f.q] } });
  const entry = f.review().entries.find((e) => e.name === 'p');
  assert.equal(entry.match.kind, 'ambiguous');
  assert.equal(f.approve(entry.id, 'Reviewed the new pnpm installation').status, 0);
  const lock = JSON.parse(fs.readFileSync(f.baseline));
  assert.deepEqual(lock.packages.p.slice(0, 2), [f.p, sibling]);
  assert.equal(f.review().entries.some((e) => e.name === 'p'), false);
});

test('a new copy does not delete an approval still used by another installed copy', () => {
  const f = fixture();
  f.currentP.installPath = 'other/node_modules/p';
  f.save(path.join(f.out, 'p.json'), f.currentP);
  f.save(path.join(f.out, 'old-p.json'), f.p);
  const entry = f.review().entries.find((e) => e.name === 'p');
  assert.equal(f.approve(entry.id).status, 0);
  const lock = JSON.parse(fs.readFileSync(f.baseline));
  assert.equal(lock.packages.p.length, 2);
  assert.deepEqual(lock.packages.p[0], f.p);
});

test('new packages can be reviewed and approved individually with fail-on-new', () => {
  const f = fixture();
  f.save(f.baseline, { schemaVersion: 2, packages: {} });
  const result = runCli(['review', f.out, '--baseline', f.baseline, '--json', '--fail-on-new']);
  assert.equal(result.status, 1);
  const entry = JSON.parse(result.stdout).entries[0];
  assert.equal(entry.newPackage, true);
  assert.ok(entry.evidence.length);
  assert.equal(f.approve(entry.id).status, 0);
  const lock = JSON.parse(fs.readFileSync(f.baseline));
  assert.deepEqual(Object.keys(lock.packages), ['p']);
});

test('nonblocking changes appear in review without making the gate fail', () => {
  const f = fixture();
  const current = f.manifest('p', '4', 'process.env.NO_COLOR;');
  const { report } = buildReview(new Map([['p', [f.p]]]), new Map([['p', [current]]]));
  assert.equal(report.wouldFail, false);
  assert.equal(report.entries[0].requiresApproval, false);
  assert.ok(report.entries[0].changes.some((c) => c.type === 'new-env-vars'));
});

test('Markdown output is written even when review returns a failing status', () => {
  const f = fixture();
  const output = path.join(f.tmp, 'review.md');
  const result = runCli(['review', f.out, '--baseline', f.baseline, '--out', output]);
  assert.equal(result.status, 1);
  const text = fs.readFileSync(output, 'utf8');
  assert.match(text, /Review ID:/);
  assert.match(text, /Source evidence before and after:/);
  assert.match(text, /index\\\.js:1/);
  assert.equal(runCli(['review', f.out, '--baseline', f.baseline, '--out', output, '--report-only']).status, 0);
});

test('package-controlled Markdown and HTML are escaped in the rendered review', () => {
  const f = fixture();
  const { report } = buildReview(new Map([['p', [f.p]]]), new Map([['p', [f.currentP]]]));
  report.entries[0].name = '<img src=x> [approve](https://evil.example)\n# approved';
  report.entries[0].evidence[0].snippet = '<script>alert(1)</script> ```';
  const text = renderMarkdown(report);
  assert.ok(!text.includes('<img'));
  assert.ok(!text.includes('<script>'));
  assert.ok(!text.includes('[approve]('));
  assert.ok(!text.includes('\n# approved'));
});

test('legacy v1 baselines are upgraded only for the selected approval', () => {
  const f = fixture();
  f.save(f.baseline, { schemaVersion: 1, packages: { p: f.p, q: f.q } });
  assert.equal(f.approve(f.review().entries[0].id).status, 0);
  const lock = JSON.parse(fs.readFileSync(f.baseline));
  assert.equal(lock.schemaVersion, 2);
  assert.deepEqual(lock.packages.q, [f.q]);
});

test('review flags an old engine even when both manifests were produced by it', () => {
  const f = fixture();
  f.p.rulesVersion = 'old-engine';
  const { report } = buildReview(new Map([['p', [f.p]]]), new Map([['p', [f.p]]]));
  assert.equal(report.entries.length, 1);
  assert.equal(report.entries[0].rulesChanged, true);
  assert.equal(report.entries[0].approvable, false);
});

test('review preserves removed evidence and keeps ambiguous predecessors separate', () => {
  const f = fixture();
  const before = f.manifest('old', '1', "require('https');", 'old');
  const other = f.manifest('old', '2', "require('child_process');", 'nested/old');
  const after = f.manifest('old', '3', 'module.exports = 1;', 'old');
  let report = buildReview(new Map([['old', [before]]]), new Map([['old', [after]]])).report;
  assert.ok(report.entries[0].changes.some((c) => c.type === 'capability-removed'));
  assert.ok(report.entries[0].baselineEvidence[0].evidence.some((e) => e.snippet.includes('https')));
  assert.equal(report.entries[0].evidence.length, 0);
  assert.match(renderMarkdown(report), /Before: 1 at old/);
  assert.match(renderMarkdown(report), /does not establish that the behavior was removed/);
  before.coverage.complete = false;
  before.capabilities.network.evidence[0].snippet = '<script>alert(1)</script>';
  after.installPath = 'another/old';
  report = buildReview(new Map([['old', [before, other]]]), new Map([['old', [after]]])).report;
  assert.equal(report.entries[0].match.kind, 'ambiguous');
  assert.deepEqual(report.entries[0].baselineEvidence.map((b) => b.version), ['1', '2']);
  const md = renderMarkdown(report);
  assert.match(md, /Before \(candidate\): 1/);
  assert.match(md, /Before \(candidate\): 2/);
  assert.match(md, /Baseline analysis is incomplete/);
  assert.ok(!md.includes('<script>'));
  assert.ok(md.includes('&lt;script&gt;'));
});

test('write-file-atomic historical snapshots report newly detected operations without claiming new behavior', () => {
  const root = path.join(__dirname, '../docs/field-reviews/results/write-file-atomic');
  function snapshot(folder) {
    return JSON.parse(fs.readFileSync(path.join(root, folder, fs.readdirSync(path.join(root, folder)).find((file) => file.endsWith('.json'))), 'utf8'));
  }
  const before = snapshot('basic-before');
  const after = snapshot('basic-after');
  const report = buildReview(new Map([[before.name, [before]]]), new Map([[after.name, [after]]])).report;
  const entry = report.entries[0];
  assert.ok(entry.changes.some((c) => c.category === 'filesystemWrite' && c.type === 'capability-added'));
  assert.equal(entry.baselineEvidence[0].version, '2.4.3');
  assert.ok(entry.evidence.some((e) => e.category === 'filesystemWrite'));
  const md = renderMarkdown(report);
  assert.match(md, /does not establish when the behavior began/);
  assert.ok(!md.includes('was not present'));
  assert.match(md, /Before: 2/);
  assert.match(md, /After: 3/);
  assert.equal(report.wouldFail, true);
});
