'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const wrapper = path.join(__dirname, '..', 'bin', 'action-review.js');

test('deep Action reviews retain launch evidence, selective approvals and coverage failures', (t) => {
  const root = mkTmpDir('deep-action');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  fs.mkdirSync(project);
  const pkg = writePackage(project, 'node_modules/pkg', { name: 'pkg', version: '1' }, {
    'index.ts': "const load = require as NodeRequire; load('child_process').spawn('node');",
  });
  fs.writeFileSync(path.join(project, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3,
    packages: { '': { dependencies: { pkg: '1' } }, 'node_modules/pkg': { name: 'pkg', version: '1' } } }));
  const manifests = path.join(root, 'baseline-manifests');
  const baseline = path.join(project, 'capsurface.lock.json');
  assert.equal(runCli(['scan-tree', path.join(project, 'node_modules'), '--deep', '--out', manifests]).status, 0);
  assert.equal(runCli(['baseline', manifests, '--out', baseline]).status, 0);
  const git = (...args) => execFileSync('git', args, { cwd: project, encoding: 'utf8' }).trim();
  git('init', '--quiet');
  git('add', 'capsurface.lock.json', 'package-lock.json');
  git('-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', `core.hooksPath=${path.join(root, 'no-hooks')}`, 'commit', '--quiet', '-m', 'test: record deep baseline');
  const sha = git('rev-parse', 'HEAD');
  fs.writeFileSync(path.join(pkg, 'index.ts'), "const load = require as NodeRequire;\nload('child_process').exec('echo fixture');");
  let sequence = 0;
  function review(deep = 'true') {
    const output = path.join(root, `output-${sequence++}`);
    const result = spawnSync(process.execPath, [wrapper], { cwd: project, encoding: 'utf8', env: {
      ...process.env, CAPSURFACE_PROJECT: project, CAPSURFACE_BASELINE: 'capsurface.lock.json',
      CAPSURFACE_LOCKFILE: 'package-lock.json', CAPSURFACE_FAIL_ON_NEW: 'true', CAPSURFACE_DEEP: deep,
      CAPSURFACE_BASE_REF: sha, RUNNER_TEMP: root, GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: path.join(root, 'summary.md'),
    } });
    assert.equal(result.status, 0, result.stderr);
    return Object.fromEntries(fs.readFileSync(output, 'utf8').trim().split('\n').map((line) => {
      const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)];
    }));
  }
  const first = review();
  assert.equal(first['would-fail'], 'true');
  assert.equal(first['analysis-incomplete'], 'false');
  const report = JSON.parse(fs.readFileSync(first.json, 'utf8'));
  const entry = report.entries[0];
  assert.equal(entry.analysisProfile, 'source-ast-v1');
  assert.equal(entry.astCoverage.complete, true);
  assert.ok(entry.evidence.some((item) => item.category === 'execShell' && item.line === 2));
  assert.match(fs.readFileSync(first.sarif, 'utf8'), /Shell execution/);
  assert.equal(runCli(['approve', path.join(first.directory, 'manifests'), '--baseline', baseline,
    '--id', entry.id, '--reason', 'Reviewed the shell launch']).status, 0);
  const approved = review();
  assert.equal(approved['would-fail'], 'false');
  assert.equal(JSON.parse(fs.readFileSync(approved.json, 'utf8')).wouldFail, true, 'base-branch report must retain the change');
  assert.equal(review('false')['would-fail'], 'true', 'basic mode cannot satisfy a deep baseline');
  fs.writeFileSync(path.join(pkg, 'index.ts'), 'const =');
  const incomplete = review();
  assert.equal(incomplete['analysis-incomplete'], 'true');
  assert.equal(incomplete['would-fail'], 'true');
  assert.match(fs.readFileSync(incomplete.markdown, 'utf8'), /AST coverage/);
  assert.equal(JSON.parse(fs.readFileSync(incomplete.json, 'utf8')).entries[0].astCoverage.errors[0].reason, 'ast-parse-error');
});

test('Action rejects invalid deep input before scanning', () => {
  const result = spawnSync(process.execPath, [wrapper], { encoding: 'utf8', env: { ...process.env, CAPSURFACE_DEEP: 'yes' } });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /deep must be true or false/);
});
