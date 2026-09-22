'use strict';

// Hosted Action smoke test: only copies and scans source. Neither fixture runs.
const assert = require('assert').strict;
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const root = path.resolve(process.argv[2]);
const repo = path.join(__dirname, '..');
const cli = path.join(repo, 'bin', 'capsurface.js');
fs.mkdirSync(root, { recursive: true });
const target = path.join(root, 'node_modules', 'handy-color-utils');
const run = (...args) => execFileSync(process.execPath, [cli, ...args], { cwd: root, stdio: 'pipe' });
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
function install(version) {
  fs.rmSync(target, { recursive: true, force: true });
  fs.cpSync(path.join(repo, 'examples', `malicious-pkg-v${version}`), target, { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(target, 'package.json')));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ name: 'action-fixture', lockfileVersion: 3,
    packages: { '': { name: 'action-fixture', dependencies: { [pkg.name]: pkg.version } },
      [`node_modules/${pkg.name}`]: { name: pkg.name, version: pkg.version } } }, null, 2));
}
function prepare() {
  install(1);
  run('scan-tree', 'node_modules', '--out', 'baseline-manifests');
  run('baseline', 'baseline-manifests', '--out', 'capsurface.lock.json');
  git('init', '--quiet');
  git('add', 'capsurface.lock.json', 'package-lock.json');
  git('-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.hooksPath=' + path.join(root, 'no-hooks'), 'commit', '--quiet', '-m', 'test: record reviewed dependency');
  const sha = git('rev-parse', 'HEAD');
  install(2);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `base-sha=${sha}\n`);
  console.log(sha);
}

function reviewedUpgrade() {
  const report = JSON.parse(fs.readFileSync(process.env.REVIEW_JSON, 'utf8'));
  assert.equal(report.wouldFail, true, 'target-baseline review must retain the escalation');
  assert.equal(report.entries.length, 1);
  assert.equal(report.entries[0].provenance.status, 'resolved');
  return report.entries[0];
}

switch (process.argv[3] || 'prepare') {
  case 'prepare':
    prepare();
    break;
  case 'approve': {
    assert.equal(process.env.OUTCOME, 'failure', 'the unapproved upgrade must be blocked');
    const entry = reviewedUpgrade();
    const manifests = path.join(path.dirname(process.env.REVIEW_JSON), 'manifests');
    run('approve', manifests, '--baseline', 'capsurface.lock.json', '--id', entry.id,
      '--reason', 'Reviewed the test fixture');
    break;
  }
  case 'verify':
    assert.equal(process.env.GATE, 'false', 'the approved upgrade must pass');
    reviewedUpgrade();
    break;
  default:
    throw new Error('Expected prepare, approve or verify');
}
