'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { mkTmpDir, writePackage } = require('./helpers');

// Run through npm run test:integration: npm_execpath selects the same npm
// version on Windows and Unix without shell expansion or registry access.
test('packed CLI reviews a real npm upgrade against the committed baseline', { timeout: 120000 }, (t) => {
  const tmp = mkTmpDir('npm-integration');
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, 'Run this test with npm run test:integration');
  const marker = path.join(tmp, 'executed-untrusted-code');
  const env = {
    ...process.env,
    npm_config_cache: path.join(tmp, 'cache'),
    npm_config_offline: 'true',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    CAPSURFACE_TEST_MARKER: marker,
  };
  function run(command, args, cwd, status = 0) {
    const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', timeout: 30000 });
    assert.ifError(result.error);
    assert.equal(result.status, status, `${command} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
    return result.stdout;
  }
  const npm = (args, cwd) => run(process.execPath, [npmCli, ...args], cwd);
  function pack(dir) {
    const result = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', tmp], dir));
    return path.join(tmp, result[0].filename);
  }
  const sentinel = "require('fs').writeFileSync(process.env.CAPSURFACE_TEST_MARKER, 'executed');";
  function dependency(version, source) {
    return writePackage(tmp, `dep-${version}`, {
      name: 'integration-dep', version,
      scripts: { preinstall: 'node hook.js', install: 'node hook.js', postinstall: 'node hook.js' },
      bin: { capsurface: 'shadow.js' },
    }, { 'index.js': source, 'hook.js': sentinel, 'shadow.js': `#!/usr/bin/env node\n${sentinel}` });
  }
  const oldTar = pack(dependency('1.0.0', 'module.exports = 1;'));
  const newTar = pack(dependency('2.0.0', "require('child_process');"));
  const extraTar = pack(writePackage(tmp, 'extra', { name: 'integration-extra', version: '1.0.0' }, {
    'index.js': "require('https');",
  }));
  const scannerTar = pack(path.join(__dirname, '..'));
  const tool = path.join(tmp, 'tool');
  npm(['install', '--prefix', tool, '--ignore-scripts', '--package-lock=false', scannerTar], tmp);
  const cli = path.join(tool, 'node_modules', 'capsurface', 'bin', 'capsurface.js');
  assert.ok(fs.existsSync(cli));
  assert.match(run(process.execPath, [cli, '--help'], tmp), /Usage:/);
  const installed = path.dirname(path.dirname(cli));
  const requiredDocs = ['README.md', 'LICENSE', 'CHANGELOG.md', 'CONTRIBUTING.md',
    'SECURITY.md', 'docs/REVIEW.md', 'docs/VERIFICATION.md', 'docs/RELEASING.md',
    'action.yml', 'examples/workflows/capsurface.yml', 'docs/GITLAB.md', 'examples/workflows/gitlab-ci.yml'];
  for (const file of requiredDocs) {
    assert.ok(fs.existsSync(path.join(installed, file)), `packed package must include ${file}`);
  }
  const expected = new Set(['package.json', ...requiredDocs]);
  const source = path.join(__dirname, '..');
  for (const dir of ['bin', 'lib']) {
    for (const file of fs.readdirSync(path.join(source, dir))) expected.add(`${dir}/${file}`);
  }
  function files(dir, prefix = '') {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const relative = prefix + entry.name;
      return entry.isDirectory() ? files(path.join(dir, entry.name), relative + '/') : [relative];
    });
  }
  assert.deepEqual(files(installed).sort(), [...expected].sort(),
    'ship runtime sources and documentation, without tests, caches or generated reports');
  assert.equal(require(path.join(installed, 'lib/rules-version')).RULES_VERSION,
    require('../lib/rules-version').RULES_VERSION, 'packing must preserve the engine fingerprint');
  assert.equal(fs.existsSync(path.join(tool, 'node_modules', 'acorn')), false,
    'the default installation must not require optional parsers');
  assert.equal(fs.existsSync(path.join(tool, 'node_modules', 'yaml')), false,
    'the default installation must not require the pnpm parser');
  const yamlLock = path.join(tmp, 'pnpm-lock.yaml');
  fs.writeFileSync(yamlLock, "lockfileVersion: '9.0'\nimporters:\n  .: {}\n");
  const missingYaml = spawnSync(process.execPath, [cli, 'scan-lock', yamlLock,
    '--tarballs', path.join(tmp, 'unused-map.json'), '--out', path.join(tmp, 'pnpm-output')],
  { cwd: tmp, encoding: 'utf8', env });
  assert.equal(missingYaml.status, 2);
  assert.match(missingYaml.stderr, /Install yaml@2\.9\.1 alongside capsurface/);
  const project = writePackage(tmp, 'project', { name: 'integration-project', version: '1.0.0', private: true });
  const scan = (...args) => run(process.execPath, [cli, ...args], project);
  const gate = (args, status) => run(process.execPath, [cli, ...args], project, status);
  const archiveUrl = 'https://registry.example/integration-dep-1.0.0.tgz';
  const archiveIntegrity = 'sha512-' + require('crypto').createHash('sha512')
    .update(fs.readFileSync(oldTar)).digest('base64');
  fs.writeFileSync(path.join(project, 'archive-map.json'), JSON.stringify({ [archiveUrl]: oldTar }));
  fs.writeFileSync(path.join(project, 'archive-lock.json'), JSON.stringify({ lockfileVersion: 3,
    packages: { '': {}, 'node_modules/integration-dep': {
      version: '1.0.0', resolved: archiveUrl, integrity: archiveIntegrity,
    } } }));
  scan('scan-lock', 'archive-lock.json', '--tarballs', 'archive-map.json', '--out', 'archive-manifests');
  scan('baseline', 'archive-manifests', '--out', 'archive-baseline.json');
  gate(['check', 'archive-manifests', '--baseline', 'archive-baseline.json'], 0);
  assert.equal(fs.existsSync(marker), false, 'packed archive scanning must not execute install hooks');
  const git = (...args) => run('git', args, project);
  npm(['install', '--ignore-scripts', '--save-exact', oldTar], project);
  npm(['ci', '--ignore-scripts'], project);
  scan('scan-tree', 'node_modules', '--out', 'manifests');
  scan('baseline', 'manifests', '--out', 'capsurface.lock.json');
  git('init', '--quiet');
  git('add', 'capsurface.lock.json');
  git('-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid',
    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + path.join(tmp, 'no-hooks'),
    'commit', '--quiet', '-m', 'Record the reviewed dependency');
  const baseSha = git('rev-parse', 'HEAD').trim();
  npm(['install', '--ignore-scripts', '--save-exact', newTar, extraTar], project);
  npm(['ci', '--ignore-scripts'], project);
  assert.equal(fs.existsSync(marker), false, 'install hooks must never execute');
  // The project has a competing capsurface bin. All commands still use the
  // separately installed tarball, exactly as the adoption workflow does.
  assert.ok(fs.existsSync(path.join(project, 'node_modules', 'integration-dep', 'shadow.js')));
  assert.ok(fs.existsSync(path.join(project, 'node_modules', '.bin',
    process.platform === 'win32' ? 'capsurface.cmd' : 'capsurface')));
  scan('scan-tree', 'node_modules', '--out', 'manifests');
  const target = path.join(tmp, 'target-baseline.json');
  fs.writeFileSync(target, git('show', `${baseSha}:capsurface.lock.json`));
  const reviewArgs = ['review', 'manifests', '--baseline', target, '--fail-on-new', '--json', '--lockfile', 'package-lock.json'];
  const before = JSON.parse(gate(reviewArgs, 1));
  assert.equal(before.entries.length, 2);
  const changed = before.entries.find((entry) => entry.name === 'integration-dep');
  assert.ok(changed.escalated);
  assert.equal(changed.provenance.status, 'resolved');
  assert.deepEqual(changed.provenance.chain.map((p) => p.name), ['integration-project', 'integration-dep']);
  assert.ok(changed.evidence.some((e) => e.file === 'index.js'));
  fs.writeFileSync(path.join(project, 'saved-review.json'), JSON.stringify(before));
  const explained = JSON.parse(scan('explain', '--report', 'saved-review.json', '--id', changed.id, '--json'));
  assert.deepEqual(explained.entry, changed, 'the packed CLI retains provenance and all source evidence');
  assert.equal(explained.source.freshness, 'not-checked');
  assert.equal(changed.baselineEvidence.length, 1);
  assert.equal(changed.baselineEvidence[0].version, '1.0.0');
  assert.equal(changed.baselineEvidence[0].analysisIncomplete, false);
  assert.ok(!changed.baselineEvidence[0].evidence.some((e) => e.category === 'exec'),
    'the old archive has no detected child_process indicator');
  scan('review', 'manifests', '--baseline', target, '--fail-on-new', '--report-only', '--out', 'review.md');
  assert.match(fs.readFileSync(path.join(project, 'review.md'), 'utf8'), /Review ID:/);
  const check = ['check', 'manifests', '--baseline', 'capsurface.lock.json', '--fail-on-new'];
  gate(check, 1);
  function gitlab(name, expected, overrides = {}) {
    const output = path.join(project, '.capsurface', name);
    const result = spawnSync(process.execPath, [path.join(installed, 'bin/gitlab-review.js')], {
      cwd: project, encoding: 'utf8', env: { ...env, CI_PROJECT_DIR: project,
        CI_PIPELINE_SOURCE: 'merge_request_event', CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
        CI_PROJECT_ID: '1', CI_MERGE_REQUEST_SOURCE_PROJECT_ID: '1', CI_MERGE_REQUEST_TARGET_PROJECT_ID: '1',
        CI_MERGE_REQUEST_IID: '2', CI_PIPELINE_ID: '3', CI_JOB_ID: '4', CI_COMMIT_SHA: baseSha,
        CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main', CAPSURFACE_PROJECT: project,
        CAPSURFACE_BASE_REF: baseSha, CAPSURFACE_OUTPUT: output, CAPSURFACE_DEEP: 'false',
        CAPSURFACE_FAIL_ON_NEW: 'true', CAPSURFACE_REPORT_ONLY: 'false', ...overrides },
    });
    assert.equal(result.status, expected, result.stderr);
    return output;
  }
  const blockedGitlab = gitlab('gitlab-blocked', 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(blockedGitlab, 'status.json'))).gate, true);
  assert.equal(gitlab('gitlab-report-only', 0, { CAPSURFACE_REPORT_ONLY: 'true' }).length > 0, true);
  const missingGitlab = gitlab('gitlab-missing', 2, { CAPSURFACE_BASELINE: 'missing.json' });
  assert.equal(JSON.parse(fs.readFileSync(path.join(missingGitlab, 'status.json'))).complete, false);
  gitlab('gitlab-fork', 2, { CI_MERGE_REQUEST_SOURCE_PROJECT_ID: '9' });
  scan('approve', 'manifests', '--baseline', 'capsurface.lock.json', '--id', changed.id,
    '--reason', 'Reviewed the child process integration');
  gate(check, 1); // Approving the upgrade cannot approve the added package.
  const added = before.entries.find((entry) => entry.name === 'integration-extra');
  scan('approve', 'manifests', '--baseline', 'capsurface.lock.json', '--id', added.id,
    '--reason', 'Reviewed the additional HTTP client');
  gate(check, 0);
  const approvedGitlab = gitlab('gitlab-approved', 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(approvedGitlab, 'status.json'))).gate, false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(approvedGitlab, 'review.json'))).wouldFail, true,
    'GitLab proposed approvals must not hide the target-branch comparison');
  assert.ok(fs.existsSync(path.join(approvedGitlab, 'review.md')));
  assert.ok(fs.existsSync(path.join(approvedGitlab, 'review.sarif')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(approvedGitlab, 'manifests/.capsurface-snapshot'))).complete, true);
  gitlab('gitlab-approved', 2); // Never retain stale artifacts from a reused directory.
  const approvedArgs = ['review', 'manifests', '--baseline', 'capsurface.lock.json'];
  const approved = JSON.parse(gate([...approvedArgs, '--json'], 0));
  assert.equal(approved.entries.length, 0);
  assert.equal(approved.audit.counts.approved, 2);
  const approval = approved.audit.installations.find((item) => item.name === 'integration-dep').approval;
  assert.equal(approval.status, 'applied');
  assert.equal(approval.reason, 'Reviewed the child process integration',
    'the installed CLI must join the baseline approval history');
  const approvedSarif = JSON.parse(gate([...approvedArgs, '--format', 'sarif'], 0));
  assert.equal(approvedSarif.runs[0].results.length, 0);
  assert.deepEqual(approvedSarif.runs[0].properties.audit, approved.audit,
    'passing SARIF reviews must retain approval information');
  const after = JSON.parse(gate(reviewArgs, 1));
  assert.deepEqual(after, before, 'proposed approvals must not hide changes from the target-branch review');
  const actionOutput = path.join(tmp, 'action-output');
  const summary = path.join(tmp, 'summary.md');
  const action = spawnSync(process.execPath, [path.join(tool, 'node_modules', 'capsurface', 'bin', 'action-review.js')], {
    cwd: project, encoding: 'utf8', env: { ...env, RUNNER_TEMP: tmp, CAPSURFACE_BASE_REF: baseSha,
      GITHUB_OUTPUT: actionOutput, GITHUB_STEP_SUMMARY: summary },
  });
  assert.equal(action.status, 0, action.stderr);
  const outputs = Object.fromEntries(fs.readFileSync(actionOutput, 'utf8').trim().split('\n').map((line) => {
    const split = line.indexOf('='); return [line.slice(0, split), line.slice(split + 1)];
  }));
  assert.equal(outputs['would-fail'], 'false');
  assert.match(fs.readFileSync(summary, 'utf8'), /Proposed baseline check: \*\*PASS/);
  assert.match(fs.readFileSync(summary, 'utf8'), /The capability check would fail/);
  const sarif = JSON.parse(fs.readFileSync(outputs.sarif));
  assert.equal(sarif.runs[0].results.length, 2);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  // A payload outside source detection still invalidates a content approval.
  fs.writeFileSync(path.join(project, 'node_modules', 'integration-dep', 'payload.bin'), Buffer.from([0, 255, 1]));
  scan('scan-tree', 'node_modules', '--out', 'manifests');
  gate(check, 1);
  const contentReview = JSON.parse(gate(['review', 'manifests', '--baseline', 'capsurface.lock.json', '--json'], 1));
  assert.equal(contentReview.entries.length, 1);
  assert.ok(contentReview.entries[0].changes.some((change) => change.type === 'approval-content-changed'));
  scan('approve', 'manifests', '--baseline', 'capsurface.lock.json', '--id', contentReview.entries[0].id,
    '--reason', 'Reviewed the added binary asset', '--expires', '2099-01-01T00:00:00Z');
  gate(check, 0);
  const inventory = path.join(project, 'manifests', '.capsurface-snapshot');
  assert.equal(JSON.parse(fs.readFileSync(inventory)).complete, true);
  fs.writeFileSync(inventory, JSON.stringify({ schemaVersion: 1, complete: false }));
  gate([...check, '--report-only'], 2);
  fs.writeFileSync(path.join(project, 'node_modules', 'integration-dep', 'package.json'), '{');
  const incompleteGitlab = gitlab('gitlab-incomplete', 2, { CAPSURFACE_REPORT_ONLY: 'true' });
  const incompleteStatus = JSON.parse(fs.readFileSync(path.join(incompleteGitlab, 'status.json')));
  assert.ok(!incompleteStatus.complete || incompleteStatus.incomplete,
    'GitLab report-only cannot turn incomplete analysis into a successful review');
  assert.equal(fs.existsSync(marker), false, 'neither lifecycle hooks nor the shadow CLI may execute');
});
