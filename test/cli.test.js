'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { mkTmpDir, writePackage, runCli } = require('./helpers');

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

describe('end-to-end scan / baseline / check pipeline', () => {
  test('catches the bundled Shai-Hulud-style escalation fixture (examples/malicious-pkg-v1 -> v2)', () => {
    const tmp = mkTmpDir('demo');
    const repoRoot = path.join(__dirname, '..');

    const scanV1 = runCli(['scan', path.join(repoRoot, 'examples/malicious-pkg-v1'), '--out', path.join(tmp, 'baseline-manifests/handy-color-utils@2.3.0.json')]);
    assert.equal(scanV1.status, 0);

    const baseline = runCli(['baseline', path.join(tmp, 'baseline-manifests'), '--out', path.join(tmp, 'capsurface.lock.json')]);
    assert.equal(baseline.status, 0);

    const scanV2 = runCli(['scan', path.join(repoRoot, 'examples/malicious-pkg-v2'), '--out', path.join(tmp, 'current-manifests/handy-color-utils@2.3.1.json')]);
    assert.equal(scanV2.status, 0);

    const check = runCli(['check', path.join(tmp, 'current-manifests'), '--baseline', path.join(tmp, 'capsurface.lock.json')]);
    assert.equal(check.status, 1, 'check must fail (exit 1) on the compromised release');
    assert.match(check.stdout, /CRITICAL/);
    assert.match(check.stdout, /telemetry-collector\.example-exfil\.net/);
  });

  test('a clean version bump with no new capabilities passes the check', () => {
    const tmp = mkTmpDir('clean-bump');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    writePackage(tmp, 'v2', { name: 'p', version: '1.0.1' }, { 'index.js': "require('fs');\n" });

    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'baseline-manifests/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'baseline-manifests'), '--out', path.join(tmp, 'capsurface.lock.json')]);
    runCli(['scan', path.join(tmp, 'v2'), '--out', path.join(tmp, 'current-manifests/p@1.0.1.json')]);
    const check = runCli(['check', path.join(tmp, 'current-manifests'), '--baseline', path.join(tmp, 'capsurface.lock.json')]);
    assert.equal(check.status, 0);
    assert.match(check.stdout, /No capability escalations/);
  });

  test('a package not in the baseline is reported but does not fail without --fail-on-new', () => {
    const tmp = mkTmpDir('new-pkg');
    fs.mkdirSync(path.join(tmp, 'baseline-manifests'), { recursive: true });
    writeJson(path.join(tmp, 'capsurface.lock.json'), { schemaVersion: 2, packages: {} });
    writePackage(tmp, 'new', { name: 'new-pkg', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    runCli(['scan', path.join(tmp, 'new'), '--out', path.join(tmp, 'current-manifests/new-pkg@1.0.0.json')]);

    const withoutFlag = runCli(['check', path.join(tmp, 'current-manifests'), '--baseline', path.join(tmp, 'capsurface.lock.json')]);
    assert.equal(withoutFlag.status, 0);
    assert.match(withoutFlag.stdout, /NEW packages not in baseline/);

    const withFlag = runCli(['check', path.join(tmp, 'current-manifests'), '--baseline', path.join(tmp, 'capsurface.lock.json'), '--fail-on-new']);
    assert.equal(withFlag.status, 1);
  });

  // Backward compatibility: the lock file schema changed from
  // `packages: {name: Manifest}` (v1) to `packages: {name: Manifest[]}`
  // (v2) to support multiple installed versions of the same package name.
  // A lock file committed by an earlier version of this tool must keep
  // working without a manual migration step.
  test('reads an old schemaVersion-1 lock file (single manifest per name) without error', () => {
    const tmp = mkTmpDir('old-lock');
    writePackage(tmp, 'v2', { name: 'p', version: '1.0.1', scripts: { postinstall: 'node evil.js' } }, {
      'evil.js': "require('https'); const t = process.env.NPM_TOKEN;\n",
    });
    const v1Manifest = {
      schemaVersion: 1,
      name: 'p',
      version: '1.0.0',
      capabilities: {
        filesystem: { present: false, evidence: [] },
        network: { present: false, evidence: [], endpoints: [] },
        exec: { present: false, evidence: [] },
        env: { present: false, evidence: [], vars: [] },
        dynamicEval: { present: false, evidence: [] },
        nativeFfi: { present: false, evidence: [] },
        sensitiveTargets: { present: false, evidence: [] },
        lifecycleScripts: { present: false, scripts: {} },
        obfuscationSignal: { present: false, evidence: [] },
      },
      riskScore: 0,
      riskFlags: [],
    };
    // Old schema: packages keyed directly to a single manifest object.
    writeJson(path.join(tmp, 'capsurface.lock.json'), { schemaVersion: 1, packages: { p: v1Manifest } });

    runCli(['scan', path.join(tmp, 'v2'), '--out', path.join(tmp, 'current-manifests/p@1.0.1.json')]);
    const check = runCli(['check', path.join(tmp, 'current-manifests'), '--baseline', path.join(tmp, 'capsurface.lock.json')]);
    assert.equal(check.status, 1, 'escalation must still be caught against an old-schema lock file');
    assert.match(check.stdout, /CRITICAL/);
  });

  test('capsurface diff exits non-zero and prints structured JSON on escalation', () => {
    const tmp = mkTmpDir('diff-cmd');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': 'module.exports = {};\n' });
    writePackage(tmp, 'v2', { name: 'p', version: '1.0.1', scripts: { postinstall: 'node x.js' } }, {
      'index.js': "require('https');\n",
    });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'v1.json')]);
    runCli(['scan', path.join(tmp, 'v2'), '--out', path.join(tmp, 'v2.json')]);
    const diff = runCli(['diff', path.join(tmp, 'v1.json'), path.join(tmp, 'v2.json')]);
    assert.equal(diff.status, 1);
    const report = JSON.parse(diff.stdout);
    assert.equal(report.escalated, true);
  });
});
