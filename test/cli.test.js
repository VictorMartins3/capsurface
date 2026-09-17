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

// A baseline records what the rules said when it was approved. Change a
// rule and the same dependency produces a different manifest, so the
// baseline silently starts meaning something else. That happened while
// tuning this tool against real projects and nothing reported it.
describe('rules-version drift', () => {
  test('warns when the baseline was written by different rules', () => {
    const tmp = mkTmpDir('rules-drift');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);

    // Rewrite the baseline as if an older ruleset had produced it.
    const lock = JSON.parse(fs.readFileSync(path.join(tmp, 'lock.json'), 'utf8'));
    for (const arr of Object.values(lock.packages)) {
      for (const m of arr) m.rulesVersion = 'deadbeef0000';
    }
    fs.writeFileSync(path.join(tmp, 'lock.json'), JSON.stringify(lock));

    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);
    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.match(res.stderr, /different scanning rules/);
  });

  test('stays quiet when the baseline matches the current rules', () => {
    const tmp = mkTmpDir('rules-match');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);
    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.ok(!/different scanning rules/.test(res.stderr));
    assert.equal(res.status, 0);
  });
});

// npm 12 and its peers block install scripts unless a project lists what may
// run one. Producing the list is mechanical; deciding what belongs on it
// needs to know what each script reaches for, which the manifest holds.
describe('capsurface allowlist', () => {
  function treeWith(tmp, packages) {
    for (const [rel, pkgJson, files] of packages) {
      writePackage(tmp, path.join('node_modules', rel), pkgJson, files);
    }
    const out = path.join(tmp, 'manifests');
    const res = runCli(['scan-tree', path.join(tmp, 'node_modules'), '--out', out]);
    assert.equal(res.status, 0, res.stderr);
    return out;
  }

  const NATIVE = ['native-thing', { name: 'native-thing', version: '2.0.0', scripts: { install: 'node-gyp rebuild' } },
    { 'index.js': "const cp = require('child_process');\nfetch('https://binaries.example.com/x');\n" }];
  const QUIET = ['quiet-lib', { name: 'quiet-lib', version: '1.0.0' }, { 'index.js': "require('fs');\n" }];

  test('lists only the packages that run something at install time, and says why', () => {
    const tmp = mkTmpDir('allowlist');
    const res = runCli(['allowlist', treeWith(tmp, [NATIVE, QUIET])]);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /1 of 2 installed package\(s\) run code at install time/);
    assert.match(res.stdout, /"allowScripts"/);
    assert.match(res.stdout, /"native-thing@2\.0\.0"/);
    assert.ok(!res.stdout.includes('quiet-lib@1.0.0'), 'a package with no install script is not on the list');
    assert.match(res.stdout, /install\s+node-gyp rebuild/);
    assert.match(res.stdout, /reaches\s+.*process execution/);
    assert.match(res.stdout, /talks to\s+https:\/\/binaries\.example\.com\/x/);
  });

  test('--names drops the version pin', () => {
    const tmp = mkTmpDir('allowlist-names');
    const res = runCli(['allowlist', treeWith(tmp, [NATIVE]), '--names']);
    assert.match(res.stdout, /"native-thing"/);
    assert.ok(!res.stdout.includes('"native-thing@2.0.0"'));
  });

  test('--format pnpm emits the workspace key', () => {
    const tmp = mkTmpDir('allowlist-pnpm');
    const res = runCli(['allowlist', treeWith(tmp, [NATIVE]), '--format', 'pnpm']);
    assert.match(res.stdout, /onlyBuiltDependencies:/);
    assert.match(res.stdout, /- native-thing@2\.0\.0/);
  });

  test('--format json is machine readable and carries the rules fingerprint', () => {
    const tmp = mkTmpDir('allowlist-json');
    const res = runCli(['allowlist', treeWith(tmp, [NATIVE, QUIET]), '--format', 'json']);
    const payload = JSON.parse(res.stdout);
    assert.deepEqual(payload.allow, ['native-thing@2.0.0']);
    assert.equal(payload.packagesScanned, 2);
    assert.equal(payload.packages[0].scripts.install, 'node-gyp rebuild');
    assert.ok(payload.rulesVersion);
  });

  test('says so when a tree needs no allowlist at all', () => {
    const tmp = mkTmpDir('allowlist-empty');
    const res = runCli(['allowlist', treeWith(tmp, [QUIET])]);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /Nothing to allow/);
  });
});

// The check skipped any package whose version string matched one already in
// the baseline, without looking at its content. That is the shape of a
// postinstall in one package rewriting a sibling's files: the version never
// changes, so the diff never ran.
describe('tampering under an unchanged version', () => {
  test('is caught', () => {
    const tmp = mkTmpDir('same-version-tamper');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);

    // Same version, new capability and a new install script.
    writePackage(tmp, 'v1b', { name: 'p', version: '1.0.0', scripts: { postinstall: 'node x.js' } }, {
      'index.js': "require('fs');\nrequire('https');\nconst t = process.env.NPM_TOKEN;\n",
    });
    runCli(['scan', path.join(tmp, 'v1b'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);

    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.equal(res.status, 1, 'a package tampered under the same version must fail the gate');
    assert.match(res.stdout, /CRITICAL/);
  });

  test('an untouched package at a baselined version stays quiet', () => {
    const tmp = mkTmpDir('same-version-clean');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);

    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /No capability escalations/);
  });

  // The union exists so a capability approved in any installed version is not
  // treated as new. It must not launder tampering of a different version.
  test('a capability approved only in a sibling version does not excuse it here', () => {
    const tmp = mkTmpDir('same-version-union');
    writePackage(tmp, 'a', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    writePackage(tmp, 'b', { name: 'p', version: '2.0.0' }, { 'index.js': "require('https');\n" });
    runCli(['scan', path.join(tmp, 'a'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['scan', path.join(tmp, 'b'), '--out', path.join(tmp, 'base/p@2.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);

    // 1.0.0 gains network, which only 2.0.0 was ever approved for.
    writePackage(tmp, 'a2', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\nrequire('https');\n" });
    runCli(['scan', path.join(tmp, 'a2'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);

    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.equal(res.status, 1);
    assert.match(res.stdout, /Network access/);
  });
});

// Nobody turns a blocking gate on in an unfamiliar codebase on day one.
describe('--report-only', () => {
  function tamperedTree() {
    const tmp = mkTmpDir('report-only');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);
    writePackage(tmp, 'v2', { name: 'p', version: '1.0.1', scripts: { postinstall: 'node x.js' } }, {
      'index.js': "require('https');\nconst t = process.env.NPM_TOKEN;\n",
    });
    runCli(['scan', path.join(tmp, 'v2'), '--out', path.join(tmp, 'cur/p@1.0.1.json')]);
    return tmp;
  }

  test('reports the same findings but exits 0', () => {
    const tmp = tamperedTree();
    const gated = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json')]);
    assert.equal(gated.status, 1);

    const reported = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json'), '--report-only']);
    assert.equal(reported.status, 0);
    assert.match(reported.stdout, /CAPABILITY ESCALATIONS/);
    assert.match(reported.stdout, /REPORT ONLY/);
    assert.match(reported.stdout, /would have failed the build/);
  });

  test('says plainly when there was nothing to suppress', () => {
    const tmp = mkTmpDir('report-only-clean');
    writePackage(tmp, 'v1', { name: 'p', version: '1.0.0' }, { 'index.js': "require('fs');\n" });
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'base/p@1.0.0.json')]);
    runCli(['baseline', path.join(tmp, 'base'), '--out', path.join(tmp, 'lock.json')]);
    runCli(['scan', path.join(tmp, 'v1'), '--out', path.join(tmp, 'cur/p@1.0.0.json')]);

    const res = runCli(['check', path.join(tmp, 'cur'), '--baseline', path.join(tmp, 'lock.json'), '--report-only']);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /nothing would have failed anyway/);
  });
});
