'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir, blankComments } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { buildReview } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function scan(source, filename = 'index.js') {
  return scanPackageDir(writePackage(mkTmpDir('fs-ops'), 'pkg', { name: 'pkg', version: '1.0.0' }, { [filename]: source }));
}
const keys = ['filesystemRead', 'filesystemWrite', 'filesystemRemove'];
function operations(manifest) { return keys.filter((key) => manifest.capabilities[key].present); }

for (const [source, expected] of [
  ["const fs = require('fs')\nfs.rm('x')", ['filesystemRemove']],
  ["const {rm} = require('fs').promises;", ['filesystemRemove']],
  ["require(`fs`).readFileSync('x');", ['filesystemRead']],
  ["require('fs').readFileSync('x');", ['filesystemRead']],
  ["require('node:fs/promises')['writeFile']('x', 'y');", ['filesystemWrite']],
  ["require('fs').promises.rm('x');", ['filesystemRemove']],
  ["const disk = require('fs');\ndisk.readFileSync('x'); disk.rmSync('x');", ['filesystemRead', 'filesystemRemove']],
  ["const s = require('node:fs').promises; s.writeFile('x','y');", ['filesystemWrite']],
  ["import * as disk from 'node:fs'; disk.unlinkSync('x');", ['filesystemRemove']],
  ["import disk from 'fs/promises'; disk?.readFile('x');", ['filesystemRead']],
  ["const { readFile, rm: remove } = require('fs/promises');", ['filesystemRead', 'filesystemRemove']],
  ["import { writeFile as save, rm } from 'node:fs/promises';", ['filesystemWrite', 'filesystemRemove']],
  ["import {\n readFile,\n rm as remove\n} from 'fs/promises';", ['filesystemRead', 'filesystemRemove']],
  ["import { type rm, readFile } from 'fs';", ['filesystemRead']],
]) {
  test(`classifies literal filesystem API selection: ${source.split('\n')[0]}`, () => {
    assert.deepEqual(operations(scan(source)), expected);
  });
}

for (const source of [
  "const fs = require('fs') && custom; fs.rm();",
  "const fs = require('fs')\n && custom; fs.rm();",
  "const {rm} = require('fs') && custom; rm();",
  "const {rm} = require('fs').custom; rm();",
  "require('fs').rm = customRemove;",
  "const fs = {rm() {}}; fs.rm();",
  "const fs = require('fs'); function remove(fs) { fs.rm(); }",
  "let fs = require('fs'); fs = somethingElse; fs.rm();",
  "const fs = require('fs'); fs.rm = customRemove; fs.rm();",
  "const fs = require('fs'); consume(fs); fs.rm();",
  "const text = \"require('fs').rm('x')\";",
  "const example = `const fs = require('fs'); fs.rm('x');`;",
  "const example = /require('fs').rm/;",
  "// require('fs').rm('x')\n/* const { rm } = require('fs'); */",
  "import type { rm } from 'fs';",
  "const fs = require('fs'); obj.fs.rm();",
  "const fs = require('fs'); fs.open('x', flags);",
]) {
  test(`does not invent filesystem operations: ${source.split('\n')[0]}`, () => {
    assert.deepEqual(operations(scan(source)), []);
  });
}

test('declaration files do not grant operations from erased imports', () => {
  assert.deepEqual(operations(scan("import { rm } from 'fs';", 'index.d.ts')), []);
  assert.deepEqual(operations(scan("require('fs').rm('x');", 'index.d.ts')), ['filesystemRemove']);
});

test('bindings stay file-local and retain original evidence lines', () => {
  const root = mkTmpDir('fs-ops-files');
  const manifest = scanPackageDir(writePackage(root, 'pkg', { name: 'pkg', version: '1' }, {
    'a.js': "const fs = require('fs');",
    'b.js': 'fs.rmSync("x");',
    'c.js': "const disk = require('fs');\n// a comment\ndisk.writeFileSync('x', 'y');",
  }));
  assert.deepEqual(operations(manifest), ['filesystemWrite']);
  assert.equal(manifest.capabilities.filesystemWrite.evidence[0].file, 'c.js');
  assert.equal(manifest.capabilities.filesystemWrite.evidence[0].line, 3);
});

test('a read-only baseline blocks newly acquired write and removal APIs', () => {
  const baseline = scan("const fs = require('fs'); fs.readFileSync('x');");
  const current = scan("const fs = require('fs'); fs.readFileSync('x'); fs.writeFileSync('x', 'y'); fs.rmSync('x');");
  const diff = diffManifests(baseline, current);
  assert.equal(diff.escalated, true);
  assert.deepEqual(diff.changes.filter((c) => c.escalates).map((c) => c.category), ['filesystemWrite', 'filesystemRemove']);
  assert.equal(current.riskScore, baseline.riskScore, 'detail must not duplicate the parent score');
  assert.equal(diffManifests(current, baseline).escalated, false);
  assert.equal(diffManifests(current, current).escalated, false);
});

test('older baselines require review without calling newly observed detail a new dependency behavior', () => {
  const current = scan("require('fs').rmSync('x');");
  const baseline = JSON.parse(JSON.stringify(current));
  for (const key of keys) delete baseline.capabilities[key];
  baseline.schemaVersion = 4;
  const diff = diffManifests(baseline, current);
  assert.equal(diff.escalated, true);
  assert.equal(diff.changes[0].type, 'capability-detail-unreviewed');
  assert.match(diff.changes[0].detail, /engine migration/);
  assert.equal(diffManifests(baseline, baseline).escalated, false);
});

test('review and SARIF expose granular evidence and selective approval clears the gate', () => {
  const baseline = scan("require('fs').readFileSync('x');");
  const current = scan("require('fs').rmSync('x');");
  const report = buildReview(new Map([['pkg', [baseline]]]), new Map([['pkg', [current]]])).report;
  assert.ok(report.entries[0].evidence.some((e) => e.category === 'filesystemRemove'));
  assert.match(renderSarif(report).runs[0].results[0].message.text, /Filesystem removal/);
  const root = mkTmpDir('fs-ops-cli');
  const out = path.join(root, 'manifests');
  fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'pkg.json'), JSON.stringify(current));
  const lock = path.join(root, 'baseline.json');
  fs.writeFileSync(lock, JSON.stringify({ schemaVersion: 2, packages: { pkg: [baseline] } }));
  assert.equal(runCli(['check', out, '--baseline', lock]).status, 1);
  assert.equal(runCli(['approve', out, '--baseline', lock, '--id', report.entries[0].id, '--reason', 'Reviewed cleanup support']).status, 0);
  assert.equal(runCli(['check', out, '--baseline', lock]).status, 0);
});

test('literal masking preserves offsets, regex character classes and escaped quotes', () => {
  const source = 'const g = "a\\\"b";\nconst re = /["/]/g; // comment\ng.rm();';
  const masked = blankComments(source, true);
  assert.equal(masked.length, source.length);
  assert.equal(masked.split('\n').length, source.split('\n').length);
  assert.match(masked, /g\.rm\(\)/);
  assert.ok(!masked.includes('comment'));
  assert.ok(!masked.includes('"'));
  assert.deepEqual(operations(scan("const g = require('fs'); /[\"/]/g.test('g'); g.rm('x');")), ['filesystemRemove']);
});

test('multiline operation evidence points at the selected API', () => {
  const named = scan("import {\n  rm as remove\n} from 'fs';");
  const direct = scan("require('fs')\n  .rm('x');");
  assert.equal(named.capabilities.filesystemRemove.evidence[0].line, 2);
  assert.equal(direct.capabilities.filesystemRemove.evidence[0].line, 2);
});

test('long blanked comments do not cause quadratic member matching', () => {
  const root = mkTmpDir('fs-ops-spacing');
  const pkg = writePackage(root, 'pkg', { name: 'pkg', version: '1' }, {
    'index.js': "const fs = require('fs') /*" + 'x'.repeat(100000) + "*/; fs.rm('x');",
  });
  const result = runCli(['scan', pkg], { timeout: 5000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).capabilities.filesystemRemove.present, true);
});
