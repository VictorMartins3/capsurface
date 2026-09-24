'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { mkTmpDir, writePackage } = require('./helpers');
const { isolatedAst } = require('../lib/isolated-ast');
const { loadParser, astImports } = require('../lib/ast-imports');

test('isolated analysis preserves JS and typed results without executing source', () => {
  const parser = loadParser();
  for (const [file, code] of [['a.js', "throw Error('never execute'); require('fs');"],
    ['a.ts', "const name: string = 'https'; require(name);"]]) {
    assert.deepEqual(isolatedAst(code, file, 'script', parser.identity), astImports(parser, code, file, 'script'));
  }
  assert.equal(isolatedAst('const =', 'a.js', 'script', parser.identity).parsed, false);
  assert.equal(isolatedAst('', 'a.js', 'script', 'wrong-identity').references[0].reason, 'ast-worker-error');
});

test('hung worker is killed and reaped; deep coverage fails closed and later scans recover', (t) => {
  const root = mkTmpDir('ast-timeout');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const tool = path.join(root, 'tool');
  for (const part of ['lib', 'bin', 'package.json']) {
    fs.cpSync(path.join(__dirname, '..', part), path.join(tool, part), { recursive: true });
  }
  fs.cpSync(path.join(__dirname, '../node_modules'), path.join(tool, 'node_modules'), { recursive: true });
  const worker = path.join(tool, 'lib/ast-worker.js');
  const original = fs.readFileSync(worker, 'utf8');
  const pidFile = path.join(root, 'pid');
  // Deterministic synchronous stall, without depending on an Acorn vulnerability.
  fs.writeFileSync(worker, `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); while (true) {}`);
  const dir = writePackage(root, 'target', { name: 'target', version: '1.0.0' }, { 'index.js': 'const n = 1;' });
  const cli = path.join(tool, 'bin/capsurface.js');
  const scan = () => spawnSync(process.execPath, [cli, 'scan', dir, '--deep'], {
    encoding: 'utf8', timeout: 20000, killSignal: 'SIGKILL',
  });
  const result = scan();
  assert.equal(result.error, undefined, result.stderr);
  const manifest = JSON.parse(result.stdout);
  assert.equal(manifest.astCoverage.complete, false);
  assert.match(JSON.stringify(manifest.astCoverage), /ast-timeout/);
  const pid = Number(fs.readFileSync(pidFile, 'utf8'));
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  const { buildReview } = require('../lib/review');
  const review = buildReview(new Map([['target', [manifest]]]), new Map([['target', [manifest]]]));
  assert.equal(review.report.entries[0].approvable, false);
  assert.equal(review.report.entries[0].blocking, true);
  fs.writeFileSync(worker, 'process.exit(1);');
  assert.match(scan().stdout, /ast-worker-error/);
  fs.writeFileSync(worker, "process.stdout.write('{broken');");
  assert.match(scan().stdout, /ast-worker-error/);
  fs.writeFileSync(worker, original);
  assert.equal(JSON.parse(scan().stdout).astCoverage.complete, true);
});
