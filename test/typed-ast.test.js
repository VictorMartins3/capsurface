'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadParser, astImports } = require('../lib/ast-imports');
const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const parser = loadParser();
assert.ok(parser.typed, 'install acorn-typescript@1.4.13 for the typed AST tests');
const analyze = (source, file = 'index.ts') => astImports(parser, source, file, 'script');

test('resolves typed aliases, satisfies, non-null assertions and generic calls with source lines', () => {
  const result = analyze("const load: NodeRequire = require as NodeRequire;\nconst again = load satisfies NodeRequire;\nagain!('child_process');\nload<string>('https');");
  assert.equal(result.parsed, true);
  assert.deepEqual(result.references, [
    { specifier: 'child_process', kind: 'require', line: 3 },
    { specifier: 'https', kind: 'require', line: 4 },
  ]);
});

test('erases type-only declarations and preserves possible side effects of value imports', () => {
  const result = analyze("import type { X } from 'https'; export type { Y } from 'fs';\ntype T = typeof import('child_process'); interface require {}\nimport { type Z } from 'undici'; import { type A, createRequire } from 'module';");
  assert.equal(result.parsed, true);
  // A value import with only inline type specifiers can still emit import {}.
  assert.deepEqual(result.references.map((r) => r.specifier), ['undici', 'module']);
  assert.deepEqual(analyze("type require = string; const load = require; load('https');").references.map((r) => r.specifier), ['https']);
});

test('declaration files do not acquire modules from type declarations or static imports', () => {
  const result = analyze("import { X } from 'https'; export * from 'fs'; import x = require('child_process');\nexport declare function f(): void; export enum E { A=1 }\ndeclare namespace N { type T = typeof import('vm'); }", 'index.d.ts');
  assert.equal(result.parsed, true);
  assert.deepEqual(result.references, []);
  const executable = analyze("require('https');", 'index.d.ts');
  assert.ok(!executable.parsed || executable.references.some((r) => r.specifier === 'https'));
  assert.equal(analyze('const =', 'index.d.ts').parsed, false);
});

test('typed parameters, ambient values and cast assignments preserve shadowing', () => {
  assert.deepEqual(analyze("class C { constructor(private require: any) { require('https'); } }\nfunction f(require: NodeRequire) { require('fs'); }").references, []);
  assert.deepEqual(analyze("declare const require: CustomLoader; require('https');").references, []);
  assert.equal(analyze("(eval as any)(source); require('https');").references[0].reason, 'ast-dynamic-scope');
  assert.deepEqual(analyze("const load = require; (require as any) = fake; load('https');").references, []);
  assert.equal(analyze("const mod = require('module'); ((mod as any).createRequire) = fake; mod.createRequire(__filename)('https');").references[0].reason, 'ast-module-mutation');
});

test('TypeScript import-equals supports acquisition and createRequire without guessing namespace aliases', () => {
  const result = analyze("import mod = require('node:module'); const load = mod.createRequire(__filename); load('https');\nimport require = require('custom-loader'); require('fs');");
  assert.equal(result.parsed, true);
  assert.deepEqual(result.references.map((r) => r.specifier), ['node:module', 'https', 'custom-loader']);
  assert.equal(analyze('import alias = Some.Namespace;').references[0].reason, 'ast-typescript-runtime-unsupported');
});

test('JSX and TSX expressions are visited while text and quoted attributes are not imports', () => {
  for (const file of ['component.jsx', 'component.tsx']) {
    const result = analyze("const load = require; const view = <div title=\"require('fs')\">require('vm'){load('https')}</div>;", file);
    assert.equal(result.parsed, true);
    assert.deepEqual(result.references.map((r) => r.specifier), ['https']);
  }
});

test('unsupported runtime TypeScript and parser budgets stay explicit', () => {
  for (const code of ['enum E { A=1 }', 'namespace N { export const x=1; }']) {
    assert.equal(analyze(code).references[0].reason, 'ast-typescript-runtime-unsupported');
  }
  assert.equal(analyze('const x = <NodeRequire>require;').references[0].reason, 'ast-parse-error');
  assert.equal(analyze('interface X {} const X = 1;').references[0].reason, 'ast-parse-error');
  assert.equal(analyze('type T = string;'.repeat(25000), 'index.d.ts').references[0].reason, 'ast-resource-limit');
  assert.equal(analyze(' '.repeat(1024 * 1024 + 1)).references[0].reason, 'ast-source-limit');
});

test('scans .mts and .cts files and respects their module modes', (t) => {
  const root = mkTmpDir('typed-extensions');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'typed' }, {
    'index.cts': "const load = require as NodeRequire; load('https');",
    'index.mts': "import { createRequire } from 'node:module'; const load = createRequire(import.meta.url); load('child_process');",
    'types.d.mts': "export type T = typeof import('fs');",
  });
  const manifest = scanPackageDir(dir, { deep: true });
  assert.equal(manifest.sourceFilesScanned, 3);
  assert.equal(manifest.astCoverage.complete, true);
  assert.equal(manifest.capabilities.network.present, true);
  assert.equal(manifest.capabilities.exec.present, true);
  assert.equal(manifest.capabilities.filesystem.present, false);
  assert.equal(runCli(['scan', dir, '--deep']).status, 0);
});

test('missing or incompatible typed parsers cannot silently certify typed coverage', (t) => {
  const root = mkTmpDir('typed-parser-isolation');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const tool = path.join(root, 'tool');
  for (const part of ['lib', 'bin', 'package.json']) fs.cpSync(path.join(__dirname, '..', part), path.join(tool, part), { recursive: true });
  const acornRoot = path.dirname(require.resolve('acorn/package.json'));
  fs.cpSync(acornRoot, path.join(tool, 'node_modules/acorn'), { recursive: true });
  const dir = writePackage(root, 'target', { name: 'typed' }, { 'index.ts': 'export type T = string;' });
  const cli = path.join(tool, 'bin/capsurface.js');
  const missing = spawnSync(process.execPath, [cli, 'scan', dir, '--deep'], { encoding: 'utf8', env: { ...process.env, NODE_PATH: '' } });
  assert.equal(missing.status, 2, missing.stderr);
  assert.equal(JSON.parse(missing.stdout).astCoverage.errors[0].reason, 'ast-typescript-parser-unavailable');
  writePackage(tool, 'node_modules/acorn-typescript', { name: 'acorn-typescript', version: '0.0.0', main: 'lib/index.js' }, {
    'lib/index.js': "throw Error('INCOMPATIBLE PARSER EXECUTED');",
  });
  const incompatible = spawnSync(process.execPath, [cli, 'scan', dir, '--deep'], { encoding: 'utf8' });
  assert.equal(incompatible.status, 2);
  assert.match(incompatible.stderr, /requires acorn-typescript@1.4.13/);
  assert.doesNotMatch(incompatible.stderr, /INCOMPATIBLE PARSER EXECUTED/);
  assert.equal(spawnSync(process.execPath, [cli, 'scan', dir]).status, 0);
});
