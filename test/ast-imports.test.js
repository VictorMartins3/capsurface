'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { astImports, loadParser } = require('../lib/ast-imports');
const { scanPackageDir } = require('../lib/scanner');
const { installLines } = require('../lib/install-context');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { diffManifests } = require('../lib/diff');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const parser = loadParser();
const analyze = (code, type = 'script', file = 'install.js') => astImports(parser, code, file, type);
const specifiers = (code, type) => analyze(code, type).references.filter((r) => r.specifier).map((r) => r.specifier);

test('resolves immutable require aliases and static template strings with original lines', () => {
  const result = analyze("const load = require; const name = 'worker';\nconst again = load;\nagain(`./${name}.js`); load('./' + 'other.js');");
  assert.equal(result.parsed, true);
  assert.deepEqual(result.references, [
    { specifier: './worker.js', kind: 'require', line: 3 },
    { specifier: './other.js', kind: 'require', line: 3 },
  ]);
});

test('resolves createRequire only when its base is the current source file', () => {
  assert.deepEqual(specifiers("const { createRequire: make } = require('node:module'); const load = make(__filename); load('./a');"), ['node:module', './a']);
  assert.deepEqual(specifiers("import { createRequire as make } from 'node:module'; const load = make(import.meta.url); load('./a');", 'module'), ['node:module', './a']);
  assert.deepEqual(specifiers("import * as mod from 'module'; const load = mod.createRequire(import.meta.url); load('./a');", 'module'), ['module', './a']);
  const unknown = analyze("const make = require('module').createRequire; const load = make('/other/index.js'); load('./a');");
  assert.equal(unknown.references[1].reason, 'create-require-base-unsupported');
  assert.deepEqual(specifiers("function f(__filename) { const load = require('module').createRequire(__filename); load('./a'); }"), ['module']);
});

test('respects parameters, destructuring, catch, lexical and hoisted var shadowing', () => {
  const source = `
    require('./outer');
    function a(require) { require('./parameter'); }
    function b({ require }) { require('./destructured'); }
    function c() { require('./hoisted'); if (true) { var require; } }
    { require('./tdz'); const require = other; }
    try {} catch (require) { require('./catch'); }
    for (const require of loaders) { require('./loop'); }
    const f = function require() { require('./self'); };
    class requireClass { method(require) { require('./method'); } }
    require('./last');`;
  assert.deepEqual(specifiers(source), ['./outer', './last']);
});

test('does not trust mutable aliases, reassigned loaders or overwritten module members', () => {
  assert.deepEqual(specifiers("let load = require; load('./a');"), []);
  assert.deepEqual(specifiers("const load = require; load('./a'); function mutate() { require = fake; }"), []);
  assert.deepEqual(specifiers("const load = require; load('./a'); [load] = values;"), []);
  assert.equal(analyze("const mod = require('module'); mod.createRequire = fake; const load = mod.createRequire(__filename); load('./a');").references[0].reason, 'ast-module-mutation');
  assert.equal(analyze("const mod = require('module'); const alias = mod; alias.createRequire = fake; mod.createRequire(__filename)('./a');").references[0].reason, 'ast-module-mutation');
  assert.equal(analyze("const mod = require('module'); mutate(mod); mod.createRequire(__filename)('./a');").references[0].reason, 'ast-module-escape');
});

test('rejects dynamic scopes and preserves nonliteral imports as unresolved', () => {
  assert.equal(analyze("eval(source); require('./a');").references[0].reason, 'ast-dynamic-scope');
  assert.equal(analyze("with (other) { require('./a'); }").references[0].reason, 'ast-dynamic-scope');
  assert.deepEqual(analyze('require(name); import(`./${name}.js`);').references.map((r) => r.reason), ['nonliteral-import', 'nonliteral-import']);
});

test('parses calls inside template interpolation, not quoted examples or member calls', () => {
  assert.deepEqual(specifiers("const x = `${require('./real')}`; const example = `require('./fake')`; object.require('./member'); /require('regex')/;"), ['./real']);
});

test('supports multiline ESM declarations and escaped specifiers without a CommonJS global', () => {
  assert.deepEqual(specifiers("import {\n value\n} from './a.js'; export * from './b.js'; import('./c.js'); require('./fake');", 'module'), ['./a.js', './b.js', './c.js']);
  assert.deepEqual(specifiers("require('./\\u0061.js');"), ['./a.js']);
});

test('unsupported syntax and parser resource exhaustion are explicit', () => {
  assert.equal(analyze('const =').references[0].reason, 'ast-parse-error');
  assert.equal(astImports({ ...parser, typed: null }, 'const x: string = "a"', 'a.ts', 'script').references[0].reason, 'ast-typescript-parser-unavailable');
  assert.equal(analyze(' '.repeat(1024 * 1024 + 1)).references[0].reason, 'ast-source-limit');
  assert.equal(analyze('('.repeat(20000) + '0' + ')'.repeat(20000)).references[0].reason, 'ast-resource-limit');
  assert.equal(analyze('0;'.repeat(60000)).references[0].reason, 'ast-resource-limit');
  const aliases = Array.from({ length: 40 }, (_, i) => `const a${i} = ${i ? 'a' + (i - 1) : 'require'};`).join('');
  assert.equal(analyze(aliases + "a39('./a');").references[0].reason, 'ast-resource-limit');
});

test('deep scan adds review context while preserving capability evidence and gating', (t) => {
  const root = mkTmpDir('deep');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'pkg', version: '1', scripts: { postinstall: 'node install.js' } }, {
    'install.js': "const load = require; load(`./${'worker'}`);",
    'worker.js': "require('https'); process.env.SERVICE_TOKEN;",
  });
  const normal = scanPackageDir(dir);
  const deep = scanPackageDir(dir, { deep: true });
  assert.equal(normal.installContext.hooks[0].reachableFiles, 1);
  assert.equal(deep.installContext.hooks[0].reachableFiles, 2);
  assert.deepEqual(deep.capabilities, normal.capabilities);
  assert.equal(diffManifests(normal, deep).escalated, false);
  assert.deepEqual(deep.installContext.ast, { parser: parser.identity, ecmaVersion: 2022, filesParsed: 2, filesFailed: 0 });
  const review = buildReview(new Map(), new Map([['pkg', [deep]]])).report;
  assert.match(renderMarkdown(review), /experimental AST analysis/);
  assert.deepEqual(renderSarif(review).runs[0].results[0].properties.installContext, deep.installContext);
  const cli = runCli(['scan', '--deep', dir]);
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).installContext.analysis, 'ast-import-graph');
  const tree = runCli(['scan-tree', root, '--deep', '--out', path.join(root, 'reports')]);
  assert.equal(tree.status, 0, tree.stderr);
});

test('uses nearest package type and source extensions, and reports parse failures on reached files', (t) => {
  const root = mkTmpDir('deep-types');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { type: 'module', scripts: { postinstall: 'node install.js' } }, {
    'install.js': "import './nested/worker.js'; import './broken.js';",
    'nested/package.json': '{"type":"commonjs"}',
    'nested/worker.js': "const load = require; load('./network');",
    'nested/network.js': "require('https');",
    'broken.js': 'const =',
  });
  const context = scanPackageDir(dir, { deep: true }).installContext;
  assert.equal(context.hooks[0].reachableFiles, 4);
  assert.equal(context.ast.filesFailed, 1);
  assert.ok(context.hooks[0].unresolved.some((r) => r.file === 'broken.js' && r.reason === 'ast-parse-error'));
  assert.match(installLines(context).join('\n'), /1 file\(s\) unavailable/);
  assert.match(installLines(context).join('\n'), /broken.js:1: unresolved import \(ast-parse-error\)/);
  assert.deepEqual(analyze("require('./a')", 'module', 'a.cjs').references[0].specifier, './a');
  assert.deepEqual(analyze("require('./a')", 'script', 'a.mjs').references, []);
});

test('missing parser fails explicitly without loading a parser from the scanned project', (t) => {
  const root = mkTmpDir('deep-isolation');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const part of ['lib', 'bin', 'package.json']) fs.cpSync(path.join(__dirname, '..', part), path.join(root, 'tool', part), { recursive: true });
  const dir = writePackage(root, 'target', { name: 'target' }, { 'node_modules/acorn/index.js': "throw Error('TARGET PARSER EXECUTED');" });
  const cli = path.join(root, 'tool/bin/capsurface.js');
  const result = spawnSync(process.execPath, [cli, 'scan', dir, '--deep'], { cwd: dir, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' } });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires acorn@8.15.0/);
  assert.doesNotMatch(result.stderr, /TARGET PARSER EXECUTED/);
  assert.equal(spawnSync(process.execPath, [cli, 'scan', dir]).status, 0);
});
