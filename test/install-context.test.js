'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { diffManifests } = require('../lib/diff');
const { installContext } = require('../lib/install-context');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function fixture(files, scripts = { postinstall: 'node install.js' }) {
  const root = mkTmpDir('install-context');
  const pkg = writePackage(root, 'pkg', { name: 'pkg', version: '1', scripts }, files);
  return { root, pkg, scan: () => scanPackageDir(pkg) };
}
const credential = 'process.env.SERVICE_TOKEN;';
const network = "require('https');";

test('traces separate network and credential files without claiming data flow', () => {
  const manifest = fixture({
    'install.js': "require('./network'); require('./credential.js');",
    'network.js': network,
    'credential.js': credential,
    'unused.js': network + credential,
  }).scan();
  const hook = manifest.installContext.hooks[0];
  assert.equal(hook.status, 'resolved');
  assert.equal(hook.reachableFiles, 3);
  assert.equal(hook.indicatorFiles, 2);
  assert.equal(hook.unresolvedCount, 0);
  assert.deepEqual(hook.paths.map((p) => p.chain), [['install.js', 'network.js'], ['install.js', 'credential.js']]);
  const review = buildReview(new Map(), new Map([['pkg', [manifest]]])).report;
  assert.match(renderMarkdown(review), /not proof of execution or data transfer/);
  assert.deepEqual(renderSarif(review).runs[0].results[0].properties.installContext, manifest.installContext);
});

test('collects import paths after source-context samples are full', () => {
  const files = { 'install.js': "require('./z-reached.js');", 'z-reached.js': network + credential };
  for (let i = 0; i < 25; i++) files[`a-${i}.js`] = network + credential;
  const manifest = fixture(files).scan();
  assert.ok(!manifest.sourceContext.matches.some((m) => m.file === 'z-reached.js'));
  assert.equal(manifest.installContext.hooks[0].paths[0].file, 'z-reached.js');
});

test('cycles terminate and repeated references do not duplicate files', () => {
  const hook = fixture({ 'install.js': "require('./a'); require('./a');",
    'a.js': "require('./install');" + network }).scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 2);
  assert.equal(hook.paths.length, 1);
});

test('literal ESM and dynamic imports use exact local filenames', () => {
  const hook = fixture({ 'install.js': "import './side.mjs'; export { x } from './reexport.mjs'; import('./lazy.mjs');",
    'side.mjs': network, 'reexport.mjs': network, 'lazy.mjs': credential }).scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 4);
  assert.equal(hook.indicatorFiles, 3);
  assert.equal(hook.unresolvedCount, 0);
});

test('comments, examples, erased imports and property calls are not import edges', () => {
  const hook = fixture({ 'install.js': "// require('./a')\nconst example = `require('./a')`; object.require('./a'); object . require('./a');",
    'a.js': network + credential }).scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 1);
  assert.equal(hook.indicatorFiles, 0);
  const typed = fixture({ 'install.ts': "import type { X } from './a.js';", 'a.js': network }, { postinstall: 'node install.ts' }).scan();
  assert.equal(typed.installContext.hooks[0].reachableFiles, 1);
});

test('dynamic, external and missing imports retain explicit reasons and lines', () => {
  const hook = fixture({ 'install.js': "require(variable);\nrequire('third-party');\nrequire('./missing');\nrequire('node:fs');" }).scan().installContext.hooks[0];
  assert.equal(hook.unresolvedCount, 3);
  assert.deepEqual(hook.unresolved.map((r) => r.reason).sort(), ['external-module', 'nonliteral-import', 'unresolved-local-import']);
  assert.equal(hook.unresolved.find((r) => r.reason === 'nonliteral-import').line, 1);
});

test('unsupported commands remain unresolved and prepare is not an install entry', () => {
  for (const command of ['node install.js && echo done', 'node --require preload install.js', 'FOO=1 node install.js', 'node -e "require(\'./install\')"', 'sh install.sh']) {
    const hook = fixture({ 'install.js': network }, { postinstall: command }).scan().installContext.hooks[0];
    assert.equal(hook.status, 'unresolved', command);
    assert.equal(hook.reason, 'unsupported-command');
  }
  assert.deepEqual(fixture({ 'install.js': network }, { prepare: 'node install.js' }).scan().installContext.hooks, []);
  assert.deepEqual(fixture({}, { postinstall: 'echo done' }).scan().installContext.hooks, []);
});

test('quoted filenames work and all three lifecycle entry points are retained', () => {
  const context = fixture({ 'install file.js': network }, {
    preinstall: 'node "install file.js"', install: "node 'install file.js'", postinstall: 'node "install file.js"',
  }).scan().installContext;
  assert.equal(context.hooks.length, 3);
  assert.ok(context.hooks.every((h) => h.entry === 'install file.js'));
});

test('outside paths, directories, symlinks and unscanned files are not guessed', () => {
  const f = fixture({ 'install.js': "require('../outside'); require('./data.json'); require('./folder'); require('./link/file.js');",
    'data.json': '{}', 'folder/index.js': network });
  fs.symlinkSync(f.root, path.join(f.pkg, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
  const hook = f.scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 1);
  assert.deepEqual(hook.unresolved.map((r) => r.reason).sort(), ['directory-resolution-unsupported', 'outside-package', 'symlink-reference', 'unscanned-file']);
  assert.equal(fixture({}, { postinstall: 'node ../outside.js' }).scan().installContext.hooks[0].reason, 'outside-package');
});

test('ESM extensionless references are not assigned CommonJS resolution', () => {
  const hook = fixture({ 'install.js': "import './a';", 'a.js': network }).scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 1);
  assert.equal(hook.unresolved[0].reason, 'unresolved-local-import');
});

test('depth and sample limits remain visible without unbounded traversal', () => {
  const files = { 'install.js': "require('./f0');" };
  for (let i = 0; i < 40; i++) files[`f${i}.js`] = `${network}\nrequire('./f${i + 1}');`;
  const hook = fixture(files).scan().installContext.hooks[0];
  assert.equal(hook.reachableFiles, 32);
  assert.equal(hook.paths.length, 20);
  assert.equal(hook.indicatorFiles, 31);
  assert.equal(hook.omittedFiles, 11);
  assert.equal(hook.unresolved[0].reason, 'depth-limit');
});

test('install context remains explanatory and supports older manifests', () => {
  const manifest = fixture({ 'install.js': network + credential }).scan();
  const baseline = { ...manifest };
  delete baseline.installContext;
  baseline.schemaVersion = 7;
  assert.equal(diffManifests(baseline, manifest).escalated, false);
  const review = buildReview(new Map(), new Map([['pkg', [baseline]]])).report;
  assert.doesNotThrow(() => renderMarkdown(review));
  assert.doesNotThrow(() => renderSarif(review));
});

test('graph and unresolved-reference samples expose resource limits', () => {
  const f = fixture({ 'install.js': Array.from({ length: 30 }, (_, i) => `require('external-${i}');`).join('\n') });
  const hook = f.scan().installContext.hooks[0];
  assert.equal(hook.unresolvedCount, 30);
  assert.equal(hook.unresolved.length, 20);
  assert.equal(hook.omittedReferences, 10);
  const graph = installContext(f.pkg, { postinstall: 'node install.js' });
  graph.add('install.js', '', '', {});
  for (let i = 0; i < 10000; i++) graph.add(`file-${i}.js`, '', '', {});
  assert.equal(graph.finish(true).truncated, true);
});

test('long comments before dynamic imports do not cause excessive backtracking', () => {
  const f = fixture({ 'install.js': 'import /*' + 'x'.repeat(100000) + '*/ (name);' });
  const result = runCli(['scan', f.pkg], { timeout: 5000 });
  assert.equal(result.status, 0, result.stderr);
  const hook = JSON.parse(result.stdout).installContext.hooks[0];
  assert.equal(hook.unresolved[0].reason, 'nonliteral-import');
});
