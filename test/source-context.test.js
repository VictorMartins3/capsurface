'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { diffManifests } = require('../lib/diff');
const { mkTmpDir, writePackage, runCli } = require('./helpers');

function fixture(files, scripts) {
  const root = mkTmpDir('source-context');
  const pkg = writePackage(root, 'pkg', { name: 'pkg', version: '1', ...(scripts ? { scripts } : {}) }, files);
  return { root, pkg, scan: () => scanPackageDir(pkg) };
}

const network = "require('https');";
const credential = 'process.env.SERVICE_TOKEN;';
const sensitive = "require('fs').readFileSync('.npmrc');";

test('records original file and line for network and credential indicators', () => {
  const manifest = fixture({ 'index.js': `// comment\n${network}\n\n${credential}` }).scan();
  const context = manifest.sourceContext;
  assert.equal(context.complete, true);
  assert.equal(context.filesAnalyzed, 1);
  assert.equal(context.matchingFiles, 1);
  assert.equal(context.matches[0].file, 'index.js');
  assert.equal(context.matches[0].network.line, 2);
  assert.equal(context.matches[0].credential.line, 4);
  assert.equal(context.matches[0].credential.kind, 'credential-env');
  assert.equal(context.matches[0].credential.name, 'SERVICE_TOKEN');
});

test('separate files retain package risk without inventing file co-occurrence', () => {
  const separate = fixture({ 'network.js': network, 'credential.js': credential }).scan();
  const together = fixture({ 'index.js': network + '\n' + credential }).scan();
  assert.equal(separate.sourceContext.matchingFiles, 0);
  assert.equal(together.sourceContext.matchingFiles, 1);
  assert.equal(separate.riskScore, together.riskScore);
  assert.deepEqual(separate.riskFlags, together.riskFlags);
});

test('finds file relationships after package evidence quotas have filled', () => {
  const files = {};
  for (let i = 0; i < 6; i++) files[`a-${i}.js`] = `${network}\n${sensitive}`;
  files['z-later.js'] = `${network}\n${sensitive}`;
  const manifest = fixture(files).scan();
  assert.equal(manifest.capabilities.network.evidence.length, 5);
  assert.equal(manifest.capabilities.sensitiveTargets.evidence.length, 5);
  assert.ok(!manifest.capabilities.network.evidence.some((e) => e.file === 'z-later.js'));
  assert.equal(manifest.sourceContext.matchingFiles, 7);
  assert.ok(manifest.sourceContext.matches.some((e) => e.file === 'z-later.js'));
});

test('multiline imports still contribute after network has already been detected', () => {
  const manifest = fixture({ 'a.js': network.repeat(6),
    'b.js': "require(\n 'https'\n);\n" + credential }).scan();
  assert.equal(manifest.sourceContext.matchingFiles, 1);
  assert.equal(manifest.sourceContext.matches[0].network.line, 1);
  assert.equal(manifest.sourceContext.matches[0].credential.line, 4);
  assert.equal(manifest.sourceContext.matches[0].file, 'b.js');
});

test('sensitive file access correlates but harmless environment variables do not', () => {
  const target = fixture({ 'index.js': `${network}\n${sensitive}` }).scan();
  assert.equal(target.sourceContext.matches[0].credential.kind, 'sensitive-target');
  const ordinary = fixture({ 'index.js': `${network}\nprocess.env.NO_COLOR;` }).scan();
  assert.equal(ordinary.sourceContext.matchingFiles, 0);
});

test('a literal endpoint alone does not establish network capability', () => {
  const manifest = fixture({ 'index.js': `const docs = 'https://example.test';\n${credential}` }).scan();
  assert.equal(manifest.capabilities.network.endpoints.length, 1);
  assert.equal(manifest.capabilities.network.present, false);
  assert.equal(manifest.sourceContext.matchingFiles, 0);
});

test('comments and erased type imports do not establish relationships', () => {
  for (const source of [`/* ${network} */\n${credential}`, `${network}\n// ${credential}`,
    `import type { Server } from 'https';\n${credential}`]) {
    assert.equal(fixture({ 'index.ts': source }).scan().sourceContext.matchingFiles, 0);
  }
});

test('script command capabilities are not attributed to unrelated source files', () => {
  const manifest = fixture({ 'index.js': credential }, { postinstall: 'curl https://example.test/install' }).scan();
  assert.equal(manifest.capabilities.network.present, true);
  assert.equal(manifest.sourceContext.matchingFiles, 0);
});

test('context samples are bounded while the matching file count stays exact', () => {
  const files = Object.fromEntries(Array.from({ length: 27 }, (_, i) => [`file-${i}.js`, `${network}\n${credential}`]));
  const context = fixture(files).scan().sourceContext;
  assert.equal(context.filesAnalyzed, 27);
  assert.equal(context.matchingFiles, 27);
  assert.equal(context.matches.length, 20);
  assert.equal(context.omittedFiles, 7);
  assert.equal(context.complete, true, 'sample truncation is separate from incomplete source analysis');
});

test('incomplete source coverage is visible independently of positive matches', () => {
  const f = fixture({ 'index.js': `${network}\n${credential}` });
  const large = path.join(f.pkg, 'large.js');
  fs.writeFileSync(large, 'x'.repeat(16 * 1024 * 1024));
  const manifest = f.scan();
  assert.equal(manifest.sourceContext.complete, false);
  assert.equal(manifest.sourceContext.matchingFiles, 1);
  assert.equal(manifest.sourceContext.filesAnalyzed, 1);
  const review = buildReview(new Map(), new Map([['pkg', [manifest]]])).report;
  assert.match(renderMarkdown(review), /Source coverage is incomplete/);
});

test('context remains explanatory and does not create a new gate condition', () => {
  const manifest = fixture({ 'index.js': `${network}\n${credential}` }).scan();
  const baseline = { ...manifest };
  delete baseline.sourceContext;
  baseline.schemaVersion = 6;
  assert.equal(diffManifests(baseline, manifest).escalated, false);
});

test('Markdown escapes correlation evidence and SARIF retains structured context', () => {
  const manifest = fixture({ 'index.js': `${network}\n${credential} // <script> [link](url)` }).scan();
  const review = buildReview(new Map(), new Map([['pkg', [manifest]]])).report;
  const markdown = renderMarkdown(review);
  assert.match(markdown, /File correlation/);
  assert.match(markdown, /does not establish execution order or data transfer/);
  assert.ok(!markdown.includes('<script>'));
  const result = renderSarif(review).runs[0].results[0];
  assert.deepEqual(result.properties.sourceContext, manifest.sourceContext);
  assert.match(result.message.text, /index.js:2: credential-env/);
  delete review.entries[0].sourceContext;
  assert.match(renderMarkdown(review), /unavailable in this manifest/);
  assert.match(renderSarif(review).runs[0].results[0].message.text, /unavailable in this manifest/);
});

test('CLI review publishes context without changing the new-package policy', () => {
  const f = fixture({ 'index.js': `${network}\n${credential}` });
  const out = path.join(f.root, 'manifests');
  const baseline = path.join(f.root, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: {} }));
  assert.equal(runCli(['scan', f.pkg, '--out', path.join(out, 'pkg.json')]).status, 0);
  const args = ['review', out, '--baseline', baseline, '--json'];
  const report = runCli(args);
  assert.equal(report.status, 0);
  assert.equal(JSON.parse(report.stdout).entries[0].sourceContext.matchingFiles, 1);
  assert.equal(runCli([...args, '--fail-on-new']).status, 1);
});
