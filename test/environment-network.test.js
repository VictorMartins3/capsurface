'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadParser, astImports } = require('../lib/ast-imports');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const parser = loadParser();
const analyze = (source) => astImports(parser, source, 'index.js', 'script');
const kinds = (source) => (analyze(source).operations || []).map((op) => op.category);

function fixture(t, source) {
  const root = mkTmpDir('environment-network');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'pkg', version: '1' }, { 'index.js': source });
  return { root, dir, scan: () => scanPackageDir(dir, { deep: true }) };
}

test('classifies exact network module calls and aliases without confusing unrelated methods', () => {
  assert.deepEqual(kinds("const { request: send } = require('https'); send(url);\nconst net = require('node:net'); net.connect(80); net.createServer();\nrequire('node:dns/promises').resolveTxt(host); require('dgram').createSocket('udp4');"),
    ['networkRequest', 'networkConnect', 'networkServer', 'networkDns', 'networkSocket']);
  assert.deepEqual(kinds("require('http2').createSecureServer(); require('dns').promises.lookup(host); require('tls').connect(443);"),
    ['networkServer', 'networkDns', 'networkConnect']);
  const esm = astImports(parser, "import { get as request } from 'node:http'; request(url);", 'index.mjs', 'module');
  assert.equal(esm.operations[0].category, 'networkRequest');
  for (const code of ["require('https-extra').request(url);", "const n = require('net'); function f(n) { n.connect(80); }", "const n = require('net'); const f = n.connect; f = custom; f(80);", "require('net').constructor();", "const n = require('http'); n.request;"]) assert.deepEqual(kinds(code), [], code);
});

test('resolves unshadowed fetch aliases and preserves parent evidence and source context', (t) => {
  assert.deepEqual(kinds("const send = fetch; send(url);"), ['networkRequest']);
  assert.deepEqual(kinds("function f(fetch) { fetch(url); }"), []);
  assert.deepEqual(kinds("const fetch = custom; fetch(url);"), []);
  const f = fixture(t, "const send = fetch;\nsend(url);\nconst token = process.env.NPM_TOKEN;");
  const manifest = f.scan();
  assert.equal(manifest.capabilities.network.present, true);
  assert.equal(manifest.capabilities.networkRequest.evidence[0].line, 2);
  assert.equal(manifest.sourceContext.matchingFiles, 1);
});

test('enumerates environment keys, values, entries, copies, rest and for-in through aliases', () => {
  for (const code of [
    'Object.keys(process.env);', 'Object.values(process.env);', 'Object.entries(process.env);',
    'Object.getOwnPropertyNames(process.env);', 'Object.assign({}, process.env);',
    'const all = { ...process.env };', 'const { HOME, ...rest } = process.env;',
    'for (const key in process.env) {}', 'const env = process.env; const keys = Object.keys; keys(env);',
    "const { env } = require('node:process'); Object.entries(env);",
  ]) assert.deepEqual(kinds(code), ['envEnumeration'], code);
  for (const code of [
    'Object.assign(process.env, defaults);', 'const { HOME } = process.env;',
    'function f(process) { Object.keys(process.env); }', 'function f(Object) { Object.keys(process.env); }',
    'const process = custom; Object.values(process.env);', 'const env = {}; Object.keys(env);',
    'process.env.HOME;',
  ]) assert.deepEqual(kinds(code), [], code);
});

test('recognized namespace mutations and escapes remain explicit coverage failures', () => {
  for (const code of ["const http = require('http'); http.request = fake; http.request(url);", "const net = require('net'); helper(net); net.connect(80);", 'process.env = fake; Object.keys(process.env);', 'Object.keys = fake; Object.keys(process.env);']) {
    assert.equal(analyze(code).parsed, false, code);
  }
});

test('bulk environment access gates even when individual environment reads were approved', (t) => {
  const f = fixture(t, 'process.env.PATH;');
  const before = f.scan();
  fs.writeFileSync(path.join(f.dir, 'index.js'), 'process.env.PATH;\nObject.entries(process.env);');
  const after = f.scan();
  assert.equal(after.riskScore, before.riskScore);
  assert.equal(after.capabilities.envEnumeration.evidence[0].line, 2);
  assert.ok(diffManifests(before, after).changes.some((c) => c.category === 'envEnumeration' && c.escalates));
  assert.equal(scanPackageDir(f.dir).capabilities.envEnumeration.present, false);
});

test('network operation changes retain report evidence and selective approval', (t) => {
  const f = fixture(t, "require('http').createServer();");
  const before = f.scan();
  fs.writeFileSync(path.join(f.dir, 'index.js'), "require('http').createServer();\nrequire('http').request(url);");
  const after = f.scan();
  assert.equal(after.riskScore, before.riskScore);
  const report = buildReview(new Map([['pkg', [before]]]), new Map([['pkg', [after]]])).report;
  assert.match(renderMarkdown(report), /HTTP requests/);
  assert.match(renderSarif(report).runs[0].results[0].message.text, /HTTP requests/);
  const evidence = after.capabilities.networkRequest.evidence[0];
  assert.equal(evidence.line, 2);
  assert.equal(evidence.pattern, 'node:http.request');
  const out = path.join(f.root, 'manifests'); fs.mkdirSync(out);
  fs.writeFileSync(path.join(out, 'pkg.json'), JSON.stringify(after));
  const baseline = path.join(f.root, 'baseline.json');
  fs.writeFileSync(baseline, JSON.stringify({ schemaVersion: 2, packages: { pkg: [before] } }));
  assert.equal(runCli(['check', out, '--baseline', baseline]).status, 1);
  assert.equal(runCli(['approve', out, '--baseline', baseline, '--id', report.entries[0].id, '--reason', 'Reviewed outbound requests']).status, 0);
  assert.equal(runCli(['check', out, '--baseline', baseline]).status, 0);
  const legacy = JSON.parse(JSON.stringify(before)); delete legacy.capabilities.networkRequest;
  assert.ok(diffManifests(legacy, after).changes.some((c) => c.category === 'networkRequest' && c.type === 'capability-detail-unreviewed'));
});
