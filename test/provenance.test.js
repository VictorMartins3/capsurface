'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadProvenance, packageLines } = require('../lib/provenance');
const { mkTmpDir } = require('./helpers');

function fixture(packages, version = 3) {
  const root = mkTmpDir('provenance');
  const file = path.join(root, 'package-lock.json');
  const text = JSON.stringify({ name: 'app', lockfileVersion: version, packages }, null, 2);
  fs.writeFileSync(file, text);
  return { root, file, text, read: () => loadProvenance(file, root) };
}
function manifest(name, installPath = name, version = '1.0.0') { return { name, version, installPath }; }

test('resolves hoisted dependencies and all immediate parents from the root', () => {
  const f = fixture({ '': { dependencies: { a: '*', b: '*' } },
    'node_modules/a': { version: '1.0.0', dependencies: { c: '*' } },
    'node_modules/b': { version: '1.0.0', dependencies: { c: '*' } },
    'node_modules/c': { version: '1.0.0' } });
  const result = f.read()(manifest('c'));
  assert.deepEqual(result.chain.map((p) => p.name), ['app', 'a', 'c']);
  assert.deepEqual(result.parents.map((p) => p.name), ['a', 'b']);
  assert.equal(f.text.split('\n')[result.location.line - 1].trim(), '"version": "1.0.0"');
});

test('selects the nested installation rather than a hoisted copy with another version', () => {
  const f = fixture({ '': { dependencies: { a: '*' } },
    'node_modules/a': { version: '1.0.0', dependencies: { c: '*' } },
    'node_modules/a/node_modules/c': { version: '2.0.0' },
    'node_modules/c': { version: '1.0.0' } }, 2);
  const resolve = f.read();
  assert.equal(resolve(manifest('c', 'a\\node_modules\\c', '2.0.0')).status, 'resolved');
  assert.equal(resolve(manifest('c')).status, 'unavailable');
  assert.match(resolve(manifest('c', 'a/node_modules/c')).reason, /does not match/);
});

test('follows workspace links and dependency cycles without inventing registry dev edges', () => {
  const f = fixture({ '': {}, 'node_modules/work': { link: true, resolved: 'packages/work' },
    'packages/work': { name: 'work', version: '1.0.0', devDependencies: { dep: '*' } },
    'node_modules/dep': { version: '1.0.0', dependencies: { work: '*' }, devDependencies: { unrelated: '*' } },
    'node_modules/unrelated': { version: '1.0.0' } });
  const resolve = f.read();
  assert.deepEqual(resolve(manifest('dep')).chain.map((p) => p.name), ['app', 'work', 'dep']);
  assert.equal(resolve(manifest('work', '../packages/work')).status, 'resolved');
  assert.equal(resolve(manifest('unrelated')).status, 'unavailable');
});

test('records npm aliases, scoped packages, optional and peer edges', () => {
  const f = fixture({ '': { optionalDependencies: { alias: '*' } },
    'node_modules/alias': { name: 'real', version: '1.0.0', peerDependencies: { '@scope/peer': '*' } },
    'node_modules/@scope/peer': { version: '1.0.0' } });
  const result = f.read()(manifest('@scope/peer'));
  assert.equal(result.chain[1].name, 'real');
  assert.equal(result.chain[1].via, 'alias');
  assert.equal(result.chain[1].kind, 'optional');
  assert.equal(result.chain[2].kind, 'peer');
});

test('indexes compact JSON, escaped keys and reordered version fields', () => {
  const text = '{"other":{"version":"ignore"},"packages":{\n"node_modules/a":{"dependencies":{"version":"*"},\n"version":"1"},"node_modules/b":{"version":"1"}}}';
  const lines = packageLines(text);
  assert.equal(lines.get('node_modules/a'), 3);
  assert.equal(lines.get('node_modules/b'), 3);
  assert.equal(packageLines('{"packages":{"node_modules/\\u0061":{"version":"1"}}}').get('node_modules/a'), 1);
});

test('rejects unsupported or invalid lockfiles and reports missing origins explicitly', () => {
  assert.throws(() => fixture({ '': {} }, 1).read(), /v2 or v3/);
  assert.throws(() => fixture({ '../escape': {} }).read(), /root package/);
  assert.throws(() => fixture({ '': {}, '../escape': {} }).read(), /invalid lockfile/);
  const f = fixture({ '': {} });
  assert.throws(() => loadProvenance(f.file, path.join(f.root, 'other')), /inside/);
  assert.equal(f.read()(manifest('missing')).status, 'unavailable');
  assert.match(f.read()({ name: 'missing', version: '1' }).reason, /no installation path/);
  assert.match(f.read()(manifest('x', '../../elsewhere')).reason, /outside/);
});
