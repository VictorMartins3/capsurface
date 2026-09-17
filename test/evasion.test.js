'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

// Detection corpus. Every fixture is inert: it acquires a capability and
// exports it. The shape is the point, not any behaviour.
//
// Each row states whether this scanner is expected to catch it. The misses
// are as much the point as the catches: a source-text matcher cannot resolve
// a specifier that is computed at runtime, and writing that down is better
// than discovering it later. If one of them starts passing, update the table.
//
// Technique taxonomy from the npm malicious-package benchmark (arXiv
// 2603.27549) and the JavaScript deobfuscation survey (arXiv 2512.14070).
const CORPUS = [
  // Specifier spelling. No obfuscation tooling needed, which is what makes
  // these the ones that matter.
  ['plain', 'exec', "const cp = require('child_process');\n", true],
  ['node: prefix', 'exec', "const cp = require('node:child_process');\n", true],
  ['template literal', 'exec', 'const cp = require(`child_process`);\n', true],
  ['template literal with node:', 'exec', 'const cp = require(`node:child_process`);\n', true],
  ['template literal, network', 'network', 'const h = require(`https`);\n', true],
  ['space before the paren', 'exec', "const cp = require ('child_process');\n", true],

  // Computed access to the same thing.
  ['process["binding"]', 'nativeFfi', "module.exports = process['binding']('spawn_sync');\n", true],
  ['globalThis["eval"]', 'dynamicEval', "module.exports = (s) => globalThis['eval'](s);\n", true],
  ['indirect (0, eval)', 'dynamicEval', 'module.exports = (s) => (0, eval)(s);\n', true],

  // Out of reach. The specifier does not exist in the source text.
  ['concatenation', 'exec', "const cp = require('child' + '_process');\n", false],
  ['through a variable', 'exec', "const m = 'child_process';\nconst cp = require(m);\n", false],
  ['hex escape', 'exec', "const cp = require('\\x63hild_process');\n", false],
  ['unicode escape', 'exec', "const cp = require('\\u0063hild_process');\n", false],
  ['String.fromCharCode', 'exec', 'const n = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);\nmodule.exports = require(n);\n', false],
  ['array join', 'exec', "module.exports = require(['child', 'process'].join('_'));\n", false],
  ['reversed string', 'exec', "module.exports = require('ssecorp_dlihc'.split('').reverse().join(''));\n", false],
  ['base64 decode', 'exec', "module.exports = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());\n", false],
  // Line-scoped matching cannot see a specifier on its own line.
  ['multi-line require', 'exec', "const cp = require(\n  'child_process'\n);\n", false],
];

describe('evasion corpus', () => {
  for (const [label, capability, src, shouldCatch] of CORPUS) {
    test(`${shouldCatch ? 'catches' : 'documented miss:'} ${label}`, () => {
      const tmp = mkTmpDir('evasion');
      const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src });
      assert.equal(scanPackageDir(dir).capabilities[capability].present, shouldCatch);
    });
  }

  test('the corpus covers both outcomes', () => {
    assert.ok(CORPUS.some(([, , , c]) => c), 'at least one catch');
    assert.ok(CORPUS.some(([, , , c]) => !c), 'at least one documented miss');
  });
});
