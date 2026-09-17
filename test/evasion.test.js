'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

// Detection corpus. Every fixture is inert: it acquires a capability and
// exports it. The shape is the point, not any behaviour.
//
// Each row states whether this scanner is expected to catch it. The misses
// are as much the point as the catches: a specifier that only exists once the
// program runs cannot be resolved by reading the source, and writing that
// down is better than discovering it later. If one of them starts passing,
// the table is wrong and should be updated.
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

  // Folded by lib/normalize.js: every input is a literal, so the specifier is
  // the one the runtime will see.
  ['concatenation', 'exec', "const cp = require('child' + '_process');\n", true],
  ['through a variable', 'exec', "const m = 'child_process';\nconst cp = require(m);\n", true],
  ['hex escape', 'exec', "const cp = require('\\x63hild_process');\n", true],
  ['unicode escape', 'exec', "const cp = require('\\u0063hild_process');\n", true],
  ['String.fromCharCode', 'exec', 'const n = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);\nmodule.exports = require(n);\n', true],
  ['array join', 'exec', "module.exports = require(['child', 'process'].join('_'));\n", true],
  ['reversed string', 'exec', "module.exports = require('ssecorp_dlihc'.split('').reverse().join(''));\n", true],
  ['base64 through Buffer.from', 'exec', "module.exports = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());\n", true],
  ['hex through Buffer.from', 'exec', "module.exports = require(Buffer.from('6368696c645f70726f63657373', 'hex').toString());\n", true],
  ['atob', 'exec', "module.exports = require(atob('Y2hpbGRfcHJvY2Vzcw=='));\n", true],

  // A specifier on its own line: caught by a whole-file pass over the
  // categories the per-line pass left absent.
  ['multi-line require', 'exec', "const cp = require(\n  'child_process'\n);\n", true],

  // Still out of reach.
  // The value only exists once the program runs.
  ['computed at runtime', 'exec', "const cp = require(process.env.MOD_NAME);\n", false],
  ['built in a loop', 'exec', "let n = '';\nfor (const c of [99,104]) n += String.fromCharCode(c);\nrequire(n + 'ild_process');\n", false],
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
