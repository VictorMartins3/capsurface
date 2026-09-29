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

  // ESM dynamic import of a literal specifier: the same acquisition as
  // require, and increasingly the only form modern code uses.
  ['dynamic import', 'exec', "import('child_process').then(cp => cp.execSync('id'));\n", true],
  ['dynamic import node:', 'exec', "const cp = await import('node:child_process');\n", true],
  ['dynamic import, network', 'network', "const dns = await import('node:dns');\n", true],

  // Reaching the module without spelling `require(`. `._load` is Node's
  // internal loader, reached through `module.constructor` to slip past a
  // require hook a scanner or defender installed; `require?.()` is a plain
  // optional call. Both stay tied to the dangerous-module literal.
  ['optional call require?.()', 'exec', "require?.('child_process').execSync('id');\n", true],
  ['loader bypass, constructor._load', 'exec', "const cp = module.constructor._load('child_process');\ncp.execSync('id');\n", true],

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

});

describe('type-position import() is not a runtime acquisition', () => {
  test('typeof import() is a TypeScript type query, not exec', () => {
    const tmp = mkTmpDir('evasion');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' },
      { 'index.ts': 'export type Reg = { child_process: typeof import("child_process") };\n' });
    assert.equal(scanPackageDir(dir).capabilities.exec.present, false);
  });

  test('import() in a .d.ts declaration file is a type, not exec', () => {
    const tmp = mkTmpDir('evasion');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' },
      { 'types.d.ts': 'export declare function run(): Promise<import("child_process").ChildProcess>;\n' });
    assert.equal(scanPackageDir(dir).capabilities.exec.present, false);
  });

  test('a real dynamic import in a .ts file still counts', () => {
    const tmp = mkTmpDir('evasion');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' },
      { 'index.ts': "async function f() { const cp = await import('child_process'); return cp; }\n" });
    assert.equal(scanPackageDir(dir).capabilities.exec.present, true);
  });
});

describe('credential targeting: modern cloud/CI/container secrets', () => {
  const scan = (src) => {
    const dir = writePackage(mkTmpDir('cred'), 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src });
    return scanPackageDir(dir).capabilities.sensitiveTargets.present;
  };

  test('reads a kube config file', () => {
    assert.equal(scan("const fs=require('fs');fs.readFileSync(process.env.HOME + '/.kube/config');\n"), true);
  });
  test('reads docker registry credentials', () => {
    assert.equal(scan("const fs=require('fs');fs.readFileSync('/root/.docker/config.json');\n"), true);
  });
  test('reads git-credentials', () => {
    assert.equal(scan("const fs=require('fs');fs.readFileSync(process.env.HOME + '/.git-credentials');\n"), true);
  });
  test('reads a GitLab token (propagation tier)', () => {
    assert.equal(scan("module.exports = process.env.GITLAB_TOKEN;\n"), true);
  });
  test('reads GCP application credentials', () => {
    assert.equal(scan("module.exports = process.env.GOOGLE_APPLICATION_CREDENTIALS;\n"), true);
  });
  // The design line: a package's own service key is credential-shaped but is
  // not the propagation-tier signal that raises a worm CRITICAL.
  test('a service key (OPENAI_API_KEY) is not propagation-tier', () => {
    assert.equal(scan("module.exports = process.env.OPENAI_API_KEY;\n"), false);
  });
});
