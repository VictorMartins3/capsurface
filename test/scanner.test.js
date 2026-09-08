'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { blankComments, looksLikeBuildArtifact, scanPackageDir } = require('../lib/scanner');
const { mkTmpDir, writePackage } = require('./helpers');

describe('blankComments', () => {
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
