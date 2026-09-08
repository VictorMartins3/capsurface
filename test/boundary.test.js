'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { discoverPackageDirs, computeDefaultBoundary, findWorkspaceRoot } = require('../lib/discovery');
const { mkTmpDir, writePackage } = require('./helpers');

// These cover the same boundary behavior as the end-to-end tests in
// discovery.test.js, but call the functions directly instead of spawning
// the CLI. Security-critical logic should be reachable without a
// subprocess, both so it can be asserted precisely and so a library
// consumer can use it.

describe('findWorkspaceRoot', () => {
  test('finds a package.json declaring workspaces', () => {
    const tmp = mkTmpDir('ws-root');
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'root', workspaces: ['packages/*'] })
    );
    const nested = path.join(tmp, 'packages', 'app');
    fs.mkdirSync(nested, { recursive: true });
    assert.equal(fs.realpathSync(findWorkspaceRoot(nested)), fs.realpathSync(tmp));
  });

  test('finds a pnpm-workspace.yaml', () => {
    const tmp = mkTmpDir('pnpm-ws-root');
    fs.writeFileSync(path.join(tmp, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n");
    const nested = path.join(tmp, 'packages', 'app');
    fs.mkdirSync(nested, { recursive: true });
    assert.equal(fs.realpathSync(findWorkspaceRoot(nested)), fs.realpathSync(tmp));
  });

  test('returns null when there is no workspace marker', () => {
    const tmp = mkTmpDir('no-ws-root');
    const nested = path.join(tmp, 'a', 'b');
    fs.mkdirSync(nested, { recursive: true });
    assert.equal(findWorkspaceRoot(nested), null);
  });

  test('ignores a package.json that is not valid JSON and keeps walking up', () => {
    const tmp = mkTmpDir('ws-bad-json');
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'root', workspaces: ['packages/*'] })
    );
    const mid = path.join(tmp, 'packages', 'app');
    fs.mkdirSync(mid, { recursive: true });
    fs.writeFileSync(path.join(mid, 'package.json'), '{ broken json');
    assert.equal(fs.realpathSync(findWorkspaceRoot(mid)), fs.realpathSync(tmp));
  });
});

describe('computeDefaultBoundary', () => {
  test('resolves the scan root before taking its parent', () => {
    // node_modules itself is a symlink to somewhere else. The boundary has
    // to be the parent of the real location, otherwise every package found
    // underneath compares as outside the boundary.
    const tmp = mkTmpDir('symlinked-root');
    const realProject = path.join(tmp, 'real-project');
    const realNodeModules = path.join(realProject, 'node_modules');
    fs.mkdirSync(realNodeModules, { recursive: true });
    const linkDir = path.join(tmp, 'link-here');
    fs.mkdirSync(linkDir, { recursive: true });
    const linkedNodeModules = path.join(linkDir, 'node_modules');
    fs.symlinkSync(realNodeModules, linkedNodeModules, 'dir');

    const boundary = computeDefaultBoundary(linkedNodeModules);
    assert.equal(fs.realpathSync(boundary), fs.realpathSync(realProject));
  });

  test('never returns the filesystem root', () => {
    const boundary = computeDefaultBoundary('/node_modules');
    assert.notEqual(boundary, path.parse(boundary).root);
  });
});

describe('discoverPackageDirs boundary enforcement', () => {
  test('reports a symlink resolving outside the boundary instead of following it', () => {
    const tmp = mkTmpDir('escape-unit');
    const outside = mkTmpDir('escape-unit-target');
    writePackage(outside, 'sneaky', { name: 'sneaky', version: '9.9.9' });
    const nm = path.join(tmp, 'node_modules');
    writePackage(tmp, 'node_modules/host', { name: 'host', version: '1.0.0' });
    const hostNested = path.join(nm, 'host', 'node_modules');
    fs.mkdirSync(hostNested, { recursive: true });
    fs.symlinkSync(path.join(outside, 'sneaky'), path.join(hostNested, 'sneaky'), 'dir');

    const { dirs, skippedEscapes } = discoverPackageDirs(nm);
    assert.equal(skippedEscapes.length, 1);
    assert.match(skippedEscapes[0].path, /sneaky$/);
    assert.ok(!dirs.some((d) => d.includes('sneaky')), 'the out-of-boundary target must not be scanned');
  });

  test('an explicit boundaryDir overrides the default', () => {
    const tmp = mkTmpDir('explicit-boundary');
    const outside = mkTmpDir('explicit-boundary-target');
    writePackage(outside, 'linked', { name: 'linked', version: '1.0.0' });
    const nm = path.join(tmp, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });
    fs.symlinkSync(path.join(outside, 'linked'), path.join(nm, 'linked'), 'dir');

    const denied = discoverPackageDirs(nm);
    assert.equal(denied.dirs.length, 0);
    assert.equal(denied.skippedEscapes.length, 1);

    // Widening the boundary to a shared ancestor of both trees allows it.
    const shared = path.dirname(fs.realpathSync(outside));
    const allowed = discoverPackageDirs(nm, { boundaryDir: shared });
    assert.equal(allowed.skippedEscapes.length, 0);
    assert.equal(allowed.dirs.length, 1);
  });

  test('returns realpaths, not the symlink paths that were validated', () => {
    const tmp = mkTmpDir('realpath-result');
    const real = writePackage(tmp, 'packages/thing', { name: 'thing', version: '1.0.0' });
    const nm = path.join(tmp, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });
    fs.symlinkSync(real, path.join(nm, 'thing'), 'dir');

    const { dirs } = discoverPackageDirs(nm);
    assert.equal(dirs.length, 1);
    assert.equal(dirs[0], fs.realpathSync(real));
  });
});
