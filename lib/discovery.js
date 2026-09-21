'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Discover every installed package under a node_modules root: top-level and
 * scoped, nested inside another package's node_modules, symlinked
 * (workspaces, `file:` deps, `npm link`), and pnpm's `.pnpm` store.
 * Deduplicated by realpath, which also makes it cycle-safe.
 *
 * Symlink targets are bounded to `boundaryDir`, because a package's own
 * node_modules is where a malicious postinstall would plant a link to `/`
 * or `$HOME`. One resolving outside is reported rather than dropped:
 * linking out of the scan tree is itself a signal. The default boundary
 * walks up to a workspace root; `--boundary` overrides it.
 */
function findWorkspaceRoot(startDir) {
  let dir = startDir;
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) return dir;
    const pkgJsonPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        if (pkg && pkg.workspaces) return dir;
      } catch (e) {
        // malformed package.json above the scan root, not our concern here
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break; // reached the filesystem root
    dir = parent;
  }
  return null;
}

/**
 * The default symlink-escape boundary. `rootDir` is resolved first and its
 * parent taken after, never the other way around: resolving the parent of an
 * unresolved root breaks the check whenever the root is itself a symlink.
 * A boundary of the filesystem root is no boundary at all, so that falls
 * back to the scan root's own directory, which errs strict.
 */
function computeDefaultBoundary(rootDir) {
  let resolvedRoot;
  try {
    resolvedRoot = fs.realpathSync(path.resolve(rootDir));
  } catch (e) {
    resolvedRoot = path.resolve(rootDir);
  }
  const projectDir = path.dirname(resolvedRoot);
  const workspaceRoot = findWorkspaceRoot(projectDir);
  let chosen = workspaceRoot || projectDir;
  if (path.parse(chosen).root === chosen) {
    // A filesystem root is too permissive to be a meaningful boundary:
    // path.relative() never produces a leading '..' against it, so every
    // absolute path on the volume would pass. Reachable when node_modules
    // sits directly at the root, e.g. a container image built that way.
    // Fall back to the scan root itself, which is strictly tighter.
    chosen = resolvedRoot;
  }
  return chosen;
}

function discoverPackageDirs(rootDir, opts = {}) {
  const seenRealpaths = new Set();
  const result = [];
  const skippedEscapes = [];
  const errors = [];
  let errorCount = 0;
  function recordError(file, operation, error) {
    errorCount++;
    if (errors.length < 10) errors.push({ path: file, operation, code: error.code || 'UNKNOWN' });
  }
  const boundaryDir =
    opts.boundaryDir !== undefined ? opts.boundaryDir : computeDefaultBoundary(rootDir);

  function isWithinBoundary(real) {
    const rel = path.relative(boundaryDir, real);
    return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
  }

  function visitPackageCandidate(pkgDir) {
    let real;
    try {
      real = fs.realpathSync(pkgDir);
    } catch (e) {
      recordError(pkgDir, 'realpath', e);
      return;
    }
    if (!isWithinBoundary(real)) {
      skippedEscapes.push({ path: pkgDir, target: real });
      return;
    }
    // Dedup check before the stat call, not after: for a "hub" dependency
    // reached through many symlinks resolving to the same realpath (routine
    // in a pnpm store), every visit past the first previously paid a wasted
    // stat() syscall before being discarded here anyway.
    if (seenRealpaths.has(real)) return;
    let st;
    try {
      st = fs.statSync(pkgDir); // follows symlinks
    } catch (e) {
      recordError(pkgDir, 'stat', e);
      return;
    }
    if (!st.isDirectory()) return;
    seenRealpaths.add(real);
    // Record the validated REALPATH, not the original (possibly symlinked)
    // pkgDir: scanning happens in a later pass over this result array, so
    // storing the symlink path would leave a TOCTOU window where the
    // symlink could be repointed between validation here and the actual
    // file reads in scanPackageDir, e.g. by the very still-running
    // malicious postinstall process this tool is trying to catch.
    // Recording the already-resolved directory closes that window.
    result.push(real);

    const nestedNodeModules = path.join(real, 'node_modules');
    if (fs.existsSync(nestedNodeModules)) {
      visitNodeModulesDir(nestedNodeModules);
    }
  }

  function visitNodeModulesDir(nmDir) {
    let entries;
    try {
      entries = fs.readdirSync(nmDir, { withFileTypes: true });
    } catch (e) {
      recordError(nmDir, 'readdir', e);
      return;
    }
    for (const entry of entries) {
      if (entry.name === '.bin' || entry.name === '.cache') continue;
      const entryPath = path.join(nmDir, entry.name);

      if (entry.name === '.pnpm') {
        // pnpm's real package storage: .pnpm/<name>@<version>[_<hash>]/node_modules/<name>.
        // Everything else under node_modules is a symlink into here, which
        // realpath-dedup would eventually reach anyway, but pnpm does not
        // flatten transitive (non-hoisted) deps into the top-level
        // node_modules at all in its default (strict) mode. The only way
        // to reach those is by walking .pnpm directly.
        let pnpmEntries;
        try {
          pnpmEntries = fs.readdirSync(entryPath, { withFileTypes: true });
        } catch (e) {
          recordError(entryPath, 'readdir', e);
          continue;
        }
        for (const slot of pnpmEntries) {
          if (!slot.isDirectory() && !slot.isSymbolicLink()) continue;
          const slotNodeModules = path.join(entryPath, slot.name, 'node_modules');
          if (fs.existsSync(slotNodeModules)) visitNodeModulesDir(slotNodeModules);
        }
        continue;
      }

      if (entry.name.startsWith('.')) continue;

      if (entry.name.startsWith('@')) {
        let scopeEntries;
        try {
          scopeEntries = fs.readdirSync(entryPath, { withFileTypes: true });
        } catch (e) {
          recordError(entryPath, 'readdir', e);
          continue;
        }
        for (const sub of scopeEntries) {
          visitPackageCandidate(path.join(entryPath, sub.name));
        }
        continue;
      }

      visitPackageCandidate(entryPath);
    }
  }

  visitNodeModulesDir(rootDir);
  return { dirs: result, skippedEscapes, errors, errorCount };
}

module.exports = { discoverPackageDirs, computeDefaultBoundary, findWorkspaceRoot };
