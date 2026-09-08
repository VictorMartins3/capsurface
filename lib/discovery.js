'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Discover every installed package directory reachable from a node_modules
 * root: top-level packages (including @scope/name), packages nested inside
 * another package's own node_modules (created by npm/yarn to resolve
 * conflicting transitive versions), symlinked packages (workspaces,
 * `file:` deps, `npm link`), and pnpm's `.pnpm` store.
 *
 * Deduplicated by realpath so a physical directory is scanned once even if
 * reached through multiple symlinks; cycle-safe for the same reason (a
 * symlink cycle resolves to an already-seen realpath and stops).
 *
 * SECURITY: symlink targets are bounded to `boundaryDir`. A package's own
 * node_modules is exactly where a malicious postinstall script could plant
 * a symlink to an arbitrary path (`/`, `$HOME`, `..`), and following it
 * unbounded would make the scanner itself read and report on locations
 * outside the project. A symlink resolving outside the boundary is
 * reported, not silently dropped, since attempting to link outside the
 * scan tree is itself a meaningful signal. `boundaryDir` defaults to the
 * scan root's own project directory (walked up to find an npm/yarn
 * `"workspaces"` root or pnpm-workspace.yaml, to cover scanning a single
 * workspace member's node_modules); `--boundary <dir>` on the CLI (or
 * `opts.boundaryDir` here) overrides it for layouts neither heuristic fits.
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
 * Compute the default symlink-escape boundary for a scan root: `rootDir`'s
 * own realpath is resolved first, then its parent is taken, not the other
 * way around. Resolving the parent of an unresolved `rootDir` breaks the
 * boundary check whenever `rootDir` itself is a symlink, since every
 * candidate package below it is compared against a fully-resolved path.
 * A fully-resolved path has no symlink components, so its ancestors are
 * already resolved too; no further realpathSync calls are needed walking
 * up. If the resulting boundary is the filesystem root itself (e.g. a
 * container image with node_modules at `/`), that's too permissive to be a
 * meaningful check, so this falls back to the scan root's own directory,
 * stricter, which is the safer failure direction for a security check.
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
      return; // broken symlink
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
  return { dirs: result, skippedEscapes };
}

module.exports = { discoverPackageDirs, computeDefaultBoundary, findWorkspaceRoot };
