#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests, unionOfManifests } = require('../lib/diff');

function die(msg) {
  console.error(`capsurface: ${msg}`);
  process.exit(2);
}

function parseFlags(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function summaryLine(m) {
  const activeCaps = Object.entries(m.capabilities)
    .filter(([k, v]) => v && v.present)
    .map(([k]) => k);
  const flag = m.riskFlags.length ? '  ⚠ ' + m.riskFlags[0] : '';
  const where = m.installPath ? `  (${m.installPath})` : '';
  return `${m.name}@${m.version}  risk=${m.riskScore}  caps=[${activeCaps.join(',')}]${flag}${where}`;
}

function cmdScan(args) {
  const { positional, flags } = parseFlags(args);
  const dir = positional[0];
  if (!dir) die('usage: capsurface scan <package-dir> [--out file.json]');
  if (!fs.existsSync(dir)) die(`directory not found: ${dir}`);
  const manifest = scanPackageDir(dir);
  if (flags.out) {
    writeJson(flags.out, manifest);
    console.log(`wrote ${flags.out}`);
  } else {
    console.log(JSON.stringify(manifest, null, 2));
  }
  if (manifest.riskFlags.length) {
    console.error('\nRisk flags:');
    for (const f of manifest.riskFlags) console.error(`  - ${f}`);
  }
}

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
    // Computed boundary is a filesystem root, too permissive to be a
    // meaningful check. Fall back to the immediate, tighter default.
    chosen = projectDir;
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

function cmdScanTree(args) {
  const { positional, flags } = parseFlags(args);
  const rootDir = positional[0];
  if (!rootDir) die('usage: capsurface scan-tree <node_modules-dir> --out <manifests-dir> [--boundary <dir>]');
  if (!flags.out) die('--out <manifests-dir> is required');
  // Checked via stat, not just existsSync: existsSync alone doesn't catch
  // "path exists but is a file, not a directory" (e.g. a typo'd path that
  // happens to hit package.json) or "exists but unreadable" (permission
  // denied). Both previously fell through to discoverPackageDirs, whose
  // internal readdirSync failures are caught and swallowed, which meant
  // scan-tree printed "Scanned 0 package install(s)" and exited 0 instead
  // of failing loudly. That's the exact silent-pass failure mode this
  // check exists to prevent, just reachable through a different trigger
  // than a plain nonexistent path.
  let rootStat;
  try {
    rootStat = fs.statSync(rootDir);
  } catch (e) {
    if (e.code === 'ENOENT') die(`directory not found: ${rootDir}`);
    die(`cannot read directory: ${rootDir} (${e.code || e.message})`);
  }
  if (!rootStat.isDirectory()) die(`not a directory: ${rootDir}`);
  const discoverOpts = {};
  if (typeof flags.boundary === 'string') {
    try {
      discoverOpts.boundaryDir = fs.realpathSync(flags.boundary);
    } catch (e) {
      die(`--boundary directory not found: ${flags.boundary}`);
    }
  }
  const { dirs: pkgDirs, skippedEscapes } = discoverPackageDirs(rootDir, discoverOpts);
  if (skippedEscapes.length) {
    console.error(`capsurface: WARNING: ${skippedEscapes.length} symlink(s) inside the scan tree point outside the project and were NOT followed:`);
    for (const s of skippedEscapes) {
      console.error(`  ${s.path} -> ${s.target}`);
    }
    console.error('  A package legitimately should not need to link outside its project directory; treat this as suspicious.\n');
  }
  const manifests = [];
  const usedFilenames = new Set();
  for (const dir of pkgDirs) {
    const manifest = scanPackageDir(dir);
    manifest.installPath = path.relative(rootDir, dir);
    manifests.push(manifest);

    const base = `${manifest.name.replace('/', '__')}@${manifest.version}`;
    let filename = `${base}.json`;
    let n = 2;
    // Two different physical installs can legitimately share the same
    // name@version (rare, but possible with vendored/duplicated copies);
    // disambiguate rather than silently overwriting one manifest with the
    // other.
    while (usedFilenames.has(filename)) {
      filename = `${base}__${n}.json`;
      n++;
    }
    usedFilenames.add(filename);
    writeJson(path.join(flags.out, filename), manifest);
  }
  manifests.sort((a, b) => b.riskScore - a.riskScore);
  console.log(`Scanned ${manifests.length} package install(s) (including nested/symlinked/pnpm-store locations). Top risk:\n`);
  for (const m of manifests.slice(0, 20)) {
    console.log('  ' + summaryLine(m));
  }
  console.log(`\nManifests written to ${flags.out}/`);

  if (skippedEscapes.length) {
    // An escape attempt must fail the exit code, not just print a WARNING.
    // Otherwise a CI pipeline checking only the exit code would treat this
    // as a clean, passing run.
    console.error(`capsurface scan-tree FAILED: ${skippedEscapes.length} package symlink(s) tried to escape the project boundary (see WARNING above).`);
    process.exit(1);
  }
}

/**
 * Load every manifest JSON file in a directory, grouped by package name.
 * A name can map to more than one manifest when the same package is
 * installed at multiple versions/locations in the tree (see
 * discoverPackageDirs), e.g. two different lodash versions present, a
 * routine outcome of dependency resolution, not an edge case.
 */
function loadManifestsFromDir(dir) {
  const byName = new Map();
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    const m = readJson(path.join(dir, file));
    if (!byName.has(m.name)) byName.set(m.name, []);
    byName.get(m.name).push(m);
  }
  return byName;
}

/**
 * Load capsurface.lock.json into the same Map<name, Manifest[]> shape used
 * by loadManifestsFromDir. Accepts both the current schema
 * (`packages: {name: Manifest[]}`) and the original schema
 * (`packages: {name: Manifest}`) so an existing committed lock file from an
 * earlier version of this tool keeps working rather than needing a manual
 * migration.
 */
function loadBaseline(lock) {
  const byName = new Map();
  for (const [name, value] of Object.entries(lock.packages || {})) {
    byName.set(name, Array.isArray(value) ? value : [value]);
  }
  return byName;
}

function compareVersions(a, b) {
  const pa = String(a).split(/[.\-+]/).map((x) => (Number.isNaN(Number(x)) ? x : Number(x)));
  const pb = String(b).split(/[.\-+]/).map((x) => (Number.isNaN(Number(x)) ? x : Number(x)));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x) < String(y) ? -1 : 1;
  }
  return 0;
}

function cmdBaseline(args) {
  const { positional, flags } = parseFlags(args);
  const manifestsDir = positional[0];
  if (!manifestsDir) die('usage: capsurface baseline <manifests-dir> [--out capsurface.lock.json]');
  const outFile = flags.out || 'capsurface.lock.json';
  const byName = loadManifestsFromDir(manifestsDir);
  const packages = {};
  let manifestCount = 0;
  for (const [name, manifests] of byName) {
    manifests.sort((a, b) => compareVersions(a.version, b.version));
    packages[name] = manifests;
    manifestCount += manifests.length;
  }
  const lock = {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    packages,
  };
  writeJson(outFile, lock);
  console.log(`Baselined ${manifestCount} manifest(s) across ${byName.size} package name(s) into ${outFile}`);
  console.log('Review this file into version control as the approved capability surface.');
}

function cmdCheck(args) {
  const { positional, flags } = parseFlags(args);
  const manifestsDir = positional[0];
  if (!manifestsDir) die('usage: capsurface check <manifests-dir> --baseline capsurface.lock.json [--fail-on-new]');
  const baselineFile = flags.baseline || 'capsurface.lock.json';
  if (!fs.existsSync(baselineFile)) die(`baseline not found: ${baselineFile} (run "capsurface baseline" first)`);
  const lock = readJson(baselineFile);
  const baselineByName = loadBaseline(lock);
  const currentByName = loadManifestsFromDir(manifestsDir);

  let anyEscalation = false;
  const newPackages = [];
  const escalations = [];
  let totalCurrentManifests = 0;
  let totalBaselineManifests = 0;
  for (const manifests of baselineByName.values()) totalBaselineManifests += manifests.length;

  for (const [name, currentManifests] of currentByName) {
    const baselineManifests = baselineByName.get(name);
    if (!baselineManifests || baselineManifests.length === 0) {
      for (const manifest of currentManifests) {
        totalCurrentManifests++;
        newPackages.push(manifest);
      }
      continue;
    }
    // Computed once per package name, not once per installed version of
    // that name. Diffing several nested/multi-version installs against
    // the same baseline previously redid this Set-merging work per version.
    const union = unionOfManifests(baselineManifests);
    for (const manifest of currentManifests) {
      totalCurrentManifests++;
      const exactMatch = baselineManifests.some((b) => b.version === manifest.version);
      if (exactMatch) continue; // this exact version has already been reviewed somewhere in the tree

      // diffManifests already sets report.baselineVersion from union.version
      // (itself derived from baselineManifests), so no need to recompute it.
      const report = diffManifests(union, manifest);
      if (report.escalated) {
        anyEscalation = true;
        escalations.push({ report, installPath: manifest.installPath });
      }
    }
  }

  console.log(`capsurface check: ${totalCurrentManifests} manifest(s) scanned against baseline of ${totalBaselineManifests}\n`);

  let anyNewFailure = false;
  if (newPackages.length) {
    console.log(`NEW packages not in baseline (${newPackages.length}):`);
    for (const m of newPackages) {
      console.log('  + ' + summaryLine(m));
    }
    console.log('  (run "capsurface baseline" after review to accept these)\n');
    anyNewFailure = flags['fail-on-new'] === true;
  }

  if (escalations.length) {
    console.log(`CAPABILITY ESCALATIONS (${escalations.length}):`);
    for (const { report: r, installPath } of escalations) {
      const where = installPath ? `  [${installPath}]` : '';
      console.log(`\n  ${r.name}: ${r.baselineVersion} -> ${r.currentVersion}${where}  (risk delta ${r.riskScoreDelta >= 0 ? '+' : ''}${r.riskScoreDelta})`);
      for (const c of r.changes) {
        console.log(`    [${c.type}] ${c.detail}`);
      }
      for (const f of r.newRiskFlags) {
        console.log(`    ⚠ NEW FLAG: ${f}`);
      }
    }
    console.log('');
  } else {
    console.log('No capability escalations vs baseline.\n');
  }

  const shouldFail = anyEscalation || (flags['fail-on-new'] && newPackages.length > 0);
  if (shouldFail) {
    console.error('capsurface check FAILED: review and re-baseline before merging.');
    process.exit(1);
  } else {
    console.log('capsurface check passed.');
  }
}

function cmdDiff(args) {
  const { positional } = parseFlags(args);
  const [baselineFile, currentFile] = positional;
  if (!baselineFile || !currentFile) die('usage: capsurface diff <baseline-manifest.json> <current-manifest.json>');
  const baseline = readJson(baselineFile);
  const current = readJson(currentFile);
  const report = diffManifests(baseline, current);
  console.log(JSON.stringify(report, null, 2));
  if (report.escalated) process.exit(1);
}

function main() {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case 'scan':
      return cmdScan(rest);
    case 'scan-tree':
      return cmdScanTree(rest);
    case 'baseline':
      return cmdBaseline(rest);
    case 'check':
      return cmdCheck(rest);
    case 'diff':
      return cmdDiff(rest);
    default:
      console.log(`capsurface: capability-aware supply-chain scanner

Usage:
  capsurface scan <package-dir> [--out manifest.json]
  capsurface scan-tree <node_modules-dir> --out <manifests-dir>
  capsurface baseline <manifests-dir> [--out capsurface.lock.json]
  capsurface check <manifests-dir> --baseline capsurface.lock.json [--fail-on-new]
  capsurface diff <baseline-manifest.json> <current-manifest.json>
`);
      process.exit(cmd ? 2 : 0);
  }
}

main();
