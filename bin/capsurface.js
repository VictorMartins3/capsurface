#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests, unionOfManifests } = require('../lib/diff');
const { discoverPackageDirs } = require('../lib/discovery');

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
