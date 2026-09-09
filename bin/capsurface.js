#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests, unionOfManifests } = require('../lib/diff');
const { discoverPackageDirs } = require('../lib/discovery');
const { INSTALL_TRIGGERING_SCRIPT_KEYS } = require('../lib/categories');
const { RULES_VERSION } = require('../lib/rules-version');

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
  // stat, not existsSync: a path that is a file, or unreadable, otherwise
  // falls through to discoverPackageDirs, which swallows readdir failures,
  // and scan-tree reports 0 packages and exits 0. Silent pass is the one
  // failure mode a gate must not have.
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
  // Install-time surface before the risk ranking. The score answers "how
  // much can this package do"; a reviewer's first question is "what runs on
  // npm install", a much shorter list and the one that decides blast
  // radius. bcrypt scores 4 and would sort below twenty packages that
  // cannot execute during install at all.
  const installTime = manifests.filter(
    (m) => m.capabilities.lifecycleScripts && m.capabilities.lifecycleScripts.installTriggering
  );
  console.log(`Scanned ${manifests.length} package install(s), including nested, symlinked and pnpm-store locations.\n`);
  console.log(`Runs code at install time: ${installTime.length} of ${manifests.length}`);
  if (installTime.length) {
    for (const m of installTime.sort((a, b) => b.riskScore - a.riskScore)) {
      console.log(`  ${m.name}@${m.version}  risk=${m.riskScore}`);
      const scripts = m.capabilities.lifecycleScripts.scripts || {};
      for (const key of INSTALL_TRIGGERING_SCRIPT_KEYS) {
        if (scripts[key]) console.log(`      ${key}: ${scripts[key]}`);
      }
    }
  }

  manifests.sort((a, b) => b.riskScore - a.riskScore);
  console.log('\nHighest capability surface:\n');
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
 * Load every manifest in a directory, grouped by package name. One name can
 * hold several: two lodash versions in one tree is a routine outcome of
 * dependency resolution, not an edge case.
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
 * Load capsurface.lock.json into the Map<name, Manifest[]> shape
 * loadManifestsFromDir uses. Both the current schema and the original
 * one-manifest-per-name schema are accepted, so a lock file committed by an
 * earlier version keeps working without a migration step.
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

// npm 12 and its peers block install scripts unless a project lists the
// packages allowed to run one. Producing that list is mechanical; deciding
// what belongs on it is not, and the decision needs to know what each script
// actually reaches for. That is what the manifest already holds.
const CAPABILITY_LABELS = {
  filesystem: 'filesystem',
  network: 'network',
  exec: 'process execution',
  env: 'env',
  dynamicEval: 'dynamic eval',
  nativeFfi: 'native code',
  sensitiveTargets: 'credential paths',
};

function installTimeEntries(manifestsDir) {
  const byName = loadManifestsFromDir(manifestsDir);
  const seen = new Set();
  const entries = [];
  let total = 0;
  for (const manifests of byName.values()) {
    for (const m of manifests) {
      total++;
      if (!m.capabilities.lifecycleScripts.installTriggering) continue;
      const id = `${m.name}@${m.version}`;
      if (seen.has(id)) continue;
      seen.add(id);
      entries.push(m);
    }
  }
  return { entries, total };
}

function cmdAllowlist(args) {
  const { positional, flags } = parseFlags(args);
  const manifestsDir = positional[0];
  if (!manifestsDir) {
    die('usage: capsurface allowlist <manifests-dir> [--format npm|pnpm|json] [--names] [--out <file>]');
  }
  const format = flags.format || 'npm';
  const nameOnly = flags.names === true;
  const { entries, total } = installTimeEntries(manifestsDir);

  const ids = entries
    .map((m) => (nameOnly ? m.name : `${m.name}@${m.version}`))
    .filter((v, i, a) => a.indexOf(v) === i)
    .sort();

  if (format === 'json') {
    const payload = {
      generatedAt: new Date().toISOString(),
      rulesVersion: RULES_VERSION,
      packagesScanned: total,
      allow: ids,
      packages: entries.map((m) => ({
        name: m.name,
        version: m.version,
        installPath: m.installPath,
        scripts: Object.fromEntries(
          INSTALL_TRIGGERING_SCRIPT_KEYS
            .filter((k) => m.capabilities.lifecycleScripts.scripts[k])
            .map((k) => [k, m.capabilities.lifecycleScripts.scripts[k]])
        ),
        capabilities: Object.keys(CAPABILITY_LABELS).filter((k) => m.capabilities[k] && m.capabilities[k].present),
        endpoints: (m.capabilities.network.endpoints || []).slice(0, 5),
        riskScore: m.riskScore,
        riskFlags: m.riskFlags,
      })),
    };
    const text = JSON.stringify(payload, null, 2);
    if (flags.out) {
      writeJson(String(flags.out), payload);
      console.log(`Wrote ${ids.length} allowlist entr(ies) to ${flags.out}`);
    } else {
      console.log(text);
    }
    return;
  }

  const body =
    format === 'pnpm'
      ? ['onlyBuiltDependencies:', ...ids.map((id) => `  - ${id}`)].join('\n')
      : ['  "allowScripts": [', ids.map((id) => `    ${JSON.stringify(id)}`).join(',\n'), '  ]'].join('\n');
  const where = format === 'pnpm' ? 'pnpm-workspace.yaml' : 'package.json';

  console.log(`${entries.length} of ${total} installed package(s) run code at install time.\n`);
  if (!entries.length) {
    console.log('Nothing to allow. Every dependency in this tree installs without running anything.');
    return;
  }
  console.log(`Add to ${where}:\n`);
  console.log(body + '\n');
  console.log('What each one does at install time, from its own source:\n');

  for (const m of entries.slice().sort((a, b) => b.riskScore - a.riskScore)) {
    console.log(`  ${m.name}@${m.version}${m.installPath ? `  (${m.installPath})` : ''}`);
    for (const key of INSTALL_TRIGGERING_SCRIPT_KEYS) {
      const cmd = m.capabilities.lifecycleScripts.scripts[key];
      if (cmd) console.log(`      ${key.padEnd(12)}${cmd}`);
    }
    const caps = Object.keys(CAPABILITY_LABELS)
      .filter((k) => m.capabilities[k] && m.capabilities[k].present)
      .map((k) => CAPABILITY_LABELS[k]);
    if (caps.length) console.log(`      ${'reaches'.padEnd(12)}${caps.join(', ')}`);
    // Concrete hosts first: an endpoint built from a template literal is
    // truncated at the interpolation and tells a reviewer less than a plain
    // one does.
    const endpoints = (m.capabilities.network.endpoints || [])
      .slice()
      .sort((a, b) => Number(a.includes('${')) - Number(b.includes('${')))
      .slice(0, 3)
      .map((e) => (e.length > 60 ? e.slice(0, 57) + '...' : e));
    if (endpoints.length) console.log(`      ${'talks to'.padEnd(12)}${endpoints.join(', ')}`);
    for (const f of m.riskFlags) console.log(`      ⚠ ${f}`);
    console.log('');
  }

  console.log('This list is the blast radius of `npm install` for this tree. Anything not on');
  console.log('it cannot execute during install at all, whatever else its code can do.');
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

  // A baseline records what the rules said when it was approved. If the
  // rules have changed since, the same dependency produces a different
  // manifest, so a difference here is not evidence about your dependencies.
  // Saying which it is matters: "we changed the rules" and "a dependency
  // changed" are different events.
  const baselineRules = new Set();
  for (const manifests of baselineByName.values()) {
    for (const m of manifests) baselineRules.add(m.rulesVersion || 'pre-versioning');
  }
  const staleRules = [...baselineRules].filter((v) => v !== RULES_VERSION);
  if (staleRules.length) {
    console.error(
      `capsurface: WARNING: this baseline was written by different scanning rules ` +
        `(${staleRules.join(', ')}, now ${RULES_VERSION}). Capabilities can appear or ` +
        `disappear from a rule change alone. Re-run "capsurface baseline" and review ` +
        `the diff before trusting this result.\n`
    );
  }

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
    // Whoever reads this has to decide between "this is an attack" and "this
    // is a legitimate upgrade", and the second answer needs a command. Not
    // printing it here means going to find the README mid-review.
    const baselineArg = flags.baseline || 'capsurface.lock.json';
    console.error('capsurface check FAILED.\n');
    console.error('Each entry above names a dependency that can do something it could not do');
    console.error('when the baseline was approved. Look at the package and version named,');
    console.error('then either reject the upgrade or accept the new surface with:\n');
    console.error(`    capsurface baseline ${manifestsDir} --out ${baselineArg}\n`);
    console.error('Commit the updated baseline in the same change, so the approval is');
    console.error('reviewed alongside the upgrade that caused it.');
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
    case 'allowlist':
      return cmdAllowlist(rest);
    default:
      console.log(`capsurface: capability-aware supply-chain scanner

Usage:
  capsurface scan <package-dir> [--out manifest.json]
  capsurface scan-tree <node_modules-dir> --out <manifests-dir>
  capsurface baseline <manifests-dir> [--out capsurface.lock.json]
  capsurface check <manifests-dir> --baseline capsurface.lock.json [--fail-on-new]
  capsurface diff <baseline-manifest.json> <current-manifest.json>
  capsurface allowlist <manifests-dir> [--format npm|pnpm|json] [--names] [--out <file>]
`);
      process.exit(cmd ? 2 : 0);
  }
}

main();
