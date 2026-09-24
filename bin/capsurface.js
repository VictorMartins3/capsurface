#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanPackageDir } = require('../lib/scanner');
const { diffManifests, isAnalysisIncomplete } = require('../lib/diff');
const { discoverPackageDirs } = require('../lib/discovery');
const { INSTALL_TRIGGERING_SCRIPT_KEYS } = require('../lib/categories');
const { RULES_VERSION } = require('../lib/rules-version');
const { compareTrees } = require('../lib/comparison');
const { buildReview, renderMarkdown, reviewId } = require('../lib/review');
const { loadProvenance } = require('../lib/provenance');
const { renderSarif } = require('../lib/sarif');
const { approve, baselinePackages: loadBaseline } = require('../lib/approval');
const { beginSnapshot, readManifests } = require('../lib/snapshot');

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
      if (key === 'deep') { flags.deep = true; continue; }
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
  const manifest = scanPackageDir(dir, { deep: flags.deep });
  if (flags.out) {
    writeJson(flags.out, manifest);
    console.log(`wrote ${flags.out}`);
  } else {
    console.log(JSON.stringify(manifest, null, 2));
  }
  if (isAnalysisIncomplete(manifest)) process.exitCode = 2;
  if (manifest.riskFlags.length) {
    console.error('\nRisk flags:');
    for (const f of manifest.riskFlags) console.error(`  - ${f}`);
  }
}

function cmdScanLock(args) {
  const { positional, flags } = parseFlags(args);
  if (positional.length !== 1 || typeof flags.tarballs !== 'string' || typeof flags.out !== 'string') {
    die('usage: capsurface scan-lock <package-lock.json> --tarballs <map.json> --out <manifests-dir> [--deep]');
  }
  const result = require('../lib/lockfile-scan').scanLockfile(positional[0], flags.tarballs, flags.out, { deep: flags.deep });
  console.log(`Scanned ${result.count} locked tarball(s) without installing packages or running scripts.`);
  console.log(`Manifests written to ${flags.out}/`);
  if (result.incomplete) { console.error(`${result.incomplete} package(s) have incomplete analysis.`); process.exitCode = 2; }
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
  if (flags.deep) require('../lib/ast-imports').loadParser();
  const snapshot = beginSnapshot(flags.out);
  try {
    const { dirs: pkgDirs, skippedEscapes, errors, errorCount } = discoverPackageDirs(rootDir, discoverOpts);
    for (const error of errors) {
      console.error(`capsurface: discovery ${error.operation} failed: ${error.path} (${error.code})`);
    }
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
      const manifest = scanPackageDir(dir, { deep: flags.deep });
      manifest.installPath = path.relative(rootDir, dir);
      manifests.push(manifest);

      const safePart = (value) => String(value).replace(/[\\/<>:"|?*\x00-\x1f]/g, '__');
      const base = `${safePart(manifest.name)}@${safePart(manifest.version)}`;
      let filename = `${base}.json`;
      let n = 2;
      // Two different physical installs can legitimately share the same
      // name@version (rare, but possible with vendored/duplicated copies);
      // disambiguate rather than silently overwriting one manifest with the
      // other.
      while (usedFilenames.has(filename.toLowerCase())) {
        filename = `${base}__${n}.json`;
        n++;
      }
      usedFilenames.add(filename.toLowerCase());
      snapshot.write(filename, manifest);
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

    if (errorCount) {
      console.error(`capsurface scan-tree FAILED: ${errorCount} discovery error(s); inventory is incomplete.`);
      process.exitCode = 2;
    } else if (skippedEscapes.length) {
      // An escape attempt must fail the exit code, not just print a WARNING.
      // Otherwise a CI pipeline checking only the exit code would treat this
      // as a clean, passing run.
      console.error(`capsurface scan-tree FAILED: ${skippedEscapes.length} package symlink(s) tried to escape the project boundary (see WARNING above).`);
      process.exitCode = 1;
    } else {
      snapshot.complete();
      if (manifests.some(isAnalysisIncomplete)) {
        console.error('capsurface scan-tree FAILED: incomplete package analysis; see manifest coverage.');
        process.exitCode = 2;
      }
    }
  } finally {
    snapshot.close();
  }
}

/**
 * Load every manifest in a directory, grouped by package name. One name can
 * hold several: two lodash versions in one tree is a routine outcome of
 * dependency resolution, not an edge case.
 */
function loadManifestsFromDir(dir) {
  const byName = new Map();
  for (const m of readManifests(dir)) {
    if (!byName.has(m.name)) byName.set(m.name, []);
    byName.get(m.name).push(m);
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
  if ([...byName.values()].some((manifests) => manifests.some(isAnalysisIncomplete))) {
    die('cannot approve incomplete analysis; fix the coverage errors and scan again');
  }
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
      if (isAnalysisIncomplete(m)) die('cannot generate an allowlist from incomplete analysis; scan again after fixing coverage errors');
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
  if (!manifestsDir) {
    die('usage: capsurface check <manifests-dir> --baseline capsurface.lock.json [--fail-on-new] [--report-only] [--json]');
  }
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

  const entries = compareTrees(baselineByName, currentByName);
  const newPackages = entries.filter((entry) => entry.match.kind === 'new').map((entry) => entry.manifest);
  const escalations = entries.filter((entry) => entry.report.escalated).map((entry) => ({
    report: entry.report, installPath: entry.manifest.installPath, match: entry.match.kind,
    id: reviewId(baselineByName.get(entry.manifest.name) || [], entry.manifest),
  }));
  const anyEscalation = escalations.length > 0;
  const totalCurrentManifests = entries.length;
  const totalBaselineManifests = [...baselineByName.values()].reduce((sum, manifests) => sum + manifests.length, 0);

  // A report nobody can aggregate is a report nobody keeps. --report-only
  // asks a team to collect weeks of findings before switching the gate on,
  // and that is only worth doing if the output goes somewhere other than a
  // CI log.
  if (flags.json) {
    const payload = {
      rulesVersion: RULES_VERSION,
      baseline: baselineFile,
      manifestsScanned: totalCurrentManifests,
      baselineManifests: totalBaselineManifests,
      escalated: anyEscalation,
      reportOnly: flags['report-only'] === true,
      newPackages: newPackages.map((m) => ({
        name: m.name,
        version: m.version,
        installPath: m.installPath,
        riskScore: m.riskScore,
        riskFlags: m.riskFlags,
      })),
      escalations: escalations.map(({ report, installPath, match, id }) => ({
        id, match,
        name: report.name,
        baselineVersion: report.baselineVersion,
        currentVersion: report.currentVersion,
        installPath,
        riskScoreDelta: report.riskScoreDelta,
        changes: report.changes,
        newRiskFlags: report.newRiskFlags,
      })),
    };
    console.log(JSON.stringify(payload, null, 2));
    const failing = anyEscalation || (flags['fail-on-new'] && newPackages.length > 0);
    process.exit(failing && !flags['report-only'] ? 1 : 0);
  }

  console.log(`capsurface check: ${totalCurrentManifests} manifest(s) scanned against baseline of ${totalBaselineManifests}\n`);

  let anyNewFailure = false;
  if (newPackages.length) {
    console.log(`NEW packages not in baseline (${newPackages.length}):`);
    for (const m of newPackages) {
      console.log('  + ' + summaryLine(m));
    }
    console.log('  (run "capsurface review" to inspect and approve individual installations)\n');
    anyNewFailure = flags['fail-on-new'] === true;
  }

  if (escalations.length) {
    console.log(`CAPABILITY ESCALATIONS (${escalations.length}):`);
    for (const { report: r, installPath, id } of escalations) {
      const where = installPath ? `  [${installPath}]` : '';
      console.log(`\n  ${r.name}: ${r.baselineVersion} -> ${r.currentVersion}${where}  (risk delta ${r.riskScoreDelta === null ? 'unknown' : (r.riskScoreDelta >= 0 ? '+' : '') + r.riskScoreDelta})`);
      console.log(`    review ID: ${id}`);
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

  // Nobody turns a blocking gate on in an unfamiliar codebase on day one.
  // --report-only prints the same report and exits 0, so a team can run it
  // for a few weeks, see what it would have stopped, and decide from data.
  if (flags['report-only']) {
    if (shouldFail) {
      console.log('capsurface check: REPORT ONLY, exiting 0.\n');
      console.log('Without --report-only this run would have failed the build.');
      console.log('Drop the flag once the findings above look like ones you want to block on.');
    } else {
      console.log('capsurface check passed. (--report-only, nothing would have failed anyway)');
    }
    return;
  }

  if (shouldFail) {
    // Whoever reads this has to decide between "this is an attack" and "this
    // is a legitimate upgrade", and the second answer needs a command. Not
    // printing it here means going to find the README mid-review.
    const baselineArg = flags.baseline || 'capsurface.lock.json';
    console.error('capsurface check FAILED.\n');
    console.error('Review the changed surface, incomplete analysis or ambiguous predecessor:');
    console.error(`    capsurface review ${manifestsDir} --baseline ${baselineArg}\n`);
    console.error('To accept one reviewed installation, use approve with its --id and --reason.');
    console.error('Commit the updated baseline in the same change, so the approval is');
    console.error('reviewed alongside the upgrade that caused it.');
    process.exit(1);
  } else {
    console.log('capsurface check passed.');
  }
}

function cmdReview(args) {
  const { positional, flags } = parseFlags(args);
  if (!positional[0]) die('usage: capsurface review <manifests-dir> --baseline <file> [--json | --format markdown|json|sarif] [--lockfile <package-lock.json>] [--project-root <dir>] [--out <file>] [--fail-on-new] [--report-only]');
  const baselineFile = flags.baseline || 'capsurface.lock.json';
  const format = flags.format || (flags.json ? 'json' : 'markdown');
  if (!['markdown', 'json', 'sarif'].includes(format)) die('--format must be markdown, json or sarif');
  if (flags.json && format !== 'json') die('--json cannot be combined with another --format');
  if (flags.lockfile !== undefined && typeof flags.lockfile !== 'string') die('--lockfile requires a filename');
  if (flags['project-root'] !== undefined && typeof flags['project-root'] !== 'string') die('--project-root requires a directory');
  const provenance = flags.lockfile ? loadProvenance(flags.lockfile, flags['project-root']) : undefined;
  const lock = readJson(baselineFile);
  const { report } = buildReview(loadBaseline(lock), loadManifestsFromDir(positional[0]), flags['fail-on-new'] === true, provenance, lock.approvals);
  report.baseline = baselineFile;
  report.reportOnly = flags['report-only'] === true;
  const text = format === 'markdown' ? renderMarkdown(report) : JSON.stringify(format === 'sarif' ? renderSarif(report) : report, null, 2) + '\n';
  if (flags.out) {
    fs.mkdirSync(path.dirname(flags.out), { recursive: true });
    fs.writeFileSync(flags.out, text);
    console.log(`Wrote review to ${flags.out}`);
  } else {
    process.stdout.write(text);
  }
  if (report.wouldFail && !report.reportOnly) process.exitCode = 1;
}

function cmdExplain(args) {
  const { positional, flags } = parseFlags(args);
  if (positional.length || Object.keys(flags).some((key) => !['report', 'id', 'json', 'out'].includes(key)) ||
      typeof flags.report !== 'string' || !flags.report || typeof flags.id !== 'string' ||
      (flags.json !== undefined && flags.json !== true) ||
      (flags.out !== undefined && (typeof flags.out !== 'string' || !flags.out))) {
    die('usage: capsurface explain --report <review.json> --id <review-id> [--json] [--out <file>]');
  }
  const { readBounded } = require('../lib/tarball');
  const { explainReview } = require('../lib/explain');
  const result = explainReview(JSON.parse(readBounded(flags.report, 64 * 1024 * 1024)), flags.id);
  const text = JSON.stringify(result, null, 2) + '\n';
  if (flags.out) {
    if (fs.existsSync(flags.out)) {
      const source = fs.statSync(flags.report), target = fs.statSync(flags.out);
      if (source.dev === target.dev && source.ino === target.ino) die('--out must not overwrite the source report');
    }
    fs.mkdirSync(path.dirname(flags.out), { recursive: true });
    fs.writeFileSync(flags.out, text);
  } else process.stdout.write(text);
}

function cmdApprove(args) {
  const { positional, flags } = parseFlags(args);
  if (!positional[0]) die('usage: capsurface approve <manifests-dir> --baseline <file> --id <review-id> --reason <text>');
  const baselineFile = flags.baseline || 'capsurface.lock.json';
  const manifest = approve(baselineFile, loadManifestsFromDir(positional[0]), flags.id, flags.reason, flags.expires);
  console.log(`Approved ${manifest.name}@${manifest.version}${manifest.installPath ? ` at ${manifest.installPath}` : ''}.`);
  console.log(`Updated ${baselineFile}; commit the approval with the dependency change.`);
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
    case 'scan-lock':
      return cmdScanLock(rest);
    case 'scan-tree':
      return cmdScanTree(rest);
    case 'baseline':
      return cmdBaseline(rest);
    case 'check':
      return cmdCheck(rest);
    case 'review':
      return cmdReview(rest);
    case 'explain':
      return cmdExplain(rest);
    case 'approve':
      return cmdApprove(rest);
    case 'diff':
      return cmdDiff(rest);
    case 'allowlist':
      return cmdAllowlist(rest);
    default:
      console.log(`capsurface: capability-aware supply-chain scanner

Usage:
  capsurface scan <package-dir> [--out manifest.json] [--deep]
  capsurface scan-tree <node_modules-dir> --out <manifests-dir> [--deep]
  capsurface scan-lock <package-lock.json> --tarballs <map.json> --out <manifests-dir> [--deep]
  capsurface baseline <manifests-dir> [--out capsurface.lock.json]
  capsurface check <manifests-dir> --baseline capsurface.lock.json [--fail-on-new] [--report-only] [--json]
  capsurface review <manifests-dir> --baseline <file> [--json | --format markdown|json|sarif] [--lockfile <package-lock.json>] [--project-root <dir>] [--out <file>] [--fail-on-new] [--report-only]
  capsurface approve <manifests-dir> --baseline <file> --id <review-id> --reason <text> [--expires <UTC-timestamp>]
  capsurface explain --report <review.json> --id <review-id> [--json] [--out <file>]
  capsurface diff <baseline-manifest.json> <current-manifest.json>
  capsurface allowlist <manifests-dir> [--format npm|pnpm|json] [--names] [--out <file>]
`);
      process.exit(!cmd || cmd === '--help' || cmd === '-h' ? 0 : 2);
  }
}

try {
  main();
} catch (error) {
  die(error.message);
}
