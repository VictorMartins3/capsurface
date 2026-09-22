'use strict';

const { diffManifests } = require('./diff');

function installPath(manifest) {
  return typeof manifest.installPath === 'string' ? manifest.installPath.replace(/\\/g, '/') : null;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

// Evidence locations and timestamps are not permissions. Two candidates
// can share an approved surface even when their source layouts differ.
function surface(manifest) {
  const capabilities = Object.fromEntries(Object.entries(manifest.capabilities).map(([key, cap]) => [key,
    Object.fromEntries(Object.entries(cap).filter(([field]) => field !== 'evidence').map(([field, value]) =>
      [field, Array.isArray(value) ? value.slice().sort() : value]
    )),
  ]));
  return JSON.stringify(canonical({ capabilities, riskFlags: (manifest.riskFlags || []).slice().sort(), rulesVersion: manifest.rulesVersion }));
}

function selectBaseline(baselines, current) {
  if (!baselines.length) return { kind: 'new', candidates: [] };
  let candidates = baselines.map((manifest, index) => ({ manifest, index }));
  const samePath = installPath(current) === null ? [] : candidates.filter(({ manifest }) => installPath(manifest) === installPath(current));
  if (samePath.length) candidates = samePath;
  const sameVersion = candidates.filter(({ manifest }) => manifest.version === current.version);
  if (sameVersion.length) candidates = sameVersion;
  if (candidates.length === 1) {
    return { kind: samePath.length ? 'install-path' : sameVersion.length ? 'version' : 'single-baseline', ...candidates[0], candidates };
  }
  const approved = surface(candidates[0].manifest);
  if (candidates.every(({ manifest }) => surface(manifest) === approved)) {
    return { kind: 'equivalent-surface', ...candidates[0], candidates };
  }
  return { kind: 'ambiguous', candidates };
}

function compareTrees(baselineByName, currentByName) {
  const entries = [];
  for (const [name, manifests] of currentByName) {
    for (const manifest of manifests) {
      const match = selectBaseline(baselineByName.get(name) || [], manifest);
      let report;
      if (match.kind === 'ambiguous') {
        // Show every candidate's differences; none can lend permissions to
        // another. An explicit review resolves this instead of a version guess.
        const reports = match.candidates.map((candidate) => diffManifests(candidate.manifest, manifest));
        report = {
          name, currentVersion: manifest.version,
          baselineVersion: match.candidates.map((c) => c.manifest.version).join(', '),
          escalated: true,
          changes: [{ type: 'ambiguous-baseline', category: 'baseline', label: 'Ambiguous predecessor', escalates: true,
            detail: 'Several different approved surfaces could precede this installation. Review this instance explicitly.' },
          ...reports.flatMap((r) => r.changes)],
          newRiskFlags: [...new Set(reports.flatMap((r) => r.newRiskFlags))],
          riskScoreDelta: null,
        };
      } else {
        report = diffManifests(match.manifest || manifest, manifest);
        if (match.kind === 'new') {
          report.baselineVersion = '(not baselined)';
          report.newRiskFlags = manifest.riskFlags || [];
        }
      }
      entries.push({ manifest, match, report });
    }
  }
  return entries;
}

module.exports = { compareTrees, selectBaseline, canonical, installPath };
