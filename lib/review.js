'use strict';

const crypto = require('crypto');
const { compareTrees, canonical, installPath } = require('./comparison');
const { isAnalysisIncomplete } = require('./diff');
const { RULES_VERSION } = require('./rules-version');

function reviewedManifest(manifest) {
  const { scannedAt, ...content } = manifest;
  if (content.installPath !== undefined) content.installPath = installPath(manifest);
  return content;
}

function reviewId(baselines, current) {
  return crypto.createHash('sha256').update(JSON.stringify(canonical({
    rulesVersion: RULES_VERSION,
    baselines: baselines.map(reviewedManifest),
    current: reviewedManifest(current),
  }))).digest('hex').slice(0, 32);
}

function buildReview(baselineByName, currentByName, failOnNew = false) {
  const comparisons = compareTrees(baselineByName, currentByName);
  const selections = [];
  const entries = [];
  for (const { manifest, match, report } of comparisons) {
    const baselines = baselineByName.get(manifest.name) || [];
    const rulesChanged = manifest.rulesVersion !== RULES_VERSION || match.candidates.some((c) => c.manifest.rulesVersion !== RULES_VERSION);
    const isNew = match.kind === 'new';
    if (!isNew && !report.escalated && !report.changes.length && !report.newRiskFlags.length &&
        report.baselineVersion === manifest.version && !rulesChanged) continue;
    const id = reviewId(baselines, manifest);
    selections.push({ id, manifest, match });
    const relevant = isNew || match.kind === 'ambiguous'
      ? Object.keys(manifest.capabilities)
      : [...new Set(report.changes.map((change) => change.category))];
    const evidence = relevant.flatMap((category) => ((manifest.capabilities[category] || {}).evidence || [])
      .map((item) => ({ category, ...item })));
    entries.push({
      id, name: manifest.name, installPath: manifest.installPath,
      baselineVersion: report.baselineVersion, currentVersion: manifest.version,
      match: { kind: match.kind, candidates: match.candidates.map(({ manifest: candidate }) => ({
        version: candidate.version, installPath: candidate.installPath,
      })) },
      newPackage: isNew,
      escalated: report.escalated,
      requiresApproval: report.escalated || isNew,
      rulesChanged,
      approvable: !isAnalysisIncomplete(manifest) && manifest.rulesVersion === RULES_VERSION,
      changes: report.changes,
      newRiskFlags: report.newRiskFlags,
      capabilities: Object.keys(manifest.capabilities).filter((key) => manifest.capabilities[key].present),
      coverage: manifest.coverage,
      evidence,
    });
  }
  entries.sort((a, b) => `${a.name}\0${a.installPath || ''}\0${a.currentVersion}`.localeCompare(`${b.name}\0${b.installPath || ''}\0${b.currentVersion}`));
  return {
    report: {
      schemaVersion: 1, rulesVersion: RULES_VERSION,
      manifestsScanned: comparisons.length,
      wouldFail: comparisons.some(({ match, report }) => report.escalated || (failOnNew && match.kind === 'new')),
      entries,
    },
    selections,
  };
}

// All package names, source snippets and error strings are untrusted text.
// Escaping also keeps a dependency from adding links or headings to a PR summary.
function markdown(value) {
  return String(value).replace(/[\r\n\t]/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/[\\`*_{}\[\]()#+.!|~-]/g, '\\$&');
}

function renderMarkdown(report) {
  const lines = ['# Dependency capability review', '',
    `${report.manifestsScanned} installation(s) scanned. ${report.entries.length} entry/entries to review.`, '',
    report.wouldFail ? '**The capability check would fail.**' : 'The capability check would pass.', ''];
  if (!report.entries.length) lines.push('No changes requiring review among the scanned installations.');
  for (const entry of report.entries) {
    lines.push(`## ${markdown(entry.name)}: ${markdown(entry.baselineVersion)} → ${markdown(entry.currentVersion)}`, '',
      `Review ID: \`${entry.id}\``, '',
      `Installation: ${markdown(entry.installPath || '(path unavailable)')}. Match: ${markdown(entry.match.kind)}.`, '',
      entry.requiresApproval ? '**Explicit review required.**' : 'Informational change; no new blocking capability.', '');
    if (entry.rulesChanged) lines.push('Scanning rules changed. Some differences may come from the engine update.', '');
    if (!entry.approvable) lines.push('This entry cannot be approved. Fix incomplete coverage or rescan with the current engine.', '');
    if (entry.match.kind === 'ambiguous') {
      lines.push('Possible predecessors:', '');
      for (const candidate of entry.match.candidates) lines.push(`- ${markdown(candidate.version)} at ${markdown(candidate.installPath || '(path unavailable)')}`);
      lines.push('');
    }
    if (entry.newPackage) lines.push(`Detected capabilities: ${markdown(entry.capabilities.join(', ') || 'none')}.`, '');
    for (const change of entry.changes) lines.push(`- **${markdown(change.type)}:** ${markdown(change.detail)}`);
    for (const flag of entry.newRiskFlags) lines.push(`- ${markdown(flag)}`);
    if (entry.changes.length || entry.newRiskFlags.length) lines.push('');
    if (entry.coverage) lines.push(`Coverage: ${markdown(entry.coverage.filesRead)} source file(s) read; ${markdown(entry.coverage.filesSkipped)} skipped; ${markdown(entry.coverage.errorCount)} I/O error(s).`, '');
    if (entry.evidence.length) {
      lines.push('Source evidence:', '');
      for (const item of entry.evidence.slice(0, 10)) lines.push(`- ${markdown(item.file)}:${markdown(item.line)} (${markdown(item.category)}): ${markdown(item.snippet)}`);
      if (entry.evidence.length > 10) lines.push('- More evidence is available in the JSON report and scan manifests.');
      lines.push('');
    }
  }
  lines.push('Approval accepts the observed surface of one installation. It does not certify package contents or execute scripts.', '');
  return lines.join('\n');
}

module.exports = { buildReview, renderMarkdown, reviewId };
