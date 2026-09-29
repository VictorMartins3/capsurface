'use strict';

const crypto = require('crypto');
const { compareTrees, canonical, installPath } = require('./comparison');
const { isAnalysisIncomplete } = require('./diff');
const { RULES_VERSION } = require('./rules-version');
const { validIntegrity } = require('./content-integrity');
const { contextLines } = require('./source-context');
const { installLines } = require('./install-context');
const { buildAudit } = require('./review-audit');

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

function buildReview(baselineByName, currentByName, failOnNew = false, provenance, approvalHistory = []) {
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
    const blocking = report.escalated || (failOnNew && isNew);
    const blockingReasons = report.changes.filter((change) => change.escalates).map((change) => change.detail);
    if (report.escalated) {
      blockingReasons.push(...report.newRiskFlags.filter((flag) => /^(HIGH|CRITICAL)/.test(flag)));
      if (!blockingReasons.length) blockingReasons.push('The comparison requires explicit review; see predecessor selection and risk flags.');
    }
    if (failOnNew && isNew) blockingReasons.push('New installation has no approved baseline (--fail-on-new).');
    entries.push({
      id, name: manifest.name, installPath: manifest.installPath,
      baselineVersion: report.baselineVersion, currentVersion: manifest.version,
      match: { kind: match.kind, candidates: match.candidates.map(({ manifest: candidate }) => ({
        version: candidate.version, installPath: candidate.installPath,
      })) },
      newPackage: isNew,
      escalated: report.escalated,
      requiresApproval: report.escalated || isNew,
      rulesChanged, blocking, blockingReasons,
      ...(provenance ? { provenance: provenance(manifest) } : {}),
      approvable: !isAnalysisIncomplete(manifest) && manifest.rulesVersion === RULES_VERSION && validIntegrity(manifest.contentIntegrity),
      contentIntegrity: manifest.contentIntegrity,
      approval: match.manifest && match.manifest.approval,
      changes: report.changes,
      newRiskFlags: report.newRiskFlags,
      capabilities: Object.keys(manifest.capabilities).filter((key) => manifest.capabilities[key].present),
      coverage: manifest.coverage,
      analysisProfile: manifest.analysisProfile,
      ...(manifest.scanOrigin ? { scanOrigin: manifest.scanOrigin, artifact: manifest.artifact } : {}),
      ...(manifest.astCoverage ? { astCoverage: manifest.astCoverage } : {}),
      sourceContext: manifest.sourceContext,
      installContext: manifest.installContext,
      evidence,
      baselineEvidence: match.candidates.map(({ manifest: candidate }) => ({
        version: candidate.version,
        installPath: candidate.installPath,
        analysisIncomplete: !!isAnalysisIncomplete(candidate),
        rulesVersion: candidate.rulesVersion,
        evidence: relevant.flatMap((category) => ((candidate.capabilities[category] || {}).evidence || [])
          .map((item) => ({ category, ...item }))),
      })),
    });
  }
  entries.sort((a, b) => `${a.name}\0${a.installPath || ''}\0${a.currentVersion}`.localeCompare(`${b.name}\0${b.installPath || ''}\0${b.currentVersion}`));
  return {
    report: {
      schemaVersion: 1, rulesVersion: RULES_VERSION,
      manifestsScanned: comparisons.length,
      audit: buildAudit(comparisons, failOnNew, approvalHistory),
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

function appendEvidence(lines, evidence) {
  if (!evidence.length) lines.push('No source evidence recorded for the reviewed categories.');
  for (const item of evidence.slice(0, 10)) lines.push(`- ${markdown(item.file)}:${markdown(item.line)} (${markdown(item.category)}): ${markdown(item.snippet)}`);
  if (evidence.length > 10) lines.push('- More evidence is available in the JSON report and scan manifests.');
  lines.push('');
}

function renderMarkdown(report) {
  const lines = ['# Dependency capability review', '',
    `${report.manifestsScanned} installation(s) scanned. ${report.entries.length} entry/entries to review.`, '',
    report.wouldFail ? '**The capability check would fail.**' : 'The capability check would pass.', ''];
  if (!report.entries.length) lines.push('No changes requiring review among the scanned installations.');
  if (report.audit) {
    const counts = report.audit.counts;
    lines.push('', '## Review audit', '',
      `${counts.approved} with applicable selective approval; ${counts.unchanged} unchanged without selective approval; ${counts.informational} with informational changes; ${counts.unbaselined} without a baseline; ${counts.incomplete} with incomplete analysis; ${counts['review-required']} requiring review.`, '',
      'Each installation is counted once. A passing check does not certify safety; new packages only block when --fail-on-new is enabled.', '');
    for (const item of report.audit.installations) {
      if (item.approval.status === 'none') continue;
      lines.push(`- ${markdown(item.name)}@${markdown(item.version)} at ${markdown(item.installPath || '(path unavailable)')}: approval ${markdown(item.approval.status)}.`);
      if (item.approval.source) lines.push(`  Source: selected baseline ${markdown(item.approval.baselineVersion)} at ${markdown(item.approval.baselineInstallPath || '(path unavailable)')}.`);
      if (item.approval.reason) lines.push(`  Reason: ${markdown(item.approval.reason)}.`);
      else if (item.approval.source) lines.push('  Approval reason unavailable in the matched baseline record.');
      if (item.approval.expiresAt) lines.push(`  Expires: ${markdown(item.approval.expiresAt)}.`);
      for (const reason of item.approval.reasons || []) lines.push(`  ${markdown(reason)}`);
    }
    lines.push('');
  }
  for (const entry of report.entries) {
    lines.push(`## ${markdown(entry.name)}: ${markdown(entry.baselineVersion)} → ${markdown(entry.currentVersion)}`, '',
      `Review ID: \`${entry.id}\``, '',
      `Installation: ${markdown(entry.installPath || '(path unavailable)')}. Match: ${markdown(entry.match.kind)}.`, '',
      entry.requiresApproval ? '**Explicit review required.**' : 'Informational change; no new blocking capability.', '');
    if (entry.provenance) {
      if (entry.provenance.status === 'resolved') {
        lines.push(`Dependency chain: ${entry.provenance.chain.map((p) => markdown(`${p.name}${p.version ? '@' + p.version : ''}`)).join(' → ')}`, '');
        lines.push(`Lockfile: ${markdown(entry.provenance.location.file)}:${entry.provenance.location.line}.`, '');
        for (const parent of entry.provenance.parents) lines.push(`- Required by ${markdown(parent.name)} at ${markdown(parent.path || '(project root)')} as ${markdown(parent.via)} (${markdown(parent.kind)}).`);
        if (entry.provenance.omittedParents) lines.push(`- ${entry.provenance.omittedParents} additional parent(s) omitted.`);
        lines.push('');
      } else lines.push(`Dependency origin unavailable: ${markdown(entry.provenance.reason)}.`, '');
    }
    if (entry.blocking) {
      lines.push('Blocking reasons:', '');
      for (const reason of entry.blockingReasons) lines.push(`- ${markdown(reason)}`);
      lines.push('');
    }
    if (entry.rulesChanged) lines.push('Scanning rules changed. Some differences may come from the engine update.', '');
    if (!entry.approvable) lines.push('This entry cannot be approved. Fix incomplete coverage or content integrity and rescan with the current engine.', '');
    if (entry.contentIntegrity && entry.contentIntegrity.complete) lines.push(`Content SHA-256: \`${markdown(entry.contentIntegrity.digest)}\`.`, '');
    if (entry.approval && entry.approval.expiresAt) lines.push(`Approval expires: ${markdown(entry.approval.expiresAt)}.`, '');
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
    if (entry.artifact) lines.push(`Input: verified npm tarball. Integrity: ${markdown(entry.artifact.integrity)}.`, '');
    if (entry.astCoverage) {
      lines.push(`AST coverage: ${markdown(entry.astCoverage.filesAnalyzed)} file(s) analyzed; ${markdown(entry.astCoverage.filesFailed)} unavailable.`, '');
      for (const error of entry.astCoverage.errors || []) lines.push(`- ${markdown(error.file)}:${markdown(error.line)}: ${markdown(error.reason)}.`);
      lines.push('');
    }
    lines.push('File correlation:', '', ...contextLines(entry.sourceContext).map(markdown), '');
    const paths = installLines(entry.installContext);
    if (paths.length) lines.push(...paths.map((line) => `- ${markdown(line)}`), '');
    lines.push('Source evidence before and after:', '',
      'Evidence describes what the scanner detected. Missing evidence does not prove an operation is absent.', '');
    const before = entry.baselineEvidence || [];
    if (!before.length) lines.push('Before: no baseline evidence available.', '');
    for (const candidate of before) {
      lines.push(`Before${entry.match.kind === 'ambiguous' || before.length > 1 ? ' (candidate)' : ''}: ${markdown(candidate.version)} at ${markdown(candidate.installPath || '(path unavailable)')}.`, '');
      if (candidate.analysisIncomplete) lines.push('Baseline analysis is incomplete; absence of a finding is inconclusive.', '');
      if (candidate.rulesVersion !== report.rulesVersion) lines.push('Baseline scanning rules differ from the current engine.', '');
      appendEvidence(lines, candidate.evidence);
    }
    lines.push(`After: ${markdown(entry.currentVersion)} at ${markdown(entry.installPath || '(path unavailable)')}.`, '');
    appendEvidence(lines, entry.evidence);
  }
  lines.push('Selective approval binds one installation to its version and installed file content. It does not certify safety or execute scripts.', '');
  return lines.join('\n');
}

module.exports = { buildReview, renderMarkdown, reviewId };
