'use strict';

const crypto = require('crypto');
const path = require('path');
const { version } = require('../package.json');
const { contextLines } = require('./source-context');
const { installLines } = require('./install-context');

const RULES = [
  ['capsurface/escalation', 'Dependency capability escalation', 'An installed dependency exceeds its reviewed capability surface.'],
  ['capsurface/new-package', 'Unreviewed dependency', 'A dependency installation has no approved baseline.'],
  ['capsurface/ambiguous-baseline', 'Ambiguous dependency predecessor', 'Several different approved surfaces could precede this installation.'],
  ['capsurface/incomplete-analysis', 'Incomplete dependency analysis', 'The scanner could not completely inspect this installation.'],
  ['capsurface/change', 'Dependency review information', 'An installation changed without adding a blocking capability.'],
].map(([id, title, detail]) => ({ id, shortDescription: { text: title }, fullDescription: { text: detail },
  help: { text: 'Inspect the dependency changes and source evidence with capsurface review. Approve one reviewed installation with capsurface approve --id <review-id> --reason <reason>.' } }));

function location(file, line) {
  if (typeof file !== 'string') return null;
  const normalized = file.replace(/\\/g, '/');
  if (path.posix.isAbsolute(normalized) || /^[A-Za-z]:/.test(normalized) ||
      normalized.split('/').some((part) => !part || part === '.' || part === '..') || /[\x00-\x1f]/.test(normalized)) return null;
  const physicalLocation = { artifactLocation: { uri: normalized.split('/').map(encodeURIComponent).join('/') } };
  if (Number.isSafeInteger(line) && line > 0) physicalLocation.region = { startLine: line };
  return { physicalLocation };
}

function ruleFor(entry) {
  if (entry.capabilities.includes('analysisIncomplete') || (entry.coverage && !entry.coverage.complete)) {
    return 'capsurface/incomplete-analysis';
  }
  if (entry.match.kind === 'ambiguous') return 'capsurface/ambiguous-baseline';
  if (entry.newPackage) return 'capsurface/new-package';
  if (entry.escalated) return 'capsurface/escalation';
  return 'capsurface/change';
}

function renderSarif(report) {
  const results = report.entries.map((entry) => {
    const ruleId = ruleFor(entry);
    const lines = [`${entry.name}: ${entry.baselineVersion} -> ${entry.currentVersion}`,
      `Installation: ${entry.installPath || '(unknown)'}`, `Review ID: ${entry.id}`,
      entry.blocking ? 'Capability check: blocked.' : 'Capability check: informational.'];
    if (entry.provenance && entry.provenance.status === 'resolved') {
      lines.push(`Dependency chain: ${entry.provenance.chain.map((p) => `${p.name}${p.version ? '@' + p.version : ''}`).join(' -> ')}`);
    } else if (entry.provenance) lines.push(`Dependency origin unavailable: ${entry.provenance.reason}`);
    for (const reason of entry.blockingReasons || []) lines.push(`Block reason: ${reason}`);
    for (const change of entry.changes) lines.push(`${change.type}: ${change.detail}`);
    for (const flag of entry.newRiskFlags) lines.push(flag);
    lines.push(...contextLines(entry.sourceContext));
    lines.push(...installLines(entry.installContext));
    // These are category samples, not proof that an endpoint is used or that
    // two capabilities are on the same execution path.
    for (const evidence of entry.evidence) lines.push(`Evidence (${evidence.category}): ${evidence.file}:${evidence.line}: ${evidence.snippet}`);
    const result = { ruleId, ruleIndex: RULES.findIndex((rule) => rule.id === ruleId),
      level: entry.blocking ? 'error' : 'note', message: { text: lines.join('\n') },
      partialFingerprints: { 'capsurface/installation/v1': crypto.createHash('sha256')
        .update(JSON.stringify([ruleId, entry.name, entry.installPath || ''])).digest('hex') },
      properties: { reviewId: entry.id, blocking: entry.blocking, evidence: entry.evidence,
        analysisProfile: entry.analysisProfile,
        ...(entry.astCoverage ? { astCoverage: entry.astCoverage } : {}),
        ...(entry.sourceContext ? { sourceContext: entry.sourceContext } : {}),
        ...(entry.installContext ? { installContext: entry.installContext } : {}),
        ...(entry.provenance ? { provenance: entry.provenance } : {}) } };
    const origin = entry.provenance && entry.provenance.location;
    const primary = origin && location(origin.file, origin.line);
    if (primary) result.locations = [primary];
    else if (entry.installPath) {
      const evidence = entry.evidence.find((item) => location(`node_modules/${entry.installPath}/${item.file}`, item.line));
      if (evidence) result.locations = [location(`node_modules/${entry.installPath}/${evidence.file}`, evidence.line)];
    }
    return result;
  });
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
    tool: { driver: { name: 'capsurface', version, informationUri: 'https://github.com/VictorMartins3/capsurface', rules: RULES } },
    automationDetails: { id: 'capsurface/dependency-review/' },
    properties: { rulesVersion: report.rulesVersion, wouldFail: report.wouldFail }, results,
  }] };
}

module.exports = { renderSarif };
