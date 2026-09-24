'use strict';

const { isAnalysisIncomplete } = require('./diff');
const { installPath } = require('./comparison');
const { RULES_VERSION } = require('./rules-version');

// Describe the comparison that actually ran. Do not reevaluate expiration
// against a later clock tick or grant permissions from the current snapshot.
function auditComparison({ manifest, match, report }, failOnNew, history) {
  const incomplete = !!isAnalysisIncomplete(manifest);
  const rulesChanged = manifest.rulesVersion !== RULES_VERSION ||
    match.candidates.some(({ manifest: candidate }) => candidate.rulesVersion !== RULES_VERSION);
  const approval = { status: 'none' };
  if (match.kind === 'ambiguous') {
    approval.status = 'ambiguous';
    approval.reasons = ['No predecessor was selected; candidate approvals cannot be applied.'];
  } else if (match.manifest && match.manifest.approval !== undefined) {
    const policy = match.manifest.approval;
    approval.source = 'selected-baseline';
    approval.baselineVersion = match.manifest.version;
    approval.baselineInstallPath = installPath(match.manifest);
    if (policy && typeof policy === 'object') {
      // id and reason are never written here by approve; only a matching
      // approval record below may supply them.
      for (const key of ['approvedAt', 'expiresAt']) {
        if (typeof policy[key] === 'string') approval[key] = policy[key];
      }
      const records = history.filter((record) => record &&
        record.name === manifest.name && record.version === policy.version &&
        installPath(record) === policy.installPath && record.approvedAt === policy.approvedAt &&
        record.expiresAt === policy.expiresAt && record.rulesVersion === match.manifest.rulesVersion &&
        record.contentIntegrity && policy.contentIntegrity &&
        record.contentIntegrity.digest === policy.contentIntegrity.digest);
      if (records.length === 1) {
        for (const key of ['id', 'reason']) {
          if (typeof records[0][key] === 'string') approval[key] = records[0][key];
        }
      }
    }
    const failures = report.changes.filter((change) => change.category === 'approval');
    approval.reasons = failures.map((change) => change.detail);
    if (failures.some((change) => change.type === 'approval-invalid')) approval.status = 'invalid';
    else if (failures.some((change) => change.type === 'approval-expired')) approval.status = 'expired';
    else if (failures.length) approval.status = 'not-applicable';
    else if (incomplete || rulesChanged || report.escalated || isAnalysisIncomplete(match.manifest)) {
      approval.status = 'needs-review';
      approval.reasons.push('The recorded approval does not establish a complete, current-engine comparison without escalations.');
    } else approval.status = 'applied';
  }
  const newPackage = match.kind === 'new';
  const blocking = report.escalated || (failOnNew && newPackage);
  const noChanges = !report.changes.length && !report.newRiskFlags.length &&
    report.baselineVersion === manifest.version && !rulesChanged;
  const state = incomplete ? 'incomplete' : newPackage ? 'unbaselined' :
    blocking || rulesChanged || approval.status === 'needs-review' ? 'review-required' :
    approval.status === 'applied' ? 'approved' : noChanges ? 'unchanged' : 'informational';
  return { name: manifest.name, version: manifest.version, installPath: installPath(manifest),
    match: match.kind, state, blocking, analysisIncomplete: incomplete, rulesChanged, approval };
}

function buildAudit(comparisons, failOnNew, history = []) {
  const installations = comparisons.map((comparison) => auditComparison(comparison, failOnNew, Array.isArray(history) ? history : []));
  installations.sort((a, b) => `${a.name}\0${a.installPath || ''}\0${a.version}`.localeCompare(`${b.name}\0${b.installPath || ''}\0${b.version}`));
  const counts = { approved: 0, unchanged: 0, informational: 0, unbaselined: 0, incomplete: 0, 'review-required': 0 };
  for (const item of installations) counts[item.state]++;
  return { counts, installations };
}

module.exports = { buildAudit };
