'use strict';

// A saved review is evidence for inspection, not a fresh approval decision.
// Preserve its exact content-bound ID and never follow paths inside the report.
function explainReview(report, id) {
  if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new Error('explain requires an exact review --id (32 lowercase hexadecimal characters)');
  if (!report || report.schemaVersion !== 1 || typeof report.rulesVersion !== 'string' ||
      typeof report.wouldFail !== 'boolean' || !Number.isSafeInteger(report.manifestsScanned) ||
      report.manifestsScanned < 0 || !Array.isArray(report.entries)) {
    throw new Error('explain requires a review JSON report (schemaVersion 1), not check JSON or SARIF');
  }
  const matches = report.entries.filter((entry) => entry && entry.id === id);
  if (matches.length !== 1) throw new Error(matches.length ? 'review ID is not unique in this report' : 'review ID not found in this report; use the ID from the saved review');
  const entry = matches[0];
  if (typeof entry.name !== 'string' || !entry.match || typeof entry.match.kind !== 'string' ||
      !Array.isArray(entry.changes) || !Array.isArray(entry.evidence)) throw new Error('invalid review entry');
  const audit = report.audit && Array.isArray(report.audit.installations)
    ? report.audit.installations.filter((item) => item && item.name === entry.name &&
      item.version === entry.currentVersion && (item.installPath || null) === (entry.installPath || null)) : [];
  return {
    schemaVersion: 1,
    idKind: 'review-content-id',
    source: { type: 'saved-review', freshness: 'not-checked', rulesVersion: report.rulesVersion,
      ...(typeof report.baseline === 'string' ? { baseline: report.baseline } : {}) },
    report: { wouldFail: report.wouldFail, manifestsScanned: report.manifestsScanned },
    entry,
    ...(audit.length === 1 ? { audit: audit[0] } : {}),
  };
}

module.exports = { explainReview };
