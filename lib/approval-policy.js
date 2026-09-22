'use strict';

const { validIntegrity } = require('./content-integrity');

function expiryTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return NaN;
  const normalized = value.length === 20 ? value.slice(0, -1) + '.000Z' : value;
  return new Date(time).toISOString() === normalized ? time : NaN;
}

function approvalChanges(baseline, current, now = Date.now()) {
  if (baseline.approval === undefined) return [];
  const policy = baseline.approval;
  const changes = [];
  function add(type, detail) {
    changes.push({ type, category: 'approval', label: 'Content approval', escalates: true, detail });
  }
  if (!policy || policy.schemaVersion !== 1 || !validIntegrity(policy.contentIntegrity) || typeof policy.version !== 'string') {
    add('approval-invalid', 'The content approval is invalid; review this installation again.');
    return changes;
  }
  const currentPath = typeof current.installPath === 'string' ? current.installPath.replace(/\\/g, '/') : null;
  if (policy.installPath !== currentPath) {
    add('approval-installation-changed', 'This content approval belongs to another installation path. Review this installation explicitly.');
  }
  if (!validIntegrity(current.contentIntegrity)) {
    add('approval-content-unavailable', 'The current scan has no complete content digest. Rescan before approving.');
  } else if (policy.version !== current.version || policy.contentIntegrity.digest !== current.contentIntegrity.digest) {
    add('approval-content-changed', 'Package version or installed content differs from the selective approval. Review this installation again.');
  }
  if (policy.expiresAt !== undefined) {
    const expiry = expiryTime(policy.expiresAt);
    if (!Number.isFinite(expiry)) add('approval-invalid', 'The approval expiration is invalid; review this installation again.');
    else if (expiry <= now) add('approval-expired', `The selective approval expired at ${policy.expiresAt}. Review this installation again.`);
  }
  return changes;
}

module.exports = { expiryTime, approvalChanges };
