'use strict';

const fs = require('fs');
const { buildReview } = require('./review');
const { installPath } = require('./comparison');
const { isAnalysisIncomplete } = require('./diff');
const { RULES_VERSION } = require('./rules-version');
const { atomicWrite } = require('./snapshot');
const { validIntegrity } = require('./content-integrity');
const { expiryTime } = require('./approval-policy');

function baselinePackages(lock) {
  if (!lock || ![1, 2].includes(lock.schemaVersion) || !lock.packages || typeof lock.packages !== 'object' || Array.isArray(lock.packages)) {
    throw new Error('invalid or unsupported baseline');
  }
  return new Map(Object.entries(lock.packages).map(([name, value]) => [name, Array.isArray(value) ? value : [value]]));
}

function approve(baselineFile, currentByName, id, reason, expiresAt) {
  if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new Error('approve requires a review --id');
  if (typeof reason !== 'string' || !reason.trim()) throw new Error('approve requires a nonempty --reason');
  if (expiresAt !== undefined && !(expiryTime(expiresAt) > Date.now())) {
    throw new Error('--expires must be a future UTC timestamp (YYYY-MM-DDTHH:mm:ssZ)');
  }
  const guard = `${baselineFile}.approval-lock`;
  let fd;
  try {
    fd = fs.openSync(guard, 'wx');
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('baseline is locked by another approval; inspect an interrupted approval before removing its lock');
    throw error;
  }
  fs.closeSync(fd);
  try {
    const original = fs.readFileSync(baselineFile, 'utf8');
    const lock = JSON.parse(original);
    if ((lock.approvals || []).some((entry) => entry.id === id)) throw new Error('review ID has already been approved; run review again');
    const baselineByName = baselinePackages(lock);
    const { selections } = buildReview(baselineByName, currentByName);
    const selected = selections.filter((entry) => entry.id === id);
    if (selected.length !== 1) throw new Error('review ID is stale, missing or not unique; run review again');
    const { manifest, match } = selected[0];
    if (isAnalysisIncomplete(manifest)) throw new Error('cannot approve incomplete analysis');
    if (manifest.rulesVersion !== RULES_VERSION) throw new Error('rescan with the current engine before approving');
    if (!validIntegrity(manifest.contentIntegrity)) throw new Error('rescan with complete content integrity before approving');
    const approvedAt = new Date().toISOString();
    const policy = { schemaVersion: 1, version: manifest.version, installPath: installPath(manifest), contentIntegrity: manifest.contentIntegrity,
      approvedAt, ...(expiresAt === undefined ? {} : { expiresAt }) };
    const approved = { ...manifest, approval: policy };

    const baselines = (baselineByName.get(manifest.name) || []).slice();
    let replace = -1;
    if (match.index !== undefined && match.kind !== 'equivalent-surface') {
      const prior = baselines[match.index];
      // A relocated/new copy must not remove the approval still used by
      // another current installation of the predecessor.
      const stillInstalled = (currentByName.get(manifest.name) || []).some((other) =>
        other !== manifest && other.version === prior.version &&
          (installPath(prior) === null || installPath(other) === installPath(prior))
      );
      if (!stillInstalled) replace = match.index;
    }
    if (replace < 0) baselines.push(approved);
    else baselines[replace] = approved;
    baselineByName.set(manifest.name, baselines);
    const updated = {
      ...lock, schemaVersion: 2, generatedAt: approvedAt,
      packages: Object.fromEntries(baselineByName),
      approvals: [...(lock.approvals || []), {
        id, name: manifest.name, version: manifest.version, installPath: manifest.installPath,
        reason: reason.trim(), approvedAt, rulesVersion: RULES_VERSION,
        contentIntegrity: manifest.contentIntegrity,
        ...(expiresAt === undefined ? {} : { expiresAt }),
      }],
    };
    if (fs.readFileSync(baselineFile, 'utf8') !== original) throw new Error('baseline changed during approval; run review again');
    atomicWrite(baselineFile, JSON.stringify(updated, null, 2));
    return manifest;
  } finally {
    fs.unlinkSync(guard);
  }
}

module.exports = { approve, baselinePackages };
