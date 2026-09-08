'use strict';

const { CATEGORIES } = require('./categories');

/**
 * Merge one or more previously-approved manifests for the same package name
 * into a synthetic "union" manifest to diff a newly-observed manifest
 * against. Needed once a baseline can hold more than one manifest per name
 * (a project can legitimately have two different installed versions of the
 * same dependency). A capability is "new" only if absent from every
 * previously-approved version, avoiding false escalations from comparing
 * against the wrong sibling version.
 *
 * Lifecycle scripts: each key maps to the array of distinct script bodies
 * ever approved under it (including `undefined` if some version had none);
 * `diffManifests` treats an array as "any of these are fine".
 */
function unionOfManifests(manifests) {
  if (!manifests || manifests.length === 0) {
    throw new Error('unionOfManifests requires at least one manifest');
  }
  // obfuscationSignal isn't in CATEGORIES (it's not a check-relevant
  // capability on its own) but must still exist on the union manifest with
  // the same {present, evidence} shape a real manifest has.
  const orMergedKeys = [...CATEGORIES.map((c) => c.key), 'obfuscationSignal'];
  const capabilities = {};
  for (const key of orMergedKeys) {
    const evidence = [];
    let present = false;
    for (const m of manifests) {
      const c = m.capabilities[key];
      if (c && c.present) present = true;
      if (c && c.evidence) evidence.push(...c.evidence);
    }
    capabilities[key] = { present, evidence: evidence.slice(0, 5) };
  }

  const endpoints = new Set();
  const vars = new Set();
  const scriptValues = {}; // key -> Set of script bodies (may include undefined)
  const riskFlags = new Set();
  let lifecyclePresent = false;
  let lifecycleInstallTriggering = false;
  let skippedLargeFilesPresent = false;
  let skippedLargeFilesCount = 0;
  const skippedLargeFilesList = [];
  for (const m of manifests) {
    for (const e of (m.capabilities.network && m.capabilities.network.endpoints) || []) endpoints.add(e);
    for (const v of (m.capabilities.env && m.capabilities.env.vars) || []) vars.add(v);
    const lifecycle = m.capabilities.lifecycleScripts || {};
    if (lifecycle.present) lifecyclePresent = true;
    if (lifecycle.installTriggering) lifecycleInstallTriggering = true;
    const scripts = lifecycle.scripts || {};
    const allKeys = new Set([...Object.keys(scriptValues), ...Object.keys(scripts)]);
    for (const key of allKeys) {
      if (!scriptValues[key]) scriptValues[key] = new Set();
      scriptValues[key].add(scripts[key]); // undefined if absent in this manifest
    }
    const skipped = m.capabilities.skippedLargeFiles || {};
    if (skipped.present) skippedLargeFilesPresent = true;
    skippedLargeFilesCount += skipped.count || 0;
    if (skippedLargeFilesList.length < 10) skippedLargeFilesList.push(...(skipped.files || []));
    for (const f of m.riskFlags || []) riskFlags.add(f);
  }
  const scripts = {};
  for (const [key, set] of Object.entries(scriptValues)) {
    scripts[key] = Array.from(set);
  }

  capabilities.network.endpoints = Array.from(endpoints);
  capabilities.env.vars = Array.from(vars);
  capabilities.lifecycleScripts = { present: lifecyclePresent, installTriggering: lifecycleInstallTriggering, scripts };
  capabilities.skippedLargeFiles = {
    present: skippedLargeFilesPresent,
    count: skippedLargeFilesCount,
    files: skippedLargeFilesList.slice(0, 10),
  };

  const versions = manifests.map((m) => m.version).join(', ');
  return {
    name: manifests[0].name,
    version: versions,
    capabilities,
    riskFlags: Array.from(riskFlags),
    riskScore: Math.max(...manifests.map((m) => m.riskScore || 0)),
  };
}

/**
 * Compare two capability manifests for the *same* package name across
 * versions (baseline = previously reviewed/approved, current = newly
 * observed) and return a structured escalation report.
 *
 * `baseline` may be a single manifest, or a synthetic union manifest from
 * `unionOfManifests` above; in the latter case `baseline.capabilities.
 * lifecycleScripts.scripts[key]` is an array of previously-approved values
 * rather than a single scalar; both shapes are handled.
 */
function diffManifests(baseline, current) {
  const changes = [];
  let escalated = false;

  for (const cat of CATEGORIES) {
    const before = baseline.capabilities[cat.key].present;
    const after = current.capabilities[cat.key].present;
    if (!before && after) {
      escalated = true;
      changes.push({
        type: 'capability-added',
        category: cat.key,
        label: cat.label,
        detail: `"${cat.label}" was not present in ${baseline.version} but appears in ${current.version}.`,
      });
    } else if (before && !after) {
      changes.push({
        type: 'capability-removed',
        category: cat.key,
        label: cat.label,
        detail: `"${cat.label}" was present in ${baseline.version} but no longer appears in ${current.version}.`,
      });
    }
  }

  // Lifecycle script content diff (even if "present" didn't change, content
  // might). `b` may be a plain string/undefined (single-manifest baseline)
  // or an array of previously-approved values (union baseline).
  const beforeScripts = baseline.capabilities.lifecycleScripts.scripts || {};
  const afterScripts = current.capabilities.lifecycleScripts.scripts || {};
  const scriptKeys = new Set([...Object.keys(beforeScripts), ...Object.keys(afterScripts)]);
  for (const key of scriptKeys) {
    const b = beforeScripts[key];
    const a = afterScripts[key];
    const approved = Array.isArray(b) ? b : [b];
    const isApproved = approved.includes(a);
    if (!isApproved) {
      escalated = true;
      const beforeDesc = Array.isArray(b)
        ? b.map((v) => (v ? JSON.stringify(v) : '(none)')).join(' OR ')
        : b
        ? JSON.stringify(b)
        : '(none)';
      changes.push({
        type: 'lifecycle-script-changed',
        category: 'lifecycleScripts',
        label: `lifecycle script "${key}"`,
        detail: `script changed:\n    previously approved: ${beforeDesc}\n    now:                 ${a ? JSON.stringify(a) : '(none)'}`,
      });
    }
  }

  // New network endpoints not seen before.
  const beforeEndpoints = new Set(baseline.capabilities.network.endpoints || []);
  const newEndpoints = (current.capabilities.network.endpoints || []).filter((e) => !beforeEndpoints.has(e));
  if (newEndpoints.length > 0) {
    escalated = true;
    changes.push({
      type: 'new-network-endpoints',
      category: 'network',
      label: 'network endpoints',
      detail: `new literal endpoint(s) referenced: ${newEndpoints.join(', ')}`,
    });
  }

  // New env vars not seen before.
  const beforeVars = new Set(baseline.capabilities.env.vars || []);
  const newVars = (current.capabilities.env.vars || []).filter((v) => !beforeVars.has(v));
  if (newVars.length > 0) {
    escalated = true;
    changes.push({
      type: 'new-env-vars',
      category: 'env',
      label: 'environment variables',
      detail: `new env var(s) referenced: ${newVars.join(', ')}`,
    });
  }

  const newFlags = (current.riskFlags || []).filter((f) => !(baseline.riskFlags || []).includes(f));
  if (newFlags.length > 0) {
    // A new risk flag can appear without any single tracked category
    // flipping from absent to present, e.g. a newly-added obfuscation
    // signal (packed/obfuscated payload) doesn't set any CATEGORIES
    // pattern, only the separate obfuscationSignal flag. Previously this
    // was surfaced as a "new flag" in the report but did NOT fail the CI
    // gate (escalated stayed false), which is a bypass for exactly the
    // "smuggle it past the regex" scenario the tool exists to catch.
    escalated = true;
  }

  return {
    name: current.name,
    baselineVersion: baseline.version,
    currentVersion: current.version,
    escalated,
    changes,
    newRiskFlags: newFlags,
    riskScoreDelta: (current.riskScore || 0) - (baseline.riskScore || 0),
  };
}

module.exports = { diffManifests, unionOfManifests };
