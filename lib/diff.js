'use strict';

const {
  CATEGORIES,
  CREDENTIAL_ENV_PATTERN,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
} = require('./categories');

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
  capabilities.noReadableSource = {
    present: manifests.some((m) => (m.capabilities.noReadableSource || {}).present),
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

// Tolerant readers: a baseline written by an older schema may not carry
// every capability key a current manifest does.
// The host of a literal endpoint, which is what gating compares. Anything
// that does not parse as one falls back to the whole string so an unusual
// value cannot silently collapse into an existing host.
function endpointHost(url) {
  const m = /^https?:\/\/([^/:?#]+)/.exec(url);
  return m ? m[1].toLowerCase() : url;
}

function isPresent(manifest, key) {
  const cap = manifest.capabilities && manifest.capabilities[key];
  return !!(cap && cap.present);
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
      // A category can opt out of gating on its own (see `gatesOnAppear` in
      // categories.js). It is still reported either way.
      const gates = cat.gatesOnAppear !== false;
      if (gates) escalated = true;
      changes.push({
        type: 'capability-added',
        category: cat.key,
        label: cat.label,
        escalates: gates,
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
      // Only a script that actually runs on a consumer's install can fail
      // the build. A changed `prepare`/`prepublish` body does not execute
      // for a registry install at all, and upgrading 14 popular packages
      // produced eleven such changes (tshy, husky, lefthook, ts-scripts),
      // every one of them a build-tooling swap. Still reported, so the
      // change is visible, just not a gate failure.
      const installTriggering = INSTALL_TRIGGERING_SCRIPT_KEYS.includes(key);
      if (installTriggering) escalated = true;
      const beforeDesc = Array.isArray(b)
        ? b.map((v) => (v ? JSON.stringify(v) : '(none)')).join(' OR ')
        : b
        ? JSON.stringify(b)
        : '(none)';
      changes.push({
        type: 'lifecycle-script-changed',
        category: 'lifecycleScripts',
        label: `lifecycle script "${key}"`,
        escalates: installTriggering,
        detail: `script changed${installTriggering ? '' : ' (build-time only, does not run on install)'}:\n    previously approved: ${beforeDesc}\n    now:                 ${a ? JSON.stringify(a) : '(none)'}`,
      });
    }
  }

  // New network endpoints not seen before. On their own these are weak:
  // every new endpoint seen while upgrading 14 popular packages was a
  // documentation or issue-tracker link in a comment or error message
  // (day.js.org/docs, github.com/node-fetch/issues/1000, a stackoverflow
  // answer). What makes a new endpoint worth blocking is the shape around
  // it, code that runs at install time or touches credentials, which is
  // exactly the exfiltration path.
  const exfiltrationShape =
    current.capabilities.lifecycleScripts.installTriggering === true ||
    current.capabilities.sensitiveTargets.present === true;
  //
  // Every new URL is reported, but only a new *host* gates. The question a
  // reviewer is being asked is whether the package now talks to somewhere it
  // did not talk to before; another path on a host it already used is not
  // that. Diffing consecutive releases of 82 popular packages, prisma failed
  // the gate on five upgrades in a row and every one was a github.com
  // documentation link on a host it already referenced.
  const beforeEndpoints = new Set(baseline.capabilities.network.endpoints || []);
  const newEndpoints = (current.capabilities.network.endpoints || []).filter((e) => !beforeEndpoints.has(e));
  if (newEndpoints.length > 0) {
    const beforeHosts = new Set((baseline.capabilities.network.endpoints || []).map(endpointHost));
    const newHosts = [...new Set(newEndpoints.map(endpointHost))].filter((h) => !beforeHosts.has(h));
    const gates = exfiltrationShape && newHosts.length > 0;
    if (gates) escalated = true;
    changes.push({
      type: 'new-network-endpoints',
      category: 'network',
      label: 'network endpoints',
      escalates: gates,
      detail: `new literal endpoint(s) referenced: ${newEndpoints.join(', ')}` +
        (newHosts.length ? `\n    new host(s): ${newHosts.join(', ')}` : '\n    no new host; all are paths on hosts already in the baseline'),
    });
  }

  // New env vars not seen before. Gating on any new name is noise (upgrades
  // routinely add NO_COLOR, no_proxy, DOTENV_CONFIG_QUIET); gating on
  // credential-shaped names keeps the signal that matters.
  const beforeVars = new Set(baseline.capabilities.env.vars || []);
  const newVars = (current.capabilities.env.vars || []).filter((v) => !beforeVars.has(v));
  const newCredentialVars = newVars.filter((v) => CREDENTIAL_ENV_PATTERN.test(v));
  if (newVars.length > 0) {
    if (newCredentialVars.length > 0) escalated = true;
    changes.push({
      type: 'new-env-vars',
      category: 'env',
      label: 'environment variables',
      escalates: newCredentialVars.length > 0,
      detail:
        newCredentialVars.length > 0
          ? `new credential-shaped env var(s) referenced: ${newCredentialVars.join(', ')}` +
            (newVars.length > newCredentialVars.length
              ? ` (also, not gated on: ${newVars.filter((v) => !newCredentialVars.includes(v)).join(', ')})`
              : '')
          : `new env var(s) referenced, none credential-shaped: ${newVars.join(', ')}`,
    });
  }

  const newFlags = (current.riskFlags || []).filter((f) => !(baseline.riskFlags || []).includes(f));

  // A new risk flag can appear without any single tracked category flipping
  // from absent to present, so flags have to be able to gate on their own:
  // a newly packed or obfuscated payload sets no CATEGORIES pattern, only
  // the obfuscationSignal flag, and letting that through was a bypass for
  // exactly the "smuggle it past the regex" case this tool exists to catch.
  //
  // Which flags gate is derived from capability state rather than matched on
  // message text. CRITICAL and HIGH always gate. Of the MEDIUM signals only
  // the two that mean "there is code here we could not read" do, since those
  // are a loss of visibility rather than an observation about the code.
  const lostVisibility =
    (!isPresent(baseline, 'obfuscationSignal') && isPresent(current, 'obfuscationSignal')) ||
    (!isPresent(baseline, 'skippedLargeFiles') && isPresent(current, 'skippedLargeFiles')) ||
    (!isPresent(baseline, 'noReadableSource') && isPresent(current, 'noReadableSource'));
  if (newFlags.some((f) => f.startsWith('CRITICAL') || f.startsWith('HIGH')) || lostVisibility) {
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
