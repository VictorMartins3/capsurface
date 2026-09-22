'use strict';

const MAX_MATCHES = 20;

// Presence in one file is a useful review lead, not a data-flow result.
// Collect it before package-wide evidence samples fill up.
function fileContext(file) {
  let network;
  let credential;
  return {
    needs(category) {
      return (category === 'network' && !network) || (category === 'sensitiveTargets' && !credential);
    },
    record(category, line, snippet, name) {
      if (category === 'network' && !network) network = { line, snippet };
      if (!credential && (category === 'sensitiveTargets' || category === 'credential-env')) {
        credential = { kind: category === 'sensitiveTargets' ? 'sensitive-target' : 'credential-env', line, snippet,
          ...(name ? { name } : {}) };
      }
    },
    result() { return network && credential ? { file, network, credential } : null; },
  };
}

function sourceContext() {
  const result = { schemaVersion: 1, filesAnalyzed: 0, complete: true, matchingFiles: 0, omittedFiles: 0, matches: [] };
  return {
    add(context) {
      result.filesAnalyzed++;
      const match = context.result();
      if (!match) return;
      result.matchingFiles++;
      if (result.matches.length < MAX_MATCHES) result.matches.push(match);
      else result.omittedFiles++;
    },
    finish(complete) { return { ...result, complete }; },
  };
}

function contextLines(context) {
  if (!context) return ['File correlation is unavailable in this manifest; rescan to collect it.'];
  const lines = [`Network and credential indicators occur together in ${context.matchingFiles} analyzed source file(s).`];
  if (!context.complete) lines.push('Source coverage is incomplete; additional relationships may be missing.');
  for (const match of context.matches.slice(0, 5)) {
    lines.push(`${match.file}:${match.network.line}: network indicator: ${match.network.snippet}`);
    lines.push(`${match.file}:${match.credential.line}: ${match.credential.kind}${match.credential.name ? ` (${match.credential.name})` : ''}: ${match.credential.snippet}`);
  }
  const omitted = context.matchingFiles - Math.min(context.matches.length, 5);
  if (omitted > 0) lines.push(`${omitted} additional matching file(s) not shown here; JSON retains up to ${MAX_MATCHES} samples.`);
  lines.push('File co-occurrence does not establish execution order or data transfer. Missing matches do not prove absence of those behaviors.');
  return lines;
}

module.exports = { fileContext, sourceContext, contextLines };
