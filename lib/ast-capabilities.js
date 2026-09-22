'use strict';

// Exact specifiers only: a string containing a module name is not an import
// of that module, and node: is valid only for built-ins.
const BUILTINS = new Map([
  ['fs', 'filesystem'], ['fs/promises', 'filesystem'],
  ...['http', 'https', 'http2', 'net', 'dgram', 'tls', 'dns'].map((name) => [name, 'network']),
  ['child_process', 'exec'], ['vm', 'dynamicEval'],
]);
const PACKAGES = new Map([
  ...['axios', 'node-fetch', 'undici', 'got', 'superagent', 'request'].map((name) => [name, 'network']),
  ...['ffi-napi', 'bindings', 'node-gyp-build', 'node-gyp-build-optional-packages'].map((name) => [name, 'nativeFfi']),
]);

function recordAstCapabilities(file, content, references, caps, context, operations = []) {
  // Walk line boundaries once; references arrive in source order. Evidence
  // always shows the original source rather than a synthesized require call.
  let line = 1;
  let start = 0;
  for (const reference of [...references, ...operations].sort((a, b) => a.line - b.line)) {
    const specifier = reference.specifier;
    let category = reference.category;
    if (typeof specifier === 'string') {
      category = BUILTINS.get(specifier.replace(/^node:/, '')) || PACKAGES.get(specifier);
      if (!category && !specifier.startsWith('node:') && specifier.endsWith('.node')) category = 'nativeFfi';
    } else if (reference.reason === 'nonliteral-import' || reference.reason === 'create-require-base-unsupported') {
      category = 'unresolvedRequire';
    }
    if (!category) continue;
    while (line < reference.line) {
      const next = content.indexOf('\n', start);
      if (next === -1) break;
      start = next + 1;
      line++;
    }
    const end = content.indexOf('\n', start);
    const snippet = content.slice(start, end === -1 ? undefined : end).slice(0, 240);
    const cap = caps[category];
    cap.present = true;
    if (cap.evidence.length < 5 && !cap.evidence.some((item) => item.file === file && item.line === reference.line)) {
      cap.evidence.push({ file, line: reference.line, snippet, pattern: reference.method ? `node:child_process.${reference.method}` : 'ast-module-acquisition',
        ...(specifier === undefined ? {} : { specifier }) });
    }
    context.record(category, reference.line, snippet);
  }
}

module.exports = { recordAstCapabilities };
