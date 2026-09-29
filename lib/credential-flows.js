'use strict';

const { CREDENTIAL_ENV_PATTERN } = require('./categories');

// Bounded local value tracing. Reuse the import analyzer's lexical bindings
// and invalidation rules; never evaluate inspected expressions or functions.
function credentialFlows({ nodes, scopes, binding, value, unwrap, code }) {
  const matches = [];
  let visits = 0;
  let truncated = false;
  const step = (node, kind, name) => ({ kind, ...(name ? { name } : {}),
    line: node.loc.start.line, snippet: code.slice(node.start, Math.min(node.end, node.start + 240)) });
  const owner = (scope) => { while (scope && !scope.function) scope = scope.parent; return scope; };
  const key = (node, scope) => node.computed ? (value(node.property || node.key, scope) || {}).text
    : (node.property || node.key).name || (node.property || node.key).value;

  function trace(input, scope, functionScope, depth = 0, at = input && input.start) {
    if (!input) return [];
    if (++visits > 10000 || depth > 32) { truncated = true; return []; }
    const node = unwrap(input);
    if (node.type === 'MemberExpression' && !node.optional &&
        (value(node.object, scope) || {}).kind === 'environment') {
      const name = key(node, scope);
      return typeof name === 'string' && CREDENTIAL_ENV_PATTERN.test(name)
        ? [{ source: name, path: [step(node, 'source', name)] }] : [];
    }
    if (node.type === 'Identifier') {
      const found = binding(scope, node.name);
      if (!found || found.invalid || !found.init || found.property || found.end > at ||
          owner(found.scope) !== functionScope) return [];
      return trace(found.init, found.scope, functionScope, depth + 1, found.init.start)
        .map((flow) => ({ ...flow, path: [...flow.path, step(node, 'binding', node.name)] }));
    }
    const parts = node.type === 'TemplateLiteral' ? node.expressions
      : node.type === 'BinaryExpression' && node.operator === '+' ? [node.left, node.right] : [];
    return parts.flatMap((part) => trace(part, scope, functionScope, depth + 1, at));
  }

  // Environment writes may replace a credential with another value. Do not
  // attribute those files using the unmodified-environment assumption.
  for (const node of nodes) {
    const target = unwrap(node.type === 'AssignmentExpression' ? node.left
      : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : null);
    if (target && target.type === 'MemberExpression' &&
        (value(target.object, scopes.get(node)) || {}).kind === 'environment') {
      return { matches: [], truncated: false, skippedReason: 'environment-mutation' };
    }
  }

  function fields(input, scope) {
    const node = unwrap(input);
    if (!node || node.type !== 'ObjectExpression') return null;
    const result = new Map();
    for (const prop of node.properties) {
      if (prop.type !== 'Property' || prop.kind !== 'init' || prop.method) return null;
      const name = key(prop, scope);
      if (typeof name !== 'string') return null;
      result.set(name, prop.value); // Last property wins, as in an object literal.
    }
    return result;
  }

  for (const node of nodes) {
    if (truncated) break;
    if (node.type !== 'CallExpression' || node.optional) continue;
    const scope = scopes.get(node);
    if ((value(node.callee, scope) || {}).rule !== 'global.fetch') continue;
    if (node.arguments.some((arg) => arg.type === 'SpreadElement')) continue;
    const inputs = [['url', node.arguments[0]]];
    const options = fields(node.arguments[1], scope);
    if (options) {
      inputs.push(['body', options.get('body')]);
      const headers = fields(options.get('headers'), scope);
      if (headers) for (const [name, input] of headers) inputs.push([`headers.${name.toLowerCase()}`, input]);
    }
    for (const [argument, input] of inputs) {
      const flows = trace(input, scope, owner(scope));
      const seen = new Set();
      for (const flow of flows) {
        // One finding per source name, call and argument, even if repeated.
        if (seen.has(flow.source)) continue;
        seen.add(flow.source);
        if (matches.length >= 100) { truncated = true; break; }
        matches.push({ source: flow.source, sink: { rule: 'global.fetch', argument, line: node.loc.start.line },
          path: [...flow.path, step(node, 'sink', `fetch.${argument}`)] });
      }
    }
  }
  return { matches, truncated };
}

// Ignore formatting and local alias names, but retain occurrence counts.
function flowSignature(flow) {
  return JSON.stringify([flow.file.replace(/\\/g, '/'), flow.source, flow.sink.rule, flow.sink.argument]);
}
function flowLines(context) {
  if (!context) return [];
  const lines = [`Credential flows: ${context.matches.length} recorded local source-to-fetch path(s).`];
  if (context.truncated || context.filesUnavailable) lines.push('Some flow evidence is unavailable or exceeds analysis limits.');
  for (const error of context.errors || []) lines.push(`${error.file}: flow analysis unavailable (${error.reason}).`);
  for (const flow of context.matches.slice(0, 10)) {
    lines.push(`${flow.file}: ${flow.source} -> ${flow.sink.rule} (${flow.sink.argument})`);
    for (const step of flow.path) lines.push(`${flow.file}:${step.line}: ${step.kind}: ${step.snippet}`);
  }
  if (context.matches.length > 10) lines.push('Additional paths are retained in JSON.');
  lines.push('Bounded static value paths do not prove execution or transmission. Unknown calls, mutable values, object aliases and cross-function flows are not traced.');
  return lines;
}
module.exports = { credentialFlows, flowSignature, flowLines };
