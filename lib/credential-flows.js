'use strict';

const { CREDENTIAL_ENV_PATTERN } = require('./categories');
const { flowModels } = require('./flow-models');
const { URL } = require('url');

// Bounded local value tracing. Reuse the import analyzer's lexical bindings
// and invalidation rules; never evaluate inspected expressions or functions.
function credentialFlows({ nodes, scopes, binding, value, unwrap, code }) {
  const matches = [];
  const unresolved = [];
  const gapKeys = new Set();
  let sink;
  let visits = 0;
  let truncated = false;
  const step = (node, kind, name) => ({ kind, ...(name ? { name } : {}),
    line: node.loc.start.line, snippet: code.slice(node.start, Math.min(node.end, node.start + 240)) });
  const owner = (scope) => { while (scope && !scope.function) scope = scope.parent; return scope; };
  const key = (node, scope) => node.computed ? (value(node.property || node.key, scope) || {}).text
    : (node.property || node.key).name || (node.property || node.key).value;
  const models = flowModels({ nodes, scopes, binding, value, unwrap });
  const functions = new Map();
  const parameters = new Map();
  const active = new Set();
  for (const node of nodes) {
    if (node.type === 'FunctionDeclaration' && node.id) {
      const found = binding(scopes.get(node).parent, node.id.name);
      if (found) functions.set(found, functions.has(found) ? null : node);
    }
  }
  function localFunction(call, scope) {
    const callee = unwrap(call.callee);
    if (!callee || callee.type !== 'Identifier' || call.optional) return null;
    const found = binding(scope, callee.name);
    if (!found || found.invalid || found.ambiguous || found.end > call.start) return null;
    const fn = functions.get(found) || unwrap(found.init);
    return fn && /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(fn.type) ? fn : null;
  }
  function summarize(call, scope, use) {
    const fn = localFunction(call, scope);
    if (!fn || fn.async || fn.generator || active.has(fn) || active.size >= 4 ||
        call.arguments.length !== fn.params.length || call.arguments.some((arg) => arg.type === 'SpreadElement') ||
        fn.params.some((param) => param.type !== 'Identifier')) return null;
    const body = fn.body.type === 'BlockStatement' && fn.body.body.length === 1 ? fn.body.body[0] : fn.body;
    const expression = body.type === 'ReturnStatement' ? body.argument
      : body.type === 'ExpressionStatement' ? body.expression
      : fn.type === 'ArrowFunctionExpression' && fn.body.type !== 'BlockStatement' ? fn.body : null;
    if (!expression) return null;
    const saved = [];
    for (let i = 0; i < fn.params.length; i++) {
      const found = binding(scopes.get(fn), fn.params[i].name);
      if (!found || found.invalid) return null;
      saved.push([found, parameters.get(found), { node: call.arguments[i], scope }]);
    }
    for (const [found, , arg] of saved) parameters.set(found, arg);
    active.add(fn);
    try { return use(expression, scopes.get(expression), body.type !== 'ExpressionStatement'); }
    finally {
      active.delete(fn);
      for (const [found, old] of saved) { if (old) parameters.set(found, old); else parameters.delete(found); }
    }
  }

  // Collect possible origins only to explain a gap. These are never flows.
  function potential(input, scope, depth = 0, seen = new Set()) {
    if (!input) return [];
    if (depth > 32) { truncated = true; return []; }
    if (++visits > 10000) { truncated = true; return []; }
    const node = unwrap(input);
    if (node.type === 'MemberExpression' && (value(node.object, scope) || {}).kind === 'environment') {
      const name = key(node, scope);
      return typeof name === 'string' && CREDENTIAL_ENV_PATTERN.test(name) ? [name] : [];
    }
    if (node.type === 'Identifier') {
      const found = binding(scope, node.name);
      const argument = parameters.get(found);
      if (argument) return potential(argument.node, argument.scope, depth + 1, seen);
      if (!found || !found.init || seen.has(found)) return [];
      if (found.property && CREDENTIAL_ENV_PATTERN.test(found.property) && (value(found.init, found.scope) || {}).kind === 'environment') return [found.property];
      const next = new Set(seen); next.add(found);
      return potential(found.init, found.scope, depth + 1, next);
    }
    if (/Function/.test(node.type)) return [];
    const inputs = node.type === 'Property' ? [node.value]
      : Object.entries(node).filter(([name]) => !['key', 'property', 'id'].includes(name))
        .flatMap(([, item]) => Array.isArray(item) ? item : [item]).filter((item) => item && typeof item.type === 'string');
    return [...new Set(inputs.flatMap((part) => potential(part, scope, depth + 1, seen)))];
  }
  function gap(input, scope, reason) {
    if (!input || !sink) return [];
    for (const source of potential(input, scope)) {
      const id = JSON.stringify([source, sink.line, sink.argument, input.start, reason]);
      if (gapKeys.has(id)) continue;
      gapKeys.add(id);
      if (unresolved.length >= 100) { truncated = true; break; }
      unresolved.push({ source, sink: { ...sink }, reason, ...step(input, 'unresolved') });
    }
    return [];
  }

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
      const argument = parameters.get(found);
      if (argument) return trace(argument.node, argument.scope, owner(argument.scope), depth + 1)
        .map((flow) => ({ ...flow, path: [...flow.path, step(node, 'parameter', node.name)] }));
      if (!found || found.invalid || !found.init || found.end > at ||
          owner(found.scope) !== functionScope) return gap(node, scope, 'unresolved-binding');
      if (found.property) {
        if ((value(found.init, found.scope) || {}).kind === 'environment' && CREDENTIAL_ENV_PATTERN.test(found.property)) {
          return [{ source: found.property, path: [step(node, 'source', found.property)] }];
        }
        const selected = (models.fields(found.init, found.scope) || new Map()).get(found.property);
        return selected ? trace(selected.node, selected.scope, functionScope, depth + 1)
          .map((flow) => ({ ...flow, path: [...flow.path, step(node, 'binding', node.name)] })) : gap(node, scope, 'unresolved-property');
      }
      return trace(found.init, found.scope, functionScope, depth + 1, found.init.start)
        .map((flow) => ({ ...flow, path: [...flow.path, step(node, 'binding', node.name)] }));
    }
    if (node.type === 'MemberExpression' && !node.optional) {
      const selected = (models.fields(node.object, scope) || new Map()).get(key(node, scope));
      if (selected) return trace(selected.node, selected.scope, functionScope, depth + 1);
    }
    const transformed = models.transform(node, scope);
    if (transformed) return transformed.flatMap((part) => trace(part.node, part.scope, functionScope, depth + 1))
      .map((flow) => ({ ...flow, path: [...flow.path, step(node, 'transform')] }));
    if (node.type === 'CallExpression') {
      const returned = summarize(node, scope, (expression, local, returns) => returns
        ? trace(expression, local, owner(local), depth + 1) : null);
      if (returned) return returned.map((flow) => ({ ...flow, path: [...flow.path, step(node, 'call')] }));
    }
    const parts = node.type === 'TemplateLiteral' ? node.expressions
      : node.type === 'BinaryExpression' && node.operator === '+' ? [node.left, node.right] : [];
    if (!parts.length && node.type !== 'Literal') return gap(node, scope,
      /^(Call|New)Expression$/.test(node.type) ? 'unmodeled-call' : 'unmodeled-value');
    return parts.flatMap((part) => trace(part, scope, functionScope, depth + 1, at));
  }

  // Environment writes may replace a credential with another value. Do not
  // attribute those files using the unmodified-environment assumption.
  for (const node of nodes) {
    const target = unwrap(node.type === 'AssignmentExpression' ? node.left
      : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : null);
    if (target && target.type === 'MemberExpression' &&
        (value(target.object, scopes.get(node)) || {}).kind === 'environment') {
      return { matches: [], unresolved: [], truncated: false, skippedReason: 'environment-mutation' };
    }
  }

  function destination(node, scope, options) {
    function text(input, local, depth = 0) {
      const unwrapped = unwrap(input);
      if (depth > 8 || !unwrapped) return null;
      const argument = unwrapped.type === 'Identifier' && parameters.get(binding(local, unwrapped.name));
      return argument ? text(argument.node, argument.scope, depth + 1) : (value(unwrapped, local) || {}).text || null;
    }
    const method = options && options.get('method');
    const result = { status: 'unresolved', method: method ? text(method.node, method.scope) : options || node.arguments.length < 2 ? 'GET' : null };
    const target = text(node.arguments[0], scope);
    if (typeof target !== 'string') return result;
    try {
      const url = new URL(target);
      if (!['https:', 'http:'].includes(url.protocol)) return result;
      return { ...result, status: 'resolved', origin: url.origin, path: url.pathname + url.search };
    } catch (_) { return result; }
  }

  function visitCall(node, scope, calls = []) {
    if (truncated || node.type !== 'CallExpression' || node.optional) return;
    if ((value(node.callee, scope) || {}).rule !== 'global.fetch') {
      const expanded = summarize(node, scope, (expression, local) => {
        visitCall(unwrap(expression), local, [...calls, node]); return true;
      });
      if (!expanded) {
        const fn = localFunction(node, scope);
        if (fn && nodes.some((part) => part.type === 'CallExpression' && owner(scopes.get(part)) === scopes.get(fn)
            && (value(part.callee, scopes.get(part)) || {}).rule === 'global.fetch')) {
          sink = { rule: 'global.fetch', argument: 'function-arguments', line: node.loc.start.line };
          gap(node, scope, 'unresolved-function');
        }
      }
      return;
    }
    sink = { rule: 'global.fetch', argument: 'arguments', line: node.loc.start.line };
    if (node.arguments.some((arg) => arg.type === 'SpreadElement')) { gap(node, scope, 'unresolved-arguments'); return; }
    const inputs = [['url', { node: node.arguments[0], scope }]];
    const options = models.fields(node.arguments[1], scope);
    const target = destination(node, scope, options);
    sink.destination = target;
    if (!options) gap(node.arguments[1], scope, 'unresolved-options');
    if (options) {
      inputs.push(['body', options.get('body')]);
      const header = options.get('headers');
      const headers = header && models.fields(header.node, header.scope);
      if (header && !headers) { sink.argument = 'headers'; gap(header.node, header.scope, 'unresolved-headers'); }
      if (headers) for (const [name, input] of headers) inputs.push([`headers.${name.toLowerCase()}`, input]);
    }
    for (const [argument, part] of inputs) {
      if (!part || !part.node) continue;
      sink = { rule: 'global.fetch', argument, line: node.loc.start.line, destination: target };
      const flows = trace(part.node, part.scope, owner(part.scope));
      const seen = new Set();
      for (const flow of flows) {
        // One finding per source name, call and argument, even if repeated.
        if (seen.has(flow.source)) continue;
        seen.add(flow.source);
        if (matches.length >= 100) { truncated = true; break; }
        matches.push({ source: flow.source, sink: { rule: 'global.fetch', argument, line: node.loc.start.line, destination: target },
          path: [...flow.path, ...calls.map((call) => step(call, 'call')), step(node, 'sink', `fetch.${argument}`)] });
      }
    }
  }
  for (const node of nodes) {
    if (truncated) break;
    visitCall(node, scopes.get(node));
  }
  return { matches, unresolved, truncated };
}

function gapSignature(gap) {
  return JSON.stringify([gap.file.replace(/\\/g, '/'), gap.source, gap.sink.rule, gap.sink.argument, gap.sink.destination || null, gap.reason]);
}

// Ignore formatting and local alias names, but retain occurrence counts.
function flowSignature(flow) {
  return JSON.stringify([flow.file.replace(/\\/g, '/'), flow.source, flow.sink.rule, flow.sink.argument, flow.sink.destination || null]);
}
function flowLines(context) {
  if (!context) return [];
  const lines = [`Credential flows: ${context.matches.length} recorded local source-to-fetch path(s).`];
  for (const gap of (context.unresolved || []).slice(0, 10)) {
    lines.push(`${gap.file}:${gap.line}: unresolved ${gap.source} path to ${gap.sink.rule} (${gap.sink.argument}): ${gap.reason}: ${gap.snippet}`);
  }
  if ((context.unresolved || []).length) lines.push('Unresolved paths are review leads, not established data transfers.');
  if (context.truncated || context.filesUnavailable) lines.push('Some flow evidence is unavailable or exceeds analysis limits.');
  for (const error of context.errors || []) lines.push(`${error.file}: flow analysis unavailable (${error.reason}).`);
  for (const flow of context.matches.slice(0, 10)) {
    lines.push(`${flow.file}: ${flow.source} -> ${flow.sink.rule} (${flow.sink.argument})`);
    if (flow.sink.destination) {
      const target = flow.sink.destination;
      lines.push(`Destination: ${target.status === 'resolved' ? target.origin + target.path : 'unresolved'}; method: ${target.method || 'unresolved'}.`);
    }
    for (const step of flow.path) lines.push(`${flow.file}:${step.line}: ${step.kind}: ${step.snippet}`);
  }
  if (context.matches.length > 10) lines.push('Additional paths are retained in JSON.');
  lines.push('Bounded static value paths do not prove execution or transmission. Unknown calls, mutable values, escaped objects and cross-file flows may remain unresolved.');
  return lines;
}
module.exports = { credentialFlows, flowSignature, gapSignature, flowLines };
