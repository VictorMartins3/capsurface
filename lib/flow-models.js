'use strict';

// Models return source expressions, never evaluated values. Unknown shapes stay
// unknown; callers may use them only as leads for an unresolved-path report.
function flowModels({ nodes, scopes, binding, value, unwrap }) {
  const changed = new Set();
  const unsafe = new Set();
  const globals = new Set(['JSON', 'Buffer', 'URLSearchParams']);
  const owner = (scope) => { while (scope && !scope.function) scope = scope.parent; return scope; };
  const name = (node, scope) => node.computed ? (value(node.property || node.key, scope) || {}).text
    : (node.property || node.key).name || (node.property || node.key).value;
  function global(input, scope, depth = 0) {
    const node = unwrap(input);
    if (!node || depth > 16) return null;
    if (node.type === 'MemberExpression') return global(node.object, scope, depth + 1);
    if (node.type !== 'Identifier') return null;
    const found = binding(scope, node.name);
    if (!found) return globals.has(node.name) ? node.name : null;
    if (found.invalid || !found.init || found.end > node.start || found.property) return null;
    return global(found.init, found.scope, depth + 1);
  }
  function object(input, scope, depth = 0) {
    const node = unwrap(input);
    if (!node || depth > 16) return null;
    if (node.type === 'ObjectExpression' || node.type === 'ArrayExpression') return { node, scope };
    if (node.type !== 'Identifier') return null;
    const found = binding(scope, node.name);
    if (!found || found.invalid || !found.init || found.property || found.end > node.start || owner(found.scope) !== owner(scope)) return null;
    return object(found.init, found.scope, depth + 1);
  }
  function base(input) {
    let node = unwrap(input);
    while (node && node.type === 'MemberExpression') node = unwrap(node.object);
    return node;
  }
  for (const node of nodes) {
    const scope = scopes.get(node);
    if (node.type === 'VariableDeclaration' && node.kind !== 'const') {
      for (const declaration of node.declarations) {
        const local = object(declaration.init, scope); if (local) unsafe.add(local.node);
      }
    }
    const target = unwrap(node.type === 'AssignmentExpression' ? node.left
      : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : null);
    if (target) {
      const root = base(target);
      const builtin = global(root, scope); if (builtin) changed.add(builtin);
      const local = object(root, scope); if (local) unsafe.add(local.node);
    }
    if (/^(CallExpression|NewExpression)$/.test(node.type)) {
      const callee = unwrap(node.callee);
      const builtin = global(callee, scope);
      const known = builtin === 'JSON' && callee.type === 'MemberExpression' && name(callee, scope) === 'stringify'
        || builtin === 'Buffer' && callee.type === 'MemberExpression' && name(callee, scope) === 'from'
        || builtin === 'URLSearchParams' && node.type === 'NewExpression';
      const fetch = (value(callee, scope) || {}).rule === 'global.fetch';
      for (const arg of node.arguments) {
        const exposed = global(arg, scope); if (exposed) changed.add(exposed);
        const local = object(arg, scope); if (local && !known && !fetch) unsafe.add(local.node);
      }
      if (callee.type === 'MemberExpression') {
        const local = object(base(callee), scope); if (local) unsafe.add(local.node);
      }
    }
    // Returning an object or storing it in another object exposes its identity.
    if (node.type === 'ReturnStatement' || node.type === 'Property' || node.type === 'AssignmentExpression') {
      const input = node.argument || node.value || node.right;
      const local = object(input, scope);
      if (local && unwrap(input).type === 'Identifier') unsafe.add(local.node);
    }
  }
  function fields(input, scope) {
    const local = object(input, scope);
    if (!local || local.node.type !== 'ObjectExpression' || unsafe.has(local.node)) return null;
    const result = new Map();
    for (const prop of local.node.properties) {
      if (prop.type !== 'Property' || prop.kind !== 'init' || prop.method) return null;
      const key = name(prop, local.scope);
      if (typeof key !== 'string' || key === '__proto__') return null;
      result.set(key, { node: prop.value, scope: local.scope });
    }
    return result;
  }
  function serialized(input, scope, depth = 0) {
    if (depth > 16) return null;
    const local = object(input, scope);
    if (!local) return [{ node: input, scope }];
    if (unsafe.has(local.node)) return null;
    const props = local.node.type === 'ObjectExpression' ? fields(input, scope) : null;
    if (local.node.type === 'ObjectExpression' && (!props || props.has('toJSON'))) return null;
    const parts = props ? [...props.values()] : local.node.elements.filter(Boolean).map((node) => ({ node, scope: local.scope }));
    const result = [];
    for (const part of parts) {
      if (part.node.type === 'SpreadElement') return null;
      const nested = serialized(part.node, part.scope, depth + 1);
      if (!nested) return null;
      result.push(...nested);
    }
    return result;
  }
  function isGlobal(input, scope, expected) {
    // A member of JSON is not the JSON namespace itself.
    const node = unwrap(input);
    if (!node || node.type !== 'Identifier' || changed.has(expected)) return false;
    const found = binding(scope, node.name);
    if (!found) return node.name === expected;
    return !found.invalid && !found.property && found.end <= node.start && found.init && unwrap(found.init).type === 'Identifier'
      && global(node, scope) === expected;
  }
  function transform(input, scope) {
    const node = unwrap(input);
    if (!node || node.optional || !/^(CallExpression|NewExpression)$/.test(node.type) || node.arguments.some((a) => a.type === 'SpreadElement')) return null;
    const callee = unwrap(node.callee);
    if (node.type === 'NewExpression' && isGlobal(callee, scope, 'URLSearchParams') && node.arguments.length === 1) {
      const props = fields(node.arguments[0], scope);
      if (!props || props.has('toString') || [...props.values()].some((part) => object(part.node, part.scope))) return null;
      return [...props.values()];
    }
    if (callee.type !== 'MemberExpression' || callee.optional) return null;
    const method = name(callee, scope);
    if (isGlobal(callee.object, scope, 'JSON') && method === 'stringify' && node.arguments.length === 1) {
      return serialized(node.arguments[0], scope);
    }
    if (isGlobal(callee.object, scope, 'Buffer') && method === 'from' && node.arguments.length === 1) {
      return [{ node: node.arguments[0], scope }];
    }
    if (method === 'toString' && node.arguments.length <= 1 &&
        (!node.arguments.length || ['base64', 'base64url', 'hex', 'utf8', 'utf-8', 'ascii', 'latin1', 'binary'].includes((value(node.arguments[0], scope) || {}).text))) {
      const inner = unwrap(callee.object);
      if (inner.type === 'CallExpression' && inner.callee.type === 'MemberExpression' &&
          name(inner.callee, scope) === 'from' && isGlobal(inner.callee.object, scope, 'Buffer')) return transform(inner, scope);
    }
    return null;
  }
  return { fields, transform };
}

module.exports = { flowModels };
