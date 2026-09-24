'use strict';

const fs = require('fs');
const nativePath = require('path');
const path = nativePath.posix;
const { typedParser } = require('./typed-parser');
const { networkModule, networkMethod } = require('./network-operations');
const { PROCESS_METHODS, processOperation } = require('./process-operations');
function moduleValue(specifier) {
  if (['module', 'node:module'].includes(specifier)) return { kind: 'module' };
  if (['child_process', 'node:child_process'].includes(specifier)) return { kind: 'process-module' };
  if (['process', 'node:process'].includes(specifier)) return { kind: 'process-global' };
  return networkModule(specifier) || { kind: 'unknown' };
}
const WRAPPERS = new Set(['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'TSSatisfiesExpression', 'TSInstantiationExpression']);
const TYPE_FIELDS = new Set(['typeAnnotation', 'typeParameters', 'typeArguments', 'returnType', 'superTypeParameters', 'superTypeArguments', 'implements', 'predicate']);
function unwrap(node) {
  while (node && WRAPPERS.has(node.type)) node = node.expression;
  return node;
}

const MAX_SOURCE = 1024 * 1024;
const MAX_NODES = 100000;
const MAX_VALUE_DEPTH = 32;

function loadParser() {
  let parser;
  try { parser = require('acorn'); } catch (_) {
    throw new Error('--deep requires acorn@8.15.0 installed alongside capsurface; scanning never installs dependencies');
  }
  if (parser.version !== '8.15.0') throw new Error('--deep requires acorn@8.15.0');
  const typed = typedParser(parser);
  return { ...parser, typed, identity: `acorn@${parser.version}${typed ? `+acorn-typescript@${typed.version}` : ''}` };
}

function children(node) {
  const result = [];
  for (const [key, value] of Object.entries(node)) {
    if (TYPE_FIELDS.has(key)) continue;
    if (Array.isArray(value)) {
      for (const item of value) if (item && typeof item.type === 'string') result.push(item);
    } else if (value && typeof value.type === 'string') result.push(value);
  }
  return result;
}

function names(pattern) {
  if (!pattern) return [];
  if (WRAPPERS.has(pattern.type)) return names(pattern.expression);
  if (pattern.type === 'TSParameterProperty') return names(pattern.parameter);
  if (pattern.type === 'Identifier') return [pattern.name];
  if (pattern.type === 'RestElement') return names(pattern.argument);
  if (pattern.type === 'AssignmentPattern') return names(pattern.left);
  if (pattern.type === 'ObjectPattern') return pattern.properties.flatMap((p) => names(p.value || p.argument));
  if (pattern.type === 'ArrayPattern') return pattern.elements.flatMap(names);
  return [];
}

// Resolve only immutable local values. No package code, getters or functions
// are evaluated; unsupported values stay unknown instead of being guessed.
function astImports(parser, code, file, sourceType) {
  const failure = (reason, line = 1) => ({ parsed: false, references: [{ line, reason }] });
  if (Buffer.byteLength(code) > MAX_SOURCE) return failure('ast-source-limit');
  const typed = /\.[cm]?tsx?$|\.jsx$/i.test(file);
  const declarations = /\.d\.[cm]?ts$/i.test(file);
  if (typed && !parser.typed) return failure('ast-typescript-parser-unavailable');
  if (/\.m[jt]s$/i.test(file)) sourceType = 'module';
  if (/\.c[jt]s$/i.test(file)) sourceType = 'script';
  let ast;
  let tokens = 0;
  try {
    const options = { ecmaVersion: 2022, sourceType: typed ? 'module' : sourceType, locations: true,
      allowHashBang: true, allowReturnOutsideFunction: sourceType === 'script',
      onToken() { if (++tokens > MAX_NODES) throw new RangeError('token budget'); } };
    ast = typed ? parser.typed.parse(code, options, declarations) : parser.parse(code, options);
  } catch (error) {
    return failure(error instanceof RangeError ? 'ast-resource-limit' : 'ast-parse-error', error.loc ? error.loc.line : 1);
  }

  const root = { bindings: new Map(), parent: null, function: true };
  const scopes = new Map();
  const nodes = [];
  const stack = [{ node: ast, scope: root }];
  function declare(scope, name, binding = {}) {
    // Duplicate declarations make attribution uncertain, including var/function
    // combinations. Keep their shadowing effect without choosing a value.
    scope.bindings.set(name, scope.bindings.has(name) ? {} : binding);
  }
  while (stack.length) {
    let { node, scope } = stack.pop();
    if (nodes.length >= MAX_NODES) return failure('ast-resource-limit');
    if (node.type === 'TSTypeAliasDeclaration' || node.type === 'TSInterfaceDeclaration' ||
        node.importKind === 'type' || node.exportKind === 'type') continue;
    if (node.declare || node.type === 'TSDeclareFunction' || node.type === 'TSDeclareMethod' ||
        (declarations && ['TSEnumDeclaration', 'TSModuleDeclaration', 'TSNamespaceExportDeclaration'].includes(node.type))) {
      if (node.id) for (const name of names(node.id)) declare(scope, name);
      for (const item of node.declarations || []) for (const name of names(item.id)) declare(scope, name);
      continue;
    }
    if (node.type.startsWith('TS') && !WRAPPERS.has(node.type) &&
        !['TSParameterProperty', 'TSImportEqualsDeclaration', 'TSExternalModuleReference', 'TSExportAssignment'].includes(node.type)) {
      return failure('ast-typescript-runtime-unsupported', node.loc.start.line);
    }
    nodes.push(node);
    const fn = /^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(node.type);
    if (node.type === 'FunctionDeclaration' && node.id) declare(scope, node.id.name);
    if (node.type === 'ClassDeclaration' && node.id) declare(scope, node.id.name);
    if (fn || /^(?:BlockStatement|CatchClause|ForStatement|ForInStatement|ForOfStatement|SwitchStatement|ClassExpression|ClassDeclaration|StaticBlock)$/.test(node.type)) {
      scope = { bindings: new Map(), parent: scope, function: fn || node.type === 'StaticBlock' };
      if (fn) {
        if (node.id) declare(scope, node.id.name);
        for (const param of node.params) for (const name of names(param)) declare(scope, name);
      }
      if (node.type === 'CatchClause') for (const name of names(node.param)) declare(scope, name);
      if (/^Class/.test(node.type) && node.id) declare(scope, node.id.name);
    }
    scopes.set(node, scope);
    if (node.type === 'VariableDeclaration') {
      let target = scope;
      if (node.kind === 'var') while (!target.function && target.parent) target = target.parent;
      for (const declaration of node.declarations) {
        for (const name of names(declaration.id)) declare(target, name);
        if (node.kind !== 'const' || !declaration.init) continue;
        if (declaration.id.type === 'Identifier') {
          target.bindings.set(declaration.id.name, { init: declaration.init, scope, end: declaration.end });
        } else if (declaration.id.type === 'ObjectPattern') {
          for (const prop of declaration.id.properties) {
            if (prop.type === 'Property' && !prop.computed && prop.value.type === 'Identifier') {
              target.bindings.set(prop.value.name, { init: declaration.init, scope, end: declaration.end,
                property: prop.key.name || prop.key.value });
            }
          }
        }
      }
    }
    if (node.type === 'ImportDeclaration') {
      for (const spec of node.specifiers) {
        if (spec.importKind === 'type') continue;
        const namespace = moduleValue(node.source.value);
        const imported = spec.imported && (spec.imported.name || spec.imported.value);
        declare(scope, spec.local.name, { value: imported ? property(namespace, imported) || { kind: 'unknown' } : namespace, end: 0 });
      }
    }
    if (node.type === 'TSImportEqualsDeclaration') {
      if (node.moduleReference.type !== 'TSExternalModuleReference') return failure('ast-typescript-runtime-unsupported', node.loc.start.line);
      const specifier = node.moduleReference.expression.value;
      declare(scope, node.id.name, { value: moduleValue(specifier), end: node.end });
    }
    for (const child of children(node).reverse()) stack.push({ node: child, scope });
  }
  function binding(scope, name) {
    for (; scope; scope = scope.parent) if (scope.bindings.has(name)) return scope.bindings.get(name);
    return null;
  }
  // Assignments invalidate a binding throughout its scope, including closures.
  // Direct eval and with can replace lexical meaning; do not invent edges there.
  for (const node of nodes) {
    const callee = node.type === 'CallExpression' ? unwrap(node.callee) : null;
    if (node.type === 'WithStatement' || (callee && callee.type === 'Identifier' && callee.name === 'eval')) {
      return failure('ast-dynamic-scope', node.loc.start.line);
    }
    if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression') {
      let target = unwrap(node.left || node.argument);
      if (target.type === 'MemberExpression') continue;
      for (const name of names(target)) {
        const found = binding(scopes.get(node), name);
        if (found) found.invalid = true;
        else root.bindings.set(name, { invalid: true });
      }
    }
  }
  function property(value, key) {
    if (!value) return null;
    if (value.kind === 'network-module') {
      if (value.module === 'dns' && key === 'promises') return networkModule('dns/promises');
      return networkMethod(value, key);
    }
    if (value.kind === 'process-global' && key === 'env') return { kind: 'environment' };
    if (value.kind === 'object-global' && ['keys', 'values', 'entries', 'getOwnPropertyNames', 'assign'].includes(key)) return { kind: 'environment-method', method: key };
    if (value && value.kind === 'process-module' && PROCESS_METHODS.has(key)) return { kind: 'process-method', method: key };
    return value && value.kind === 'module' && key === 'createRequire' ? { kind: 'factory' } : null;
  }
  const values = new Map();
  let evaluations = 0;
  let depthExceeded = false;
  function value(node, scope, depth = 0, at = node && node.start) {
    if (++evaluations > MAX_NODES || !node) return null;
    if (depth > MAX_VALUE_DEPTH) { depthExceeded = true; return null; }
    const next = (child) => value(child, scope, depth + 1, at);
    if (WRAPPERS.has(node.type)) return next(node.expression);
    if (node.type === 'Literal' && typeof node.value === 'string') return node.value.length <= 4096 ? { kind: 'string', text: node.value } : null;
    if (node.type === 'Identifier') {
      const found = binding(scope, node.name);
      if (!found) {
        if (sourceType === 'script' && node.name === 'require') return { kind: 'require' };
        if (node.name === 'process') return { kind: 'process-global' };
        if (node.name === 'Object') return { kind: 'object-global' };
        if (node.name === 'fetch') return { kind: 'network-method', category: 'networkRequest', rule: 'global.fetch' };
        return null;
      }
      if (found.invalid || found.end > at) return null;
      if (values.has(found)) return values.get(found);
      const resolved = found.value || value(found.init, found.scope, depth + 1, found.init && found.init.start);
      const result = found.property ? property(resolved, found.property) : resolved;
      values.set(found, result);
      return result;
    }
    if (node.type === 'MemberExpression' && !node.optional) {
      const key = node.computed ? next(node.property) : { kind: 'string', text: node.property.name };
      return key && key.kind === 'string' ? property(next(node.object), key.text) : null;
    }
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const left = next(node.left), right = next(node.right);
      if (left && right && left.kind === 'string' && right.kind === 'string' && left.text.length + right.text.length <= 4096) {
        return { kind: 'string', text: left.text + right.text };
      }
    }
    if (node.type === 'TemplateLiteral') {
      let text = node.quasis[0].value.cooked;
      if (text === null) return null;
      for (let i = 0; i < node.expressions.length; i++) {
        const part = next(node.expressions[i]);
        if (!part || part.kind !== 'string' || node.quasis[i + 1].value.cooked === null) return null;
        text += part.text + node.quasis[i + 1].value.cooked;
        if (text.length > 4096) return null;
      }
      return text.length <= 4096 ? { kind: 'string', text } : null;
    }
    if (node.type === 'CallExpression' && !node.optional && node.arguments.length === 1) {
      const callee = next(node.callee);
      if (callee && callee.kind === 'require') {
        const specifier = next(node.arguments[0]);
        if (specifier && specifier.kind === 'string') return moduleValue(specifier.text);
      }
      if (callee && callee.kind === 'factory') {
        const base = unwrap(node.arguments[0]);
        const filename = sourceType === 'script' && base.type === 'Identifier' && base.name === '__filename' && !binding(scope, '__filename');
        const meta = sourceType === 'module' && base.type === 'MemberExpression' && !base.computed && base.property.name === 'url'
          && base.object.type === 'MetaProperty' && base.object.meta.name === 'import';
        return { kind: filename || meta ? 'require' : 'unsupported-base' };
      }
    }
    return null;
  }
  // Module namespace objects can be mutated through aliases or unknown calls.
  // Abandon this file's graph rather than attribute a replaced createRequire.
  for (const node of nodes) {
    const scope = scopes.get(node);
    const target = unwrap(node.type === 'AssignmentExpression' ? node.left
      : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : null);
    if (target && target.type === 'MemberExpression') {
      const object = value(target.object, scope);
      if (object && ['module', 'process-module', 'network-module', 'process-global', 'object-global'].includes(object.kind)) return failure('ast-module-mutation', node.loc.start.line);
    }
    const exposed = /^(?:CallExpression|NewExpression)$/.test(node.type) ? node.arguments
      : node.type === 'ReturnStatement' ? [node.argument] : [];
    for (const argument of exposed) {
      const object = value(argument, scope);
      if (object && ['module', 'process-module', 'network-module'].includes(object.kind)) return failure('ast-module-escape', node.loc.start.line);
    }
  }
  const references = [];
  const operations = [];
  function enumeration(node, argument, scope, rule) {
    const resolved = value(argument, scope);
    if (resolved && resolved.kind === 'environment') operations.push({ category: 'envEnumeration', parent: 'env', rule, line: node.loc.start.line });
  }
  function reference(node, argument, kind, scope) {
    const specifier = value(argument, scope);
    references.push(specifier && specifier.kind === 'string'
      ? { specifier: specifier.text, kind, line: node.loc.start.line }
      : { line: node.loc.start.line, reason: 'nonliteral-import' });
  }
  for (const node of nodes) {
    const scope = scopes.get(node);
    if (node.type === 'ForInStatement') enumeration(node, node.right, scope, 'for-in process.env');
    if (node.type === 'ObjectExpression') for (const prop of node.properties) {
      if (prop.type === 'SpreadElement') enumeration(prop, prop.argument, scope, 'object spread process.env');
    }
    if (node.type === 'VariableDeclarator' && node.id.type === 'ObjectPattern' && node.id.properties.some((p) => p.type === 'RestElement')) {
      enumeration(node, node.init, scope, 'object rest process.env');
    }
    if (/^(?:ImportDeclaration|ExportNamedDeclaration|ExportAllDeclaration)$/.test(node.type) && node.source) {
      if (!declarations) reference(node, node.source, 'import', scope);
    } else if (node.type === 'TSImportEqualsDeclaration') {
      if (!declarations) reference(node, node.moduleReference.expression, 'require', scope);
    } else if (node.type === 'ImportExpression') reference(node, node.source, 'import', scope);
    else if (node.type === 'CallExpression') {
      const callee = value(node.callee, scope);
      if (callee && callee.kind === 'network-method') operations.push({ category: callee.category, parent: 'network', rule: callee.rule, line: node.loc.start.line });
      if (callee && callee.kind === 'environment-method') {
        const sources = callee.method === 'assign' ? node.arguments.slice(1) : node.arguments.slice(0, 1);
        for (const source of sources) enumeration(node, source, scope, `Object.${callee.method}(process.env)`);
      }
      if (callee && callee.kind === 'process-method') {
        operations.push({ category: processOperation(callee.method, node.arguments, unwrap),
          method: callee.method, line: node.loc.start.line });
      }
      if (callee && callee.kind === 'require') reference(node, node.arguments.length === 1 ? node.arguments[0] : null, 'require', scope);
      if (callee && callee.kind === 'unsupported-base') references.push({ line: node.loc.start.line, reason: 'create-require-base-unsupported' });
    }
  }
  return depthExceeded || evaluations > MAX_NODES ? failure('ast-resource-limit') : { parsed: true, references, ...(operations.length ? { operations } : {}) };
}


function createAstAnalyzer(root, parser, packageType = 'commonjs') {
  const types = new Map([['.', packageType === 'module' ? 'module' : 'script']]);
  function sourceType(file) {
    const dir = path.dirname(file);
    if (types.has(dir)) return types.get(dir);
    const manifest = nativePath.join(root, dir, 'package.json');
    let type;
    try {
      const stat = fs.lstatSync(manifest);
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('unsupported package boundary');
      type = JSON.parse(fs.readFileSync(manifest, 'utf8')).type === 'module' ? 'module' : 'script';
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      type = sourceType(dir);
    }
    types.set(dir, type);
    return type;
  }
  return (file, code) => {
    try { return require('./isolated-ast').isolatedAst(code, file, sourceType(file.replace(/\\/g, '/')), parser.identity); }
    catch (_) { return { parsed: false, references: [{ line: 1, reason: 'ast-analysis-error' }] }; }
  };
}

module.exports = { loadParser, astImports, createAstAnalyzer };
