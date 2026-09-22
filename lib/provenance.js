'use strict';

const fs = require('fs');
const path = require('path');

function safePath(value) {
  return typeof value === 'string' && !value.includes('\\') && !/[\x00-\x1f]/.test(value) &&
    !path.posix.isAbsolute(value) && !/^[A-Za-z]:/.test(value) &&
    (value === '' || value.split('/').every((part) => part && part !== '.' && part !== '..'));
}

// JSON.parse validates the document first. This token walk indexes object keys
// without relying on indentation, property order or unique dependency names.
function packageLines(text) {
  const lines = new Map();
  const stack = [];
  const tokens = /"(?:\\.|[^"\\])*"|[{}\[\]:,]/g;
  let line = 1;
  let previous = 0;
  let token;
  while ((token = tokens.exec(text))) {
    for (let i = previous; i < token.index; i++) if (text[i] === '\n') line++;
    previous = token.index;
    const value = token[0];
    const frame = stack[stack.length - 1];
    if (value === '{' || value === '[') {
      stack.push({ object: value === '{', key: null, expectKey: value === '{',
        path: frame ? (frame.path.length < 3 ? [...frame.path, frame.key] : [null, null, null]) : [] });
    } else if (value === '}' || value === ']') {
      stack.pop();
    } else if (value === ',' && frame) {
      frame.expectKey = frame.object;
      frame.key = null;
    } else if (value[0] === '"' && frame && frame.expectKey) {
      frame.key = JSON.parse(value);
      frame.expectKey = false;
      if (frame.path.length === 1 && frame.path[0] === 'packages') lines.set(frame.key, line);
      if (frame.path.length === 2 && frame.path[0] === 'packages' && frame.key === 'version') lines.set(frame.path[1], line);
    }
  }
  return lines;
}

function loadProvenance(file, projectRoot = process.cwd()) {
  // Git and Node can spell the same Windows temp directory using long and
  // 8.3 paths. Compare physical paths, also rejecting links outside the root.
  const absolute = fs.realpathSync.native(path.resolve(file));
  const root = fs.realpathSync.native(path.resolve(projectRoot));
  const relative = path.relative(root, absolute).split(path.sep).join('/');
  if (!safePath(relative)) throw new Error('lockfile must be inside --project-root');
  if (fs.statSync(absolute).size > 32 * 1024 * 1024) throw new Error('lockfile exceeds the 32 MiB provenance limit');
  const text = fs.readFileSync(absolute, 'utf8');
  const lock = JSON.parse(text);
  if (![2, 3].includes(lock.lockfileVersion) || !lock.packages || typeof lock.packages !== 'object' || Array.isArray(lock.packages)) {
    throw new Error('dependency provenance requires an npm package-lock.json v2 or v3');
  }
  const packages = new Map(Object.entries(lock.packages));
  if (!packages.has('')) throw new Error('lockfile is missing the root package entry');
  if (packages.size > 100000) throw new Error('lockfile exceeds the 100,000-package provenance limit');
  for (const [key, value] of packages) {
    if (!safePath(key) || !value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`invalid lockfile package entry: ${key}`);
  }
  function dereference(key) {
    const seen = new Set();
    while (packages.has(key) && packages.get(key).link) {
      if (seen.has(key)) return null;
      seen.add(key);
      key = packages.get(key).resolved;
      if (!safePath(key)) return null;
    }
    return packages.has(key) ? key : null;
  }
  function resolve(from, name) {
    if (!/^(?:@[^/]+\/)?[^/]+$/.test(name) || !safePath(name)) return null;
    let dir = from;
    while (true) {
      if (path.posix.basename(dir) !== 'node_modules') {
        const candidate = dir ? `${dir}/node_modules/${name}` : `node_modules/${name}`;
        if (packages.has(candidate)) return dereference(candidate);
      }
      if (!dir) return null;
      dir = path.posix.dirname(dir);
      if (dir === '.') dir = '';
    }
  }
  const parents = new Map();
  const predecessor = new Map([['', null]]);
  const queue = [''];
  let edgeCount = 0;
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const from = queue[cursor];
    const pkg = packages.get(from);
    const groups = [ ['dependencies', 'dependency'], ['optionalDependencies', 'optional'], ['peerDependencies', 'peer'] ];
    // Development dependencies of registry packages are not installed for consumers.
    if (!from || !from.split('/').includes('node_modules')) groups.push(['devDependencies', 'dev']);
    const edges = new Map();
    for (const [field, kind] of groups) {
      if (pkg[field] && (typeof pkg[field] !== 'object' || Array.isArray(pkg[field]))) throw new Error(`invalid ${field} in lockfile: ${from}`);
      for (const name of Object.keys(pkg[field] || {}).sort()) {
        if (++edgeCount > 1000000) throw new Error('lockfile exceeds the 1,000,000-edge provenance limit');
        const target = resolve(from, name);
        if (target !== null && !edges.has(target)) edges.set(target, { from, to: target, name, kind });
      }
    }
    // npm workspaces are linked into the root even when not listed in dependencies.
    if (!from) for (const [key, value] of packages) {
      if (!value.link || !/^node_modules\/(?:@[^/]+\/)?[^/]+$/.test(key)) continue;
      const target = dereference(key);
      if (target !== null && !edges.has(target)) edges.set(target, { from, to: target, name: key.slice(13), kind: 'workspace' });
    }
    for (const [target, edge] of edges) {
      if (!parents.has(target)) parents.set(target, []);
      parents.get(target).push(edge);
      if (!predecessor.has(target)) {
        predecessor.set(target, edge);
        queue.push(target);
      }
    }
  }
  const lines = packageLines(text);
  function describe(key) {
    const pkg = packages.get(key);
    return { name: pkg.name || (key ? key.split('node_modules/').pop() : lock.name) || '(project)',
      version: pkg.version || null, path: key };
  }
  return (manifest) => {
    const unknown = (reason) => ({ status: 'unavailable', reason, lockfile: relative });
    if (typeof manifest.installPath !== 'string') return unknown('manifest has no installation path; use scan-tree');
    const input = manifest.installPath.replace(/\\/g, '/');
    const key = path.posix.normalize(`node_modules/${input}`);
    if (!safePath(key)) return unknown('installation is outside the lockfile project');
    const target = dereference(key);
    if (target === null) return unknown('installation is not represented in this lockfile');
    const pkg = packages.get(target);
    if (pkg.version !== manifest.version || (pkg.name || target.split('node_modules/').pop()) !== manifest.name) return unknown('installed package does not match the lockfile name/version');
    if (!predecessor.has(target)) return unknown('no dependency path from the project root was resolved');
    const chain = [];
    let current = target;
    while (current) {
      if (chain.length >= 256) return unknown('dependency chain exceeds the 256-hop reporting limit');
      const edge = predecessor.get(current);
      chain.push({ ...describe(current), via: edge.name, kind: edge.kind });
      current = edge.from;
    }
    chain.push(describe(''));
    chain.reverse();
    const incoming = parents.get(target) || [];
    return { status: 'resolved', lockfile: relative, packagePath: target,
      location: { file: relative, line: lines.get(target) || 1 },
      chain, parents: incoming.slice(0, 50).map((edge) => ({ ...describe(edge.from), via: edge.name, kind: edge.kind })),
      omittedParents: Math.max(0, incoming.length - 50) };
  };
}

module.exports = { loadProvenance, packageLines };
