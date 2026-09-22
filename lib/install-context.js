'use strict';

const path = require('path').posix;
const nativePath = require('path');
const fs = require('fs');
const { createAstAnalyzer } = require('./ast-imports');
const { builtinModules } = require('module');
const BUILTINS = new Set(builtinModules.map((name) => name.replace(/^node:/, '')));
const MAX_FILES = 10000;
const MAX_EDGES = 100000;
const MAX_SAMPLES = 20;
const MAX_DEPTH = 32;

function importReferences(code, mask) {
  const references = [];
  const keywords = /(?<![.$\w])(?:require|import|export)\b/g;
  const literal = /^(['"])([^'"\n\\]{0,4096})\1/;
  let cursor = 0;
  let line = 1;
  function lineAt(index) {
    for (; cursor < index; cursor++) if (code[cursor] === '\n') line++;
    return line;
  }
  function afterSpace(index) {
    while (index < code.length && /\s/.test(code[index])) index++;
    return index;
  }
  let match;
  while ((match = keywords.exec(mask))) {
    let previous = match.index - 1;
    while (previous >= 0 && /\s/.test(mask[previous])) previous--;
    if (mask[previous] === '.') continue;
    const keyword = match[0];
    let offset = afterSpace(keywords.lastIndex);
    let specifier;
    if (keyword !== 'export' && code[offset] === '(') {
      offset = afterSpace(offset + 1);
      const value = literal.exec(code.slice(offset));
      if (value && code[afterSpace(offset + value[0].length)] === ')') specifier = value[2];
      else references.push({ line: lineAt(match.index), reason: 'nonliteral-import' });
    } else if (keyword !== 'require') {
      const direct = literal.exec(code.slice(offset));
      if (direct) specifier = direct[2];
      else {
        // Bound the import clause and never backtrack over arbitrarily long
        // blanked comments. Complex/multiline declarations remain unsupported.
        const clause = code.slice(offset, offset + 500).split(/[;\n]/, 1)[0];
        const from = /\bfrom\s+(['"])([^'"\n\\]{0,4096})\1/.exec(clause);
        if (from && mask.slice(offset + from.index, offset + from.index + 4) === 'from') specifier = from[2];
      }
    }
    if (specifier !== undefined) references.push({ specifier, kind: keyword === 'require' ? 'require' : 'import', line: lineAt(match.index) });
    if (references.length > MAX_EDGES) break;
  }
  return references;
}

function entryFile(command) {
  // Shell operators, expansions, environment prefixes and Node flags need
  // their own interpreter. Accept only a direct node invocation here.
  const match = /^\s*node\s+(?:"([^"\r\n$`]+)"|'([^'\r\n]+)'|([^\s'";&|<>$`\\]+))\s*$/.exec(command);
  if (!match) return null;
  const file = match[1] || match[2] || match[3];
  if (file.startsWith('-') || file.includes('\\') || file.includes('\0')) return null;
  return file;
}

function installContext(root, scripts, parser = null, packageType = 'commonjs') {
  const ast = parser ? { parser: `acorn@${parser.version}`, ecmaVersion: 2022, filesParsed: 0, filesFailed: 0 } : null;
  const analyze = parser ? createAstAnalyzer(root, parser, packageType) : null;
  const nodes = new Map();
  let edges = 0;
  let truncated = false;
  function resolve(from, specifier, entry = false, kind = 'require') {
    if (!entry && !/^\.{1,2}(?:\/|$)/.test(specifier)) {
      return { reason: BUILTINS.has(specifier.replace(/^node:/, '')) ? 'builtin' : 'external-module' };
    }
    if (path.isAbsolute(specifier) || /^[A-Za-z]:/.test(specifier)) return { reason: 'outside-package' };
    const file = path.normalize(path.join(entry ? '' : path.dirname(from), specifier));
    if (file === '..' || file.startsWith('../')) return { reason: 'outside-package' };
    // Respect file precedence; an unscanned JSON/native file must not be
    // skipped in favor of a different source file. Never traverse symlinks.
    const candidates = kind === 'import' ? [file] : [file, `${file}.js`, `${file}.json`, `${file}.node`];
    for (const candidate of candidates) {
      let full = root;
      try {
        const parts = candidate.split('/');
        for (let i = 0; i < parts.length; i++) {
          full = nativePath.join(full, parts[i]);
          const stat = fs.lstatSync(full);
          if (stat.isSymbolicLink()) return { reason: 'symlink-reference' };
          if (i === parts.length - 1) {
            if (stat.isDirectory()) return { reason: 'directory-resolution-unsupported' };
            return nodes.has(candidate) && stat.isFile() ? { file: candidate } : { reason: 'unscanned-file' };
          }
        }
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') return { reason: 'unreadable-reference' };
      }
    }
    return { reason: 'unresolved-local-import' };
  }
  function trace(script, command) {
    const rawEntry = entryFile(command);
    if (!rawEntry) return { script, command, status: 'unresolved', reason: 'unsupported-command' };
    const entry = resolve('', rawEntry, true);
    if (!entry.file) return { script, command, status: 'unresolved', reason: entry.reason };
    const queue = [{ file: entry.file, chain: [entry.file] }];
    const seen = new Set([entry.file]);
    const samples = [];
    const unresolved = [];
    let unresolvedCount = 0;
    let indicatorFiles = 0;
    function missing(file, reference, reason) {
      unresolvedCount++;
      if (unresolved.length < MAX_SAMPLES) unresolved.push({ file, ...reference, reason });
    }
    for (let i = 0; i < queue.length; i++) {
      const { file, chain } = queue[i];
      const node = nodes.get(file);
      if (node.indicators.network || node.indicators.credential) {
        indicatorFiles++;
        if (samples.length < MAX_SAMPLES) samples.push({ file, chain, ...node.indicators });
      }
      for (const reference of node.references) {
        const target = reference.reason ? reference : resolve(file, reference.specifier, false, reference.kind);
        if (target.reason === 'builtin') continue;
        if (!target.file) { missing(file, reference, target.reason); continue; }
        if (seen.has(target.file)) continue;
        if (chain.length >= MAX_DEPTH) { missing(file, reference, 'depth-limit'); continue; }
        seen.add(target.file);
        queue.push({ file: target.file, chain: [...chain, target.file] });
      }
    }
    return { script, command, status: 'resolved', entry: entry.file, reachableFiles: seen.size,
      indicatorFiles, omittedFiles: indicatorFiles - samples.length, paths: samples,
      unresolvedCount, unresolved, omittedReferences: unresolvedCount - unresolved.length };
  }
  return {
    add(file, code, mask, indicators, original = code, analyzed = null) {
      if (nodes.size >= MAX_FILES || edges >= MAX_EDGES) { truncated = true; return; }
      let references;
      if (parser) {
        const result = analyzed || analyze(file, original);
        ast[result.parsed ? 'filesParsed' : 'filesFailed']++;
        references = result.references;
      } else references = importReferences(code, mask);
      if (edges + references.length > MAX_EDGES) { truncated = true; return; }
      edges += references.length;
      nodes.set(file.replace(/\\/g, '/'), { references, indicators });
    },
    finish(sourceCoverageComplete) {
      return { schemaVersion: parser ? 2 : 1, analysis: parser ? 'ast-import-graph' : 'literal-import-graph', ...(ast ? { ast } : {}), sourceCoverageComplete, truncated,
        hooks: Object.entries(scripts).map(([script, command]) => trace(script, command)) };
    },
  };
}

function installLines(context) {
  if (!context) return [];
  if (!context.hooks.length) return [];
  const deep = context.analysis === 'ast-import-graph';
  const lines = [deep ? 'Potential paths from installation scripts (experimental AST analysis):' : 'Potential paths from installation scripts (literal imports only):'];
  if (deep) lines.push(`${context.ast.parser}: ${context.ast.filesParsed} file(s) parsed, ${context.ast.filesFailed} file(s) unavailable. Parsing success does not imply complete import resolution.`);
  if (!context.sourceCoverageComplete || context.truncated) lines.push('Graph coverage is limited by source errors or resource budgets.');
  for (const hook of context.hooks) {
    if (hook.status !== 'resolved') { lines.push(`${hook.script}: entry unavailable (${hook.reason}).`); continue; }
    lines.push(`${hook.script}: ${hook.entry}; ${hook.reachableFiles} file(s) reached, ${hook.unresolvedCount} unresolved reference(s).`);
    if (deep) {
      for (const ref of hook.unresolved.slice(0, 5)) lines.push(`${ref.file}:${ref.line}: unresolved import (${ref.reason}).`);
      if (hook.unresolvedCount > 5) lines.push(`${hook.unresolvedCount - 5} additional unresolved reference(s) not shown here.`);
    }
    for (const item of hook.paths.slice(0, 5)) {
      lines.push(`Import path: ${item.chain.join(' -> ')}`);
      for (const key of ['network', 'credential']) if (item[key]) lines.push(`${item.file}:${item[key].line}: ${key}: ${item[key].snippet}`);
    }
    if (hook.indicatorFiles > 5) lines.push(`${hook.indicatorFiles - 5} additional indicator file(s) not shown here.`);
  }
  lines.push('Syntactic reachability is not proof of execution or data transfer. ' + (deep
    ? 'Only supported immutable aliases and static strings are resolved; conditions, calls and runtime resolution are not evaluated.'
    : 'Aliases, conditions and runtime resolution are not evaluated.'));
  return lines;
}

module.exports = { installContext, installLines };
