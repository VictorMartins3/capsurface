'use strict';

// File-local, literal API selection. This is deliberately narrower than a
// scope resolver: a namespace used as a value or rebound is not attributed.
const OPERATIONS = {
  filesystemRead: ['readFile', 'readFileSync', 'read', 'readSync', 'readv', 'readvSync',
    'createReadStream', 'readdir', 'readdirSync', 'opendir', 'opendirSync', 'readlink', 'readlinkSync'],
  filesystemWrite: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'write', 'writeSync',
    'writev', 'writevSync', 'createWriteStream', 'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync',
    'copyFile', 'copyFileSync', 'cp', 'cpSync', 'rename', 'renameSync', 'truncate', 'truncateSync',
    'ftruncate', 'ftruncateSync', 'link', 'linkSync', 'symlink', 'symlinkSync'],
  filesystemRemove: ['rm', 'rmSync', 'rmdir', 'rmdirSync', 'unlink', 'unlinkSync'],
};
const CATEGORY = new Map(Object.entries(OPERATIONS).flatMap(([key, methods]) => methods.map((method) => [method, key])));
const MODULE = String.raw`(['"\x60])(?:node:)?fs(?:/promises)?\1`;
const LOAD = new RegExp(String.raw`(?<![.$\w])require\s*(?:\?\.\s*)?\(\s*${MODULE}\s*\)`, 'g');
const LOAD_AT = new RegExp(LOAD.source, 'y');
const IMPORT = /\b(?:import|export)\s*\{([^{}]{0,4096})\}\s*from\s*(['"])(?:node:)?fs(?:\/promises)?\2/g;
const DESTRUCTURE = /\b(?:const|let|var)\s*\{([^{}]{0,4096})\}\s*=\s*require\s*\(\s*(['"`])(?:node:)?fs(?:\/promises)?\2\s*\)/g;
const NAMESPACE_IMPORT = /\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*(['"])(?:node:)?fs(?:\/promises)?\2/g;
const DECLARATION = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/g;
const IDENTIFIER = /[A-Za-z_$][\w$]*/g;
const MEMBER = /^\s*(?:(?:\.|\?\.)\s*([A-Za-z_$][\w$]*)|(?:\?\.\s*)?\[\s*(['"])([A-Za-z_$][\w$]*)\2\s*\])/;

function memberAt(code, offset) {
  const match = MEMBER.exec(code.slice(offset));
  if (!match) return null;
  const name = match[1] || match[3];
  return { name, index: offset + match[0].indexOf(name), end: offset + match[0].length };
}

function filesystemOperations(code, mask, emit) {
  // mask has comments, strings, regexes and erased syntax blanked, at the
  // same offsets as code. Module names and bracket keys come from code only.
  const isCode = (match, length) => mask.slice(match.index, match.index + length) === code.slice(match.index, match.index + length);
  function record(method, index) {
    const category = CATEGORY.get(method);
    if (category) emit(category, index, `node:fs.${method}`);
  }
  function isMutation(offset) {
    return /^\s*(?:=(?!=|>)|\+\+|--|[+*/%&|^-]=|\?\?=|&&=|\|\|=)/.test(mask.slice(offset));
  }
  function selection(offset) {
    let member = memberAt(code, offset);
    if (member && member.name === 'promises') member = memberAt(code, member.end);
    return member;
  }

  function namespaceValue(offset) {
    const member = memberAt(code, offset);
    if (member) {
      if (member.name !== 'promises') return false;
      offset = member.end;
    }
    const tail = code.slice(offset);
    const space = /^\s*/.exec(tail)[0];
    const next = tail.slice(space.length);
    if (/^(?:[;,}]|$)/.test(next)) return true;
    // A newline may terminate a declaration, but an operator or type cast
    // can continue its initializer. Do not attribute that resulting value.
    return space.includes('\n') && /^[A-Za-z_$]/.test(next) &&
      !/^(?:in|instanceof|as|satisfies|of)\b/.test(next);
  }

  LOAD.lastIndex = 0;
  let match;
  while ((match = LOAD.exec(code))) {
    if (!isCode(match, 7)) continue;
    const member = selection(LOAD.lastIndex);
    if (member && !isMutation(member.end)) record(member.name, member.index);
  }
  for (const pattern of [IMPORT, DESTRUCTURE]) {
    pattern.lastIndex = 0;
    while ((match = pattern.exec(code))) {
      if (!isCode(match, 6)) continue;
      if (pattern === DESTRUCTURE && !namespaceValue(pattern.lastIndex)) continue;
      let itemOffset = match.index + match[0].indexOf('{') + 1;
      for (const item of match[1].split(',')) {
        // Type-only members, defaults, rest and nested patterns are excluded.
        const selected = /^\s*([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*[A-Za-z_$][\w$]*)?\s*$/.exec(item);
        if (selected) record(selected[1], itemOffset + item.indexOf(selected[1]));
        itemOffset += item.length + 1;
      }
    }
  }

  const bindings = new Map();
  function bind(name, index) {
    if (bindings.has(name)) bindings.get(name).valid = false;
    else bindings.set(name, { index, valid: true, hits: [] });
  }
  NAMESPACE_IMPORT.lastIndex = 0;
  while ((match = NAMESPACE_IMPORT.exec(code))) {
    if (!isCode(match, 6)) continue;
    bind(match[1], match.index + match[0].indexOf(match[1], 6));
  }
  DECLARATION.lastIndex = 0;
  while ((match = DECLARATION.exec(code))) {
    if (!isCode(match, match[0].length)) continue;
    LOAD_AT.lastIndex = DECLARATION.lastIndex;
    const load = LOAD_AT.exec(code);
    if (!load || load.index !== DECLARATION.lastIndex) continue;
    if (!namespaceValue(LOAD_AT.lastIndex)) continue;
    bind(match[1], match.index + /^(?:const|let|var)\s+/.exec(match[0])[0].length);
  }
  if (!bindings.size) return;

  IDENTIFIER.lastIndex = 0;
  while ((match = IDENTIFIER.exec(mask))) {
    const binding = bindings.get(match[0]);
    if (!binding || !binding.valid || match.index === binding.index) continue;
    // obj.fs refers to a property, not the local fs binding.
    let previous = match.index - 1;
    while (previous >= 0 && /\s/.test(mask[previous])) previous--;
    if (mask[previous] === '.') continue;
    const member = selection(IDENTIFIER.lastIndex);
    if (!member || isMutation(member.end)) {
      binding.valid = false;
      binding.hits.length = 0;
      continue;
    }
    // Bound memory independently of the size of a bundle. Only evidence is
    // capped; the three presence bits continue to be collected.
    if (CATEGORY.has(member.name)) {
      const key = CATEGORY.get(member.name);
      if (binding.hits.filter((hit) => hit.category === key).length < 5) {
        binding.hits.push({ category: key, method: member.name, index: member.index });
      }
    }
  }
  for (const binding of bindings.values()) {
    if (binding.valid) for (const hit of binding.hits) record(hit.method, hit.index);
  }
}

module.exports = { filesystemOperations };
