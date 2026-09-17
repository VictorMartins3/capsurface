'use strict';

// Fold the string constructions a scanner can resolve without running the
// code, so the capability rules see the specifier the runtime will see.
//
// This is source-text rewriting, not parsing. It is deliberately narrow: each
// fold only fires when every input is a literal, which is the case an
// attacker gets for free and the case a parser would resolve anyway. Anything
// involving a value computed at runtime is left alone, and the README's
// limitations still hold for it.
//
// The rewritten text is only ever matched against, never executed, so a wrong
// fold costs a false positive rather than anything worse.

const MAX_PASSES = 4;

// 'child' + '_process'  ->  'child_process'
const CONCAT = /(['"])((?:[^'"\\]|\\.)*)\1\s*\+\s*(['"])((?:[^'"\\]|\\.)*)\3/g;

// `child_process`  ->  'child_process', when there is no interpolation
const TEMPLATE = /`([^`\\$]*)`/g;

// ['child', 'process'].join('_')  ->  'child_process'
const ARRAY_JOIN = /\[\s*((?:(['"])(?:[^'"\\]|\\.)*\2\s*,\s*)*(['"])(?:[^'"\\]|\\.)*\3)\s*\]\s*\.\s*join\s*\(\s*(['"])((?:[^'"\\]|\\.)*)\4\s*\)/g;

// 'ssecorp_dlihc'.split('').reverse().join('')
const REVERSE = /(['"])((?:[^'"\\]|\\.)*)\1\s*\.\s*split\s*\(\s*(['"])\3\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(['"])\4\s*\)/g;

// Buffer.from('...', 'base64'|'hex').toString()  and  atob('...')
const BUFFER_FROM = /Buffer\s*\.\s*from\s*\(\s*(['"])((?:[^'"\\]|\\.)*)\1\s*,\s*(['"])(base64|hex)\3\s*\)\s*(?:\.\s*toString\s*\(\s*\))?/g;
const ATOB = /\batob\s*\(\s*(['"])((?:[^'"\\]|\\.)*)\1\s*\)/g;

// String.fromCharCode(99, 104, ...)
const FROM_CHAR_CODE = /String\s*\.\s*fromCharCode\s*\(\s*((?:\d+\s*,\s*)*\d+)\s*\)/g;

// A string literal whose escapes hide the real characters.
const ESCAPED_LITERAL = /(['"])((?:[^'"\\]|\\.)*\\(?:x[0-9a-fA-F]{2}|u\{?[0-9a-fA-F]{1,6}\}?)(?:[^'"\\]|\\.)*)\1/g;

const SAFE_VALUE = /^[\w@/\-.:+ ]{0,200}$/;
// A line can only fold into a literal if it already contains one, or builds
// one from character codes, which is the single form with no quote in it.
const FOLDABLE = /['"`]|fromCharCode/;
const BINDING_LINE = /(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=/;
// Bindings are only ever used to substitute `require(name)`, so a file with
// no such call needs none. Collecting them anyway was 14% of scan time on a
// real 992-package tree.
const REQUIRES_IDENTIFIER = /(?<![.$\w])(?:require|import)\s*\(\s*[A-Za-z_$]/;

function quote(value) {
  return SAFE_VALUE.test(value) ? `'${value}'` : null;
}

function decodeEscapes(raw) {
  return raw.replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, (m, a, b, c) =>
    String.fromCodePoint(parseInt(a || b || c, 16))
  );
}

// Each fold is gated on a cheap substring test. Almost no line in a real
// package contains any of these, and running eight regexes over every line of
// every file cost 1.8x the scan time before the gates went in.
function foldOnce(line) {
  let out = line;

  if (out.includes('\\')) {
    out = out.replace(ESCAPED_LITERAL, (m, q, body) => quote(decodeEscapes(body)) ?? m);
  }
  if (out.includes('`')) {
    out = out.replace(TEMPLATE, (m, body) => quote(body) ?? m);
  }
  if (out.includes('+')) {
    out = out.replace(CONCAT, (m, q1, a, q2, b) => quote(a + b) ?? m);
  }
  if (out.includes('.reverse')) {
    out = out.replace(REVERSE, (m, q, body) => quote([...body].reverse().join('')) ?? m);
  }
  if (out.includes('.join')) {
    out = out.replace(ARRAY_JOIN, (m, items, _q1, _q2, _q3, sep) => {
      const parts = [...items.matchAll(/(['"])((?:[^'"\\]|\\.)*)\1/g)].map((x) => x[2]);
      return quote(parts.join(sep)) ?? m;
    });
  }
  if (out.includes('fromCharCode')) {
    out = out.replace(FROM_CHAR_CODE, (m, nums) =>
      quote(nums.split(',').map((n) => String.fromCharCode(Number(n.trim()))).join('')) ?? m
    );
  }
  if (out.includes('Buffer')) {
    out = out.replace(BUFFER_FROM, (m, q, payload, _q2, enc) => {
      try { return quote(Buffer.from(payload, enc).toString('utf8')) ?? m; } catch { return m; }
    });
  }
  if (out.includes('atob')) {
    out = out.replace(ATOB, (m, q, payload) => {
      try { return quote(Buffer.from(payload, 'base64').toString('utf8')) ?? m; } catch { return m; }
    });
  }

  return out;
}

/**
 * Collect `const x = 'literal'` bindings so a specifier reached through a
 * variable can be substituted at its use site. Single assignment only: a name
 * assigned twice is dropped rather than guessed at.
 *
 * The folds run first, so a binding written as `String.fromCharCode(...)` or
 * a concatenation is already a literal by the time this reads it.
 */
function literalBindings(source) {
  if (!REQUIRES_IDENTIFIER.test(source)) {
    return new Map();
  }
  // Only a line that declares something can produce a binding, so the folds
  // run on those and nothing else.
  const code = source.replace(/[^\n]+/g, (line) => {
    if (!BINDING_LINE.test(line) || !FOLDABLE.test(line)) {
      return line;
    }
    let out = line;
    for (let i = 0; i < MAX_PASSES; i++) {
      const next = foldOnce(out);
      if (next === out) break;
      out = next;
    }
    return out;
  });
  const seen = new Map();
  const re = /(?:^|[;{}\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"])((?:[^'"\\]|\\.)*)\2\s*[;\n]/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const [, name, , value] = m;
    if (seen.has(name)) seen.set(name, null);
    else seen.set(name, value);
  }
  for (const [k, v] of seen) if (v === null) seen.delete(k);
  return seen;
}

function substituteBindings(line, bindings) {
  if (bindings.size === 0) return line;
  return line.replace(/\b(require|import)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g, (m, kind, name) => {
    const value = bindings.get(name);
    const literal = value === undefined ? null : quote(value);
    return literal ? `${kind}(${literal})` : m;
  });
}

/**
 * Normalise one line. Returns the line unchanged when nothing folded, which
 * is the common case and lets the caller keep exact offsets.
 */
function normalizeLine(line, bindings) {
  let out = line;
  if (bindings.size !== 0 && line.includes('(')) {
    out = substituteBindings(out, bindings);
  }
  if (!FOLDABLE.test(out)) {
    return out;
  }
  for (let i = 0; i < MAX_PASSES; i++) {
    const next = foldOnce(out);
    if (next === out) break;
    out = next;
  }
  return out;
}

module.exports = { normalizeLine, literalBindings };
