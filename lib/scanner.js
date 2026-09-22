'use strict';

const fs = require('fs');
const path = require('path');
const {
  CATEGORIES,
  URL_PATTERN,
  ENDPOINT_TRAILING_JUNK,
  ENDPOINT_HOST,
  ENV_VAR_PATTERN,
  LONG_LINE_THRESHOLD,
  GENERATED_LONG_LINE,
  MIN_LONG_LINES_FOR_OBFUSCATION,
  LIFECYCLE_SCRIPT_KEYS,
  INSTALL_TRIGGERING_SCRIPT_KEYS,
  CREDENTIAL_ENV_PATTERN,
  DECLARATION_FILE_PATTERN,
  ERASED_SYNTAX,
  INSTALL_COMMAND_RULES,
  INERT_INSTALL_COMMAND,
  UNRESOLVED_REQUIRE,
  LOCAL_SPECIFIER,
  EXECUTABLE_SHEBANG_PATTERN,
  SHEBANG_PROBE_BYTES,
} = require('./categories');
const { RULES_VERSION } = require('./rules-version');
const { filesystemOperations } = require('./filesystem-operations');
const { contentIntegrity } = require('./content-integrity');
const { fileContext, sourceContext } = require('./source-context');
const { normalizeLine, literalBindings } = require('./normalize');

const SOURCE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx']);

// A nested node_modules is scanned in its own right; .git holds no shipped
// code. Nothing else is skipped. test/ and docs/ look tempting but anything
// inside a published tarball can be require()d, so a directory name carries
// no authority, and flatmap-stream hid the event-stream payload in test/
// precisely because that directory was absent from its GitHub repo.
const SKIP_DIRS = new Set(['node_modules', '.git']);

// This scanner's input is attacker-controlled by definition, so the size it
// will read into memory is bounded. Well above any real JS file; the largest
// seen across the benchmark corpora was under 2 MB. A skip is recorded in
// the manifest rather than silently reducing coverage.
const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024;

// Machine-generated output, where very long lines are expected and mean
// nothing. Without this a third of popular packages trip the obfuscation
// signal on an ordinary minified bundle. The names come from what actually
// fired across the corpus: `bundles/`, `fesm2022/` and `esm2020/` are the
// Angular Package Format, `coverage/` is an istanbul report, `.yarn/` a
// vendored package manager. `lib/` and `src/` are deliberately absent
// because both hold hand-authored code. Capability matching still runs on
// every one of these files; only the long-line signal is suppressed.
const BUILD_ARTIFACT_PATH =
  /(^|[\\/])(dist(-[a-z0-9]+)?|build(-[a-z0-9]+)?|umd|cjs|esm|f?esm\d+|es|bundles|lib-esm|vendor|coverage|assets|public|docs?|\.yarn)([\\/]|$)|[.\-]min\.[jt]sx?$|\.bundle\.[jt]sx?$/i;

function looksLikeBuildArtifact(relPath) {
  return BUILD_ARTIFACT_PATH.test(relPath);
}

// Reads the first bytes of an extension-less file to see whether it is a
// script the shell will hand to node. See EXECUTABLE_SHEBANG_PATTERN.
function hasNodeShebang(file, onError) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(SHEBANG_PROBE_BYTES);
    const read = fs.readSync(fd, buf, 0, SHEBANG_PROBE_BYTES, 0);
    const head = buf.toString('utf8', 0, read).split('\n', 1)[0];
    return EXECUTABLE_SHEBANG_PATTERN.test(head);
  } catch (e) {
    if (onError) onError(file, 'read-shebang', e);
    return false;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (e) { /* already gone */ }
    }
  }
}

function walk(dir, files, onError = () => {}) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    onError(dir, 'readdir', e);
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, files, onError);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SOURCE_EXTENSIONS.has(ext)) files.push(full);
      else if (ext === '' && hasNodeShebang(full, onError)) files.push(full);
    }
  }
}

// Every path `bin` points at, which is the code a consumer runs directly.
// The shebang probe above already reaches most of them; this makes it a
// guarantee that does not depend on the file's contents, and covers a bin
// target with an extension the filter does not know.
function binTargets(dir, pkgJson) {
  const bin = pkgJson && pkgJson.bin;
  if (!bin) return [];
  const raw = typeof bin === 'string' ? [bin] : Object.values(bin);
  const out = [];
  for (const rel of raw) {
    if (typeof rel !== 'string' || !rel) continue;
    const full = path.resolve(dir, rel);
    // A bin entry is attacker-controlled text; keep it inside the package.
    if (full !== dir && !full.startsWith(dir + path.sep)) continue;
    try {
      if (fs.statSync(full).isFile()) out.push(full);
    } catch (e) { /* declared but not shipped */ }
  }
  return out;
}

/**
 * Blank comments to spaces, preserving line and column offsets. Strings,
 * template literals and regex literals are left alone: rules must match
 * inside strings, and a regex may legally contain a quote (`/['"]/`).
 *
 * A character scanner, not a parser. Regex-vs-division is ambiguous in JS
 * without full parsing, so it is resolved from the last significant token:
 *   - after an identifier/number/string/regex/`]` -> division (a value was
 *     just produced: `total / 2`, `arr[0] / 2`, `"x" / 2`).
 *   - after `)` -> depends on the kind of `)`. A call/group close
 *     (`foo() / 2`) is a value, so division; a control-flow condition
 *     close (`if (x) /re/.test(y)`) is not, so a regex is allowed.
 *     Tracked via a paren stack recording, at each `(`, whether the
 *     preceding token was `if`/`while`/`for`/`switch`/`catch`/`with`.
 *   - after an expression-expecting keyword (`return`, `typeof`, `new`,
 *     `else`, `case`, etc, see REGEX_PERMITTING_KEYWORDS) -> regex.
 *   - after any other punctuation/operator, or at start-of-input -> regex.
 *
 * Known gap: `${...}` template interpolation is treated as opaque string
 * content, so a comment inside it won't be blanked.
 */
function blankComments(content, blankLiterals = false) {
  // Collect spans and splice blanks over them instead of rebuilding each
  // character. Operation attribution also masks literals; category matching
  // keeps them because module specifiers and indicators are string values.
  const blankRanges = [];
  let commentStart = -1;
  const NORMAL = 0;
  const LINE_COMMENT = 1;
  const BLOCK_COMMENT = 2;
  const STRING = 3;
  const REGEX = 4;
  let state = NORMAL;
  let quoteChar = '';
  let literalStart = -1;
  let regexInClass = false;
  let lastSignificant = ''; // last non-whitespace char seen in NORMAL state
  let wordBuf = ''; // accumulates the identifier currently being scanned
  let lastWord = ''; // most recently completed identifier/keyword token
  let lastParenWasControlFlow = false; // was the most recent ')' a control-flow condition close?
  const parenStack = [];
  const VALUE_CONTEXT = /[A-Za-z0-9_$\]]/; // last char implies division follows, not regex
  // These run on every character of every file and were 16% of scan time as
  // regexes. ASCII-only, matching what /[A-Za-z0-9_$]/ and /\s/ covered in
  // practice; a non-ASCII identifier falls through to the punctuation path.
  const isIdentCharCode = (code) =>
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 95 || // _
    code === 36; // $
  const isAsciiSpaceCode = (code) => code === 32 || (code >= 9 && code <= 13); // space, \t\n\v\f\r
  const CONTROL_FLOW_KEYWORDS = new Set(['if', 'while', 'for', 'switch', 'catch', 'with']);
  const REGEX_PERMITTING_KEYWORDS = new Set([
    'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
    'throw', 'do', 'else', 'yield', 'case', 'default', 'await',
  ]);

  function regexAllowed() {
    if (lastSignificant === ')') return lastParenWasControlFlow;
    if (VALUE_CONTEXT.test(lastSignificant)) return REGEX_PERMITTING_KEYWORDS.has(lastWord);
    return true; // operator, opening punctuation, or start-of-input
  }

  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    const next = content[i + 1];

    if (state === LINE_COMMENT) {
      if (c === '\n') {
        state = NORMAL;
        blankRanges.push(commentStart, i);
      }
      continue;
    }
    if (state === BLOCK_COMMENT) {
      if (c === '*' && next === '/') {
        i++;
        state = NORMAL;
        blankRanges.push(commentStart, i + 1);
      }
      continue;
    }
    if (state === STRING) {
      if (c === '\\') {
        // Skip the escaped character so we don't misread an escaped quote as
        // the string terminator.
        if (next !== undefined) {
          i++;
        }
        continue;
      }
      if (c === quoteChar) {
        if (blankLiterals) blankRanges.push(literalStart, i + 1);
        state = NORMAL;
        lastSignificant = 'x'; // a completed string is a value, like an identifier
        // A stale lastWord from before this string must not leak through:
        // regexAllowed() checks REGEX_PERMITTING_KEYWORDS.has(lastWord)
        // whenever lastSignificant is alnum, and without this reset
        // `return "foo" / 2` would wrongly reuse "return" from before the
        // string and misjudge the following `/` as a regex start.
        lastWord = '';
      }
      continue;
    }
    if (state === REGEX) {
      if (c === '\\') {
        if (next !== undefined) {
          i++;
        }
        continue;
      }
      if (c === '[') {
        regexInClass = true;
      } else if (c === ']') {
        regexInClass = false;
      } else if (c === '/' && !regexInClass) {
        if (blankLiterals) {
          let end = i + 1;
          while (end < content.length && /[dgimsuvy]/.test(content[end])) end++;
          blankRanges.push(literalStart, end);
        }
        state = NORMAL;
        lastSignificant = 'x'; // a completed regex literal is a value
        lastWord = ''; // same stale-keyword hazard as the STRING case above
      }
      continue;
    }
    // NORMAL
    if (isIdentCharCode(content.charCodeAt(i))) {
      wordBuf += c;
      lastSignificant = c;
      continue;
    }
    // c is not an identifier character: finalize any pending word first.
    if (wordBuf) {
      lastWord = wordBuf;
      wordBuf = '';
    }
    if (c === '/' && next === '/') {
      state = LINE_COMMENT;
      commentStart = i;
      i++;
      continue;
    }
    if (c === '/' && next === '*') {
      state = BLOCK_COMMENT;
      commentStart = i;
      i++;
      continue;
    }
    if (c === '(') {
      parenStack.push(CONTROL_FLOW_KEYWORDS.has(lastWord));
      // Consume lastWord: without this reset, a second `(` right after the
      // first (`if ((a + b) / c)`) would reuse the stale 'if' for the
      // inner paren too, wrongly marking it a control-flow close.
      lastWord = '';
      lastSignificant = c;
      continue;
    }
    if (c === ')') {
      lastParenWasControlFlow = parenStack.length ? parenStack.pop() : false;
      lastSignificant = ')';
      continue;
    }
    if (c === '/' && regexAllowed()) {
      state = REGEX;
      literalStart = i;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      state = STRING;
      literalStart = i;
      quoteChar = c;
      continue;
    }
    if (!isAsciiSpaceCode(content.charCodeAt(i))) lastSignificant = c;
  }
  if (state === LINE_COMMENT || state === BLOCK_COMMENT) {
    blankRanges.push(commentStart, content.length);
  }
  if (blankLiterals && (state === STRING || state === REGEX)) blankRanges.push(literalStart, content.length);
  if (blankRanges.length === 0) return content;

  let result = '';
  let pos = 0;
  for (let k = 0; k < blankRanges.length; k += 2) {
    const from = blankRanges[k];
    const to = blankRanges[k + 1];
    result += content.slice(pos, from);
    result += blankRun(content.slice(from, to));
    pos = to;
  }
  return result + content.slice(pos);
}

// Same length, same line breaks, no content. Keeping the length is what
// lets evidence keep pointing at the right column.
function blankRun(run) {
  return run.indexOf('\n') === -1 ? ' '.repeat(run.length) : run.replace(/[^\n]/g, ' ');
}

// Blank out TypeScript syntax the compiler erases, preserving line and
// column offsets the same way blankComments does, so evidence still points
// at the right place. See ERASED_SYNTAX in categories.js for why this is
// syntax-scoped rather than a file skip.
function blankErasedSyntax(code, relPath) {
  const isDeclaration = DECLARATION_FILE_PATTERN.test(relPath);
  let out = code;
  for (const rule of ERASED_SYNTAX) {
    if (rule.declarationFileOnly && !isDeclaration) continue;
    out = out.replace(rule.pattern, (m) => m.replace(/[^\n]/g, ' '));
  }
  return out;
}

// Strips what a source file glues onto a URL literal and rejects a match
// whose host is not one. See ENDPOINT_HOST in categories.js.
function normalizeEndpoint(raw) {
  const url = raw.replace(ENDPOINT_TRAILING_JUNK, '');
  return ENDPOINT_HOST.test(url) ? url : null;
}

// How near a match its context has to be. A minified bundle is one enormous
// line, so a line-scoped context is satisfied by anything in the file: a
// help string mentioning ~/.ssh/config and an `open(` call 50 KB away. On an
// ordinary line this window covers the whole line and changes nothing.
const CONTEXT_WINDOW = 120;

// A category pattern is either a RegExp or { match, context }; the second
// counts only where `context` also matches nearby. See sensitiveTargets.
function matchRule(rule, text) {
  if (rule instanceof RegExp) return rule.exec(text);
  // Cheap discriminator first. The context regex is an alternation over
  // every filesystem call and was 12% of total scan time when it ran on
  // every line; `.npmrc` and its siblings almost never match, so running
  // them first skips it for practically every line in the corpus.
  const hit = rule.match.exec(text);
  if (!hit) return null;
  if (!rule.context) return hit;
  const from = hit.index > CONTEXT_WINDOW ? hit.index - CONTEXT_WINDOW : 0;
  const to = hit.index + hit[0].length + CONTEXT_WINDOW;
  return rule.context.test(text.slice(from, to)) ? hit : null;
}

function ruleSource(rule) {
  return rule instanceof RegExp ? String(rule) : String(rule.match);
}

function initCapabilities() {
  const caps = {};
  for (const cat of CATEGORIES) {
    caps[cat.key] = { present: false, evidence: [] };
  }
  caps.network.endpoints = [];
  caps.env.vars = [];
  caps.lifecycleScripts = {
    present: false,
    installTriggering: false,
    scripts: {},
  };
  caps.obfuscationSignal = { present: false, evidence: [] };
  caps.skippedLargeFiles = { present: false, count: 0, files: [] };
  // "Nothing was read" and "nothing was found" produce the same empty
  // manifest, and only one of them means the package is inert.
  caps.noReadableSource = { present: false };
  // A require whose specifier we could not resolve. See UNRESOLVED_REQUIRE.
  caps.unresolvedRequire = { present: false, evidence: [] };
  caps.analysisIncomplete = { present: false, reasons: [] };
  return caps;
}

const SNIPPET_MAX = 200;

// Evidence entries kept per capability category. Once a category is present
// and has this many, another match teaches nothing.
const MAX_EVIDENCE_PER_CATEGORY = 5;

// These are resource budgets, not display limits. Hitting either makes the
// analysis incomplete; a truncated set must never pass as a complete scan.
const MAX_INDICATORS = 10000;
const MAX_INDICATOR_BYTES = 1024 * 1024;

function indicatorCollector(caps, incomplete) {
  const sets = new Map();
  return (key, value) => {
    if (!value) return;
    if (!sets.has(key)) sets.set(key, { values: new Set(), bytes: 0, exhausted: false });
    const state = sets.get(key);
    if (state.exhausted || state.values.has(value)) return;
    const bytes = Buffer.byteLength(value, 'utf8');
    if (state.values.size >= MAX_INDICATORS || state.bytes + bytes > MAX_INDICATOR_BYTES) {
      state.exhausted = true;
      incomplete(`${key}-limit`);
      return;
    }
    state.values.add(value);
    state.bytes += bytes;
    const target = key === 'endpoints' ? caps.network.endpoints : caps.env.vars;
    target.push(value);
  };
}

// Cheap gate for the whole-file pass: an import keyword with a line break
// before its specifier is the only shape the per-line pass can miss.
const MULTILINE_CANDIDATE = /\b(?:require|from)\s*\(?\s*\n/;

// Centre the snippet on the match. A minified bundle is one enormous line,
// so its first 200 characters routinely have nothing to do with what
// matched. Blanking preserves offsets, so the index still addresses the
// original line.
function excerpt(line, matchIndex) {
  const lead = line.length - line.trimStart().length;
  const trimmed = line.trim();
  if (matchIndex < 0 || trimmed.length <= SNIPPET_MAX) return trimmed.slice(0, SNIPPET_MAX);
  const at = Math.max(0, matchIndex - lead);
  let end = Math.min(trimmed.length, Math.max(0, at - 60) + SNIPPET_MAX);
  const start = Math.max(0, end - SNIPPET_MAX);
  return (start > 0 ? '...' : '') + trimmed.slice(start, end) + (end < trimmed.length ? '...' : '');
}

// `pattern` records which rule matched. Without it a reviewer asking "why
// was this flagged" has to re-derive the answer by eye, and attributing a
// false positive to a specific rule across a large corpus is guesswork.
function addEvidence(list, file, lineNo, line, pattern, max = MAX_EVIDENCE_PER_CATEGORY, matchIndex = -1) {
  if (list.length >= max) return;
  const entry = { file, line: lineNo, snippet: excerpt(line, matchIndex) };
  if (pattern) entry.pattern = String(pattern);
  list.push(entry);
}

function scanFileContent(relPath, content, caps, collect, context) {
  const longLines = [];
  const codeOnly = blankErasedSyntax(blankComments(content), relPath);
  if (/['"`](?:node:)?fs(?:\/promises)?['"`]/.test(codeOnly)) {
    const mask = blankErasedSyntax(blankComments(content, true), relPath);
    filesystemOperations(codeOnly, mask, (category, index, rule) => {
      const cap = caps[category];
      cap.present = true;
      if (cap.evidence.length >= MAX_EVIDENCE_PER_CATEGORY) return;
      const lineStart = content.lastIndexOf('\n', index - 1) + 1;
      let lineEnd = content.indexOf('\n', index);
      if (lineEnd === -1) lineEnd = content.length;
      addEvidence(cap.evidence, relPath, content.slice(0, index).split('\n').length,
        content.slice(lineStart, lineEnd), rule, MAX_EVIDENCE_PER_CATEGORY, index - lineStart);
    });
  }
  // Specifiers a scanner can fold without running the code. See normalize.js.
  const bindings = literalBindings(codeOnly);
  // Blanking preserves length and line breaks, so both strings share their
  // line boundaries. Walking those boundaries instead of splitting both
  // strings avoids allocating two arrays of every line in the file, and the
  // original line is sliced only when there is evidence to record.
  let lineCount = 0;
  // A declaration file has no executable code to hide, so a long type union
  // is not reduced coverage; graphql's index.d.ts carries 1,722-character
  // lines and made a routine upgrade fail the gate. Capability matching
  // still runs on it, only the long-line signal is suppressed.
  const isGenerated = looksLikeBuildArtifact(relPath) || DECLARATION_FILE_PATTERN.test(relPath);

  // Keep looking for the first file-local match even when the package-wide
  // evidence quota is full. Context must not be inferred from capped samples.
  const active = CATEGORIES.filter(
    (cat) => context.needs(cat.key) || !(caps[cat.key].present && caps[cat.key].evidence.length >= MAX_EVIDENCE_PER_CATEGORY)
  );

  for (let lineStart = 0; lineStart <= codeOnly.length; ) {
    let lineEnd = codeOnly.indexOf('\n', lineStart);
    if (lineEnd === -1) lineEnd = codeOnly.length;
    const rawLine = codeOnly.slice(lineStart, lineEnd);
    const codeLine = normalizeLine(rawLine, bindings);
    // A folded line no longer lines up with the original, so evidence falls
    // back to the head of the source line rather than pointing at a column
    // that moved.
    const folded = codeLine !== rawLine;
    const from = lineStart;
    const to = lineEnd;
    lineStart = lineEnd + 1;
    const lineNo = ++lineCount;

    // Measured on the comment-blanked line with whitespace trimmed off.
    // Blanking preserves length so columns stay accurate, which means a
    // 592-character JSDoc line becomes 592 spaces and used to count as a
    // long line: documentation was being reported as obfuscation. Trimming
    // collapses a blanked comment to nothing while leaving real minified
    // code untouched.
    const codeLength = codeLine.trim().length;
    if (!isGenerated && codeLength > LONG_LINE_THRESHOLD && !GENERATED_LONG_LINE.some((re) => re.test(codeLine))) {
      longLines.push({ lineNo, codeLength });
    }

    for (let ci = 0; ci < active.length; ci++) {
      const cat = active[ci];
      const cap = caps[cat.key];
      for (const rule of cat.patterns) {
        const hit = matchRule(rule, codeLine);
        if (hit) {
          cap.present = true;
          if (context.needs(cat.key)) context.record(cat.key, lineNo, excerpt(content.slice(from, to), folded ? -1 : hit.index));
          addEvidence(cap.evidence, relPath, lineNo, content.slice(from, to), ruleSource(rule), MAX_EVIDENCE_PER_CATEGORY, folded ? -1 : hit.index);
          if (cap.evidence.length >= MAX_EVIDENCE_PER_CATEGORY && !context.needs(cat.key)) {
            active.splice(ci, 1);
            ci--;
          }
          break;
        }
      }
    }

    if (!caps.unresolvedRequire.present || caps.unresolvedRequire.evidence.length < MAX_EVIDENCE_PER_CATEGORY) {
      const unresolved = UNRESOLVED_REQUIRE.exec(codeLine);
      if (unresolved && !LOCAL_SPECIFIER.test(unresolved[0])) {
        caps.unresolvedRequire.present = true;
        addEvidence(
          caps.unresolvedRequire.evidence, relPath, lineNo, content.slice(from, to),
          String(UNRESOLVED_REQUIRE), MAX_EVIDENCE_PER_CATEGORY, folded ? -1 : unresolved.index
        );
      }
    }

    let m;
    URL_PATTERN.lastIndex = 0;
    while ((m = URL_PATTERN.exec(codeLine)) !== null) {
      collect('endpoints', normalizeEndpoint(m[0]));
    }
    ENV_VAR_PATTERN.lastIndex = 0;
    while ((m = ENV_VAR_PATTERN.exec(codeLine)) !== null) {
      collect('env-vars', m[1] || m[2]);
      const name = m[1] || m[2];
      if (CREDENTIAL_ENV_PATTERN.test(name)) context.record('credential-env', lineNo,
        excerpt(content.slice(from, to), folded ? -1 : m.index), name);
    }
  }

  // A specifier can sit on its own line: `require(\n  'child_process'\n)`.
  // Line-scoped matching cannot see that, and the patterns already allow
  // newlines through `\s*`, so any category still absent gets one pass over
  // the whole file. Only the categories that found nothing, so the common
  // case costs nothing.
  const maySpanLines = active.length > 0 && MULTILINE_CANDIDATE.test(codeOnly);
  for (const cat of maySpanLines ? CATEGORIES : []) {
    const cap = caps[cat.key];
    if (cap.present && !context.needs(cat.key)) {
      continue;
    }
    for (const rule of cat.patterns) {
      const hit = matchRule(rule, codeOnly);
      if (!hit) {
        continue;
      }
      const lineNo = codeOnly.slice(0, hit.index).split('\n').length;
      if (context.needs(cat.key)) {
        const start = content.lastIndexOf('\n', hit.index - 1) + 1;
        let end = content.indexOf('\n', hit.index);
        if (end === -1) end = content.length;
        context.record(cat.key, lineNo, excerpt(content.slice(start, end), hit.index - start));
      }
      if (!cap.present) {
        cap.present = true;
        addEvidence(
          cap.evidence, relPath, lineNo, hit[0].replace(/\s+/g, ' '),
          ruleSource(rule), MAX_EVIDENCE_PER_CATEGORY, -1
        );
      }
      break;
    }
  }

  // Minification means many long lines, or the whole file on one. A single
  // long line is almost always data or one big regex, like js-tokens' 632
  // character tokenizer, and packed payloads are never one stray line.
  if (longLines.length) {
    const avgLineLength = codeOnly.length / Math.max(1, lineCount);
    if (longLines.length >= MIN_LONG_LINES_FOR_OBFUSCATION || avgLineLength > LONG_LINE_THRESHOLD) {
      caps.obfuscationSignal.present = true;
      for (const l of longLines.slice(0, 3)) {
        addEvidence(
          caps.obfuscationSignal.evidence,
          relPath,
          l.lineNo,
          `<line of length ${l.codeLength}>`,
          null,
          3
        );
      }
    }
  }
}

// A lifecycle script command runs at install time but is not a file, so the
// directory walk never sees it. See INSTALL_COMMAND_RULES in categories.js.
function scanScriptCommand(scriptKey, command, caps, collect) {
  const where = `package.json#scripts.${scriptKey}`;
  for (const cat of CATEGORIES) {
    for (const rule of cat.patterns) {
      const hit = matchRule(rule, command);
      if (hit) {
        caps[cat.key].present = true;
        addEvidence(caps[cat.key].evidence, where, 1, command, ruleSource(rule), MAX_EVIDENCE_PER_CATEGORY, hit.index);
        break;
      }
    }
  }
  for (const rule of INSTALL_COMMAND_RULES) {
    const hit = rule.pattern.exec(command);
    if (hit) {
      caps[rule.key].present = true;
      addEvidence(caps[rule.key].evidence, where, 1, command, rule.pattern, 5, hit.index);
    }
  }
  let m;
  URL_PATTERN.lastIndex = 0;
  while ((m = URL_PATTERN.exec(command)) !== null) {
    collect('endpoints', normalizeEndpoint(m[0]));
  }
  ENV_VAR_PATTERN.lastIndex = 0;
  while ((m = ENV_VAR_PATTERN.exec(command)) !== null) {
    collect('env-vars', m[1] || m[2]);
  }
}

// Distinguishes "no package.json here" (unremarkable, e.g. `scan` invoked
// on an arbitrary directory) from "package.json exists but is not valid
// JSON" (which a real published npm package cannot have, since the
// registry validates it at publish time; unparseable is a real anomaly
// worth surfacing, not the same as absent).
function readPackageJson(dir, onError) {
  const pkgPath = path.join(dir, 'package.json');
  let raw;
  try {
    raw = fs.readFileSync(pkgPath, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') onError(pkgPath, 'read-package-json', e);
    return { data: null, malformed: false };
  }
  try {
    // npm and every real consumer strip a leading byte-order mark, so a
    // BOM-prefixed package.json is valid rather than malformed.
    return { data: JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw), malformed: false };
  } catch (e) {
    return { data: null, malformed: true };
  }
}

function computeRisk(caps) {
  let score = 0;
  const flags = [];
  for (const cat of CATEGORIES) {
    if (caps[cat.key].present) score += cat.severity;
  }
  if (caps.lifecycleScripts.installTriggering) {
    score += 4;
  } else if (caps.lifecycleScripts.present) {
    // Build-time-only script (prepare/prepublish): doesn't run for a normal
    // registry install, so it's weighted far lower than an install-
    // triggering script, but still worth a small amount of signal (e.g. the
    // package is pulled via a git dependency somewhere in the tree).
    score += 1;
  }
  if (caps.obfuscationSignal.present) score += 3;

  const hasInstallTriggering = caps.lifecycleScripts.installTriggering;
  const hasBuildTimeOnly = caps.lifecycleScripts.present && !hasInstallTriggering;
  const hasNetwork = caps.network.present;
  const hasSensitive = caps.sensitiveTargets.present;
  const hasExec = caps.exec.present;
  // Credential-shaped, not env access of any kind: esbuild's postinstall
  // downloads its own binary and reads ESBUILD_BINARY_PATH, which is the
  // worm's shape without its substance.
  const hasCredentialEnv = (caps.env.vars || []).some((v) => CREDENTIAL_ENV_PATTERN.test(v));
  const hasCredentialAccess = hasSensitive || hasCredentialEnv;

  // A worm propagates on credentials belonging to the environment it lands
  // in: an npm or GitHub token, an SSH key, AWS keys, ~/.npmrc. Its own
  // service key is not that, so a Figma CLI reading FIGMA_TOKEN gets the
  // HIGH below rather than being told it looks like Shai-Hulud.
  if (hasInstallTriggering && hasNetwork && hasSensitive) {
    score += 10;
    flags.push(
      'CRITICAL: install-time lifecycle script (preinstall/install/postinstall) combined with ' +
        'network access and credential/env access, matching the self-propagating supply-chain ' +
        'worm pattern (e.g. Shai-Hulud).'
    );
  } else if (hasInstallTriggering && hasNetwork && hasCredentialEnv) {
    score += 5;
    flags.push(
      'HIGH: runs code at install time, has network access, and reads a credential-shaped ' +
        'environment variable. Check whether the credential is the package\'s own service key ' +
        'or one that belongs to the environment it is installed into.'
    );
  } else if (hasBuildTimeOnly && hasNetwork && hasCredentialAccess) {
    flags.push(
      'MEDIUM: build-time script (prepare/prepublish) combined with network and credential/env ' +
        'access. This script does NOT run for a normal registry install of this package as a ' +
        'dependency, only for local development or a git-URL dependency, so it is lower risk ' +
        'than an install-triggering script, but worth a look if this package is pulled via git.'
    );
  }
  if (hasInstallTriggering && hasExec) {
    flags.push('HIGH: install-time lifecycle script combined with process execution.');
  }
  if (hasSensitive && hasNetwork) {
    flags.push('HIGH: code reads credential-like paths/vars and also has network access (possible exfiltration path).');
  }
  if (caps.obfuscationSignal.present) {
    flags.push('MEDIUM: minified/obfuscated-looking source (very long lines); static analysis coverage is reduced here.');
  }
  if (caps.dynamicEval.present) {
    flags.push('MEDIUM: dynamic code execution (eval/new Function) can hide capabilities from static analysis entirely.');
  }
  // Scores nothing on purpose: it is common enough that scoring it would
  // move the ranking without adding information. The flag is the signal, and
  // it gates a diff through lostVisibility.
  if (caps.unresolvedRequire.present) {
    flags.push(
      'MEDIUM: loads a module whose name could not be resolved from the source, so whatever that ' +
        'module can do is not in this manifest. See unresolvedRequire for where.'
    );
  }
  if (caps.noReadableSource.present) {
    flags.push(
      'MEDIUM: no source file was read for this package, so an empty capability set here means ' +
        'nothing was scanned rather than nothing was found.'
    );
  }
  if (caps.skippedLargeFiles.present) {
    score += 2;
    flags.push(
      'MEDIUM: one or more source files exceeded the size limit for scanning and were skipped. ' +
        'Static analysis coverage is reduced for this package. See skippedLargeFiles for which files.'
    );
  }
  if (caps.analysisIncomplete.present) {
    flags.push('HIGH: analysis is incomplete; review coverage errors and resource limits before trusting this manifest.');
  }

  return { score, flags };
}

/**
 * Scan a single package directory (e.g. a node_modules/<pkg> folder, or a
 * package source checkout) and return a capability manifest.
 */
function scanPackageDir(dir) {
  dir = path.resolve(dir);
  const caps = initCapabilities();
  const context = sourceContext();
  const coverage = { complete: true, filesDiscovered: 0, filesRead: 0, bytesRead: 0, filesSkipped: 0, errorCount: 0, errors: [] };
  const incomplete = (reason) => {
    coverage.complete = false;
    caps.analysisIncomplete.present = true;
    if (!caps.analysisIncomplete.reasons.includes(reason)) caps.analysisIncomplete.reasons.push(reason);
  };
  const onError = (file, operation, error) => {
    incomplete('io-error');
    coverage.errorCount++;
    if (coverage.errors.length < 10) {
      coverage.errors.push({ file: path.relative(dir, file) || '.', operation, code: error.code || 'UNKNOWN' });
    }
  };
  const collect = indicatorCollector(caps, incomplete);
  const { data: pkgJson, malformed: malformedPackageJson } = readPackageJson(dir, onError);
  const name = (pkgJson && pkgJson.name) || path.basename(dir);
  const version = (pkgJson && pkgJson.version) || '0.0.0-unknown';
  if (malformedPackageJson) incomplete('invalid-package-json');

  const scripts = { ...((pkgJson && pkgJson.scripts) || {}) };
  // npm's implicit native build exists even without a scripts entry.
  // This records the potential command, not permission to execute it.
  if (pkgJson && pkgJson.gypfile !== false && !scripts.install && !scripts.preinstall) {
    const gypPath = path.join(dir, 'binding.gyp');
    try {
      if (fs.statSync(gypPath).isFile()) {
        scripts.install = 'node-gyp rebuild';
        caps.lifecycleScripts.implicit = { install: 'binding.gyp' };
      }
    } catch (e) {
      if (e.code !== 'ENOENT') onError(gypPath, 'stat-binding-gyp', e);
    }
  }
  for (const key of LIFECYCLE_SCRIPT_KEYS) {
    const command = scripts[key];
    if (typeof command !== 'string' || !command) continue;
    caps.lifecycleScripts.present = true;
    caps.lifecycleScripts.scripts[key] = command;
    // Recorded either way; a reviewer should still see the command. It
    // just isn't code running at install time. See INERT_INSTALL_COMMAND.
    if (INERT_INSTALL_COMMAND.test(command)) continue;
    // Only commands a consumer actually runs contribute capabilities.
    // `prepare` does not run for a registry install, and glob's is
    // `tshy && bash scripts/build.sh`. It stays in the manifest, and
    // diff.js still reports a changed prepare without gating on it.
    if (!INSTALL_TRIGGERING_SCRIPT_KEYS.includes(key)) continue;
    caps.lifecycleScripts.installTriggering = true;
    scanScriptCommand(key, command, caps, collect);
  }

  const files = [];
  walk(dir, files, onError);
  for (const target of binTargets(dir, pkgJson)) {
    if (!files.includes(target)) files.push(target);
  }
  coverage.filesDiscovered = files.length;
  for (const file of files) {
    const relPath = path.relative(dir, file);
    try {
      const st = fs.statSync(file);
      if (st.size > MAX_FILE_SIZE_BYTES) {
        incomplete('file-size-limit');
        coverage.filesSkipped++;
        caps.skippedLargeFiles.present = true;
        caps.skippedLargeFiles.count++;
        // `.files` is capped for evidence display; `.count` above is the
        // true total and is what sourceFilesSkipped reports. Using
        // `.files.length` there would silently undercount past the cap.
        if (caps.skippedLargeFiles.files.length < 10) {
          caps.skippedLargeFiles.files.push({ file: relPath, sizeBytes: st.size });
        }
        continue;
      }
    } catch (e) {
      onError(file, 'stat', e);
      coverage.filesSkipped++;
      continue;
    }
    let source;
    try {
      source = fs.readFileSync(file);
    } catch (e) {
      onError(file, 'read', e);
      coverage.filesSkipped++;
      continue;
    }
    coverage.filesRead++;
    coverage.bytesRead += source.length;
    const local = fileContext(relPath);
    scanFileContent(relPath, source.toString('utf8'), caps, collect, local);
    context.add(local);
  }
  caps.noReadableSource.present = coverage.filesRead === 0;

  let { score, flags } = computeRisk(caps);
  if (malformedPackageJson) {
    // A published npm package always has valid package.json (the registry
    // validates it at publish time), so a package.json present but not
    // parseable as JSON is not expected noise, it is an anomaly worth a
    // reviewer's attention.
    score += 2;
    flags = [...flags, 'MEDIUM: package.json exists but is not valid JSON.'];
  }

  return {
    schemaVersion: 7,
    sourceContext: context.finish(coverage.complete),
    contentIntegrity: contentIntegrity(dir),
    rulesVersion: RULES_VERSION,
    name,
    version,
    scannedAt: new Date().toISOString(),
    sourceFilesScanned: coverage.filesRead,
    sourceFilesSkipped: coverage.filesSkipped,
    coverage,
    malformedPackageJson,
    capabilities: caps,
    riskScore: score,
    riskFlags: flags,
  };
}

module.exports = { scanPackageDir, walk, blankComments, blankErasedSyntax, excerpt, looksLikeBuildArtifact };
